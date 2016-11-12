/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <semaphore.h>
#include <mqueue.h>
#include <queue>
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#include <sys/epoll.h>  
#include "service.h"
#include "session.h"
#include "util/trace.h"
#include "tinyxml/tinyxml.h"

#define MAX_EVENTS_NUM  65536
#define MAX_SOCKFD_NUM  65536

enum CLIENT_PARAM_CTRL{
	SessionParamData = 0,
	SessionParamQuit
};

typedef struct {
	CLIENT_PARAM_CTRL ctrl;
	char client_ip[128];
    char backend_ip[128];
    unsigned short backend_port;
} CLIENT_PARAM;

static int send_sockfd(int sfd, int fd_file, CLIENT_PARAM* param) 
{
	struct msghdr msg;  
    struct iovec iov[1];  
    union{  
        struct cmsghdr cm;  
        char control[CMSG_SPACE(sizeof(int))];  
    }control_un;  
    struct cmsghdr *cmptr;     
    msg.msg_control = control_un.control;   
    msg.msg_controllen = sizeof(control_un.control);  
    cmptr = CMSG_FIRSTHDR(&msg);  
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;   
    cmptr->cmsg_type = SCM_RIGHTS;
    *((int*)CMSG_DATA(cmptr)) = fd_file;
    msg.msg_name = NULL;  
    msg.msg_namelen = 0;  
    iov[0].iov_base = param;  
    iov[0].iov_len = sizeof(CLIENT_PARAM);  
    msg.msg_iov = iov;  
    msg.msg_iovlen = 1;

    return sendmsg(sfd, &msg, 0); 

}

static int recv_sockfd(int sfd, int* fd_file, CLIENT_PARAM* param) 
{
    struct msghdr msg;  
    struct iovec iov[1];  
    int nrecv;  
    union{
		struct cmsghdr cm;  
		char control[CMSG_SPACE(sizeof(int))];  
    }control_un;  
    struct cmsghdr *cmptr;  
    msg.msg_control = control_un.control;  
    msg.msg_controllen = sizeof(control_un.control);
    msg.msg_name = NULL;  
    msg.msg_namelen = 0;  

    iov[0].iov_base = param;  
    iov[0].iov_len = sizeof(CLIENT_PARAM);  
    msg.msg_iov = iov;  
    msg.msg_iovlen = 1;

    if((nrecv = recvmsg(sfd, &msg, 0)) <= 0)  
    {  

        return nrecv;  
    }

    cmptr = CMSG_FIRSTHDR(&msg);  
    if((cmptr != NULL) && (cmptr->cmsg_len == CMSG_LEN(sizeof(int))))  
    {  
        if(cmptr->cmsg_level != SOL_SOCKET)  
        {  
            printf("control level != SOL_SOCKET/n");  
            exit(-1);  
        }  
        if(cmptr->cmsg_type != SCM_RIGHTS)  
        {  
            printf("control type != SCM_RIGHTS/n");  
            exit(-1);  
        } 
        *fd_file = *((int*)CMSG_DATA(cmptr));  
    }  
    else  
    {  
        if(cmptr == NULL)
			printf("null cmptr, fd not passed.\n");  
        else
			printf("message len[%d] if incorrect.\n", cmptr->cmsg_len);  
        *fd_file = -1; // descriptor was not passed  
    }   
    return *fd_file;  
}

static void clear_mqueue(mqd_t qid)
{
	mq_attr attr;
	struct timespec ts;
	mq_getattr(qid, &attr);
	char* buf = (char*)malloc(attr.mq_msgsize);
	while(1)
	{
		clock_gettime(CLOCK_REALTIME, &ts);
		if(mq_timedreceive(qid, (char*)buf, attr.mq_msgsize, NULL, &ts) == -1)
		{
			break;
		}
	}
	free(buf);
}

//////////////////////////////////////////////////////////////////////////////////
//Worker
Worker::Worker(const char* service_name, int process_seq, int sockfd)
{
	m_sockfd = sockfd;
	m_process_seq = process_seq;
	m_service_name = service_name;
    
    m_client_list = new Session*[MAX_SOCKFD_NUM];
    memset(m_client_list, 0, MAX_SOCKFD_NUM * sizeof(Session*));
    
    m_backend_list = new Session*[MAX_SOCKFD_NUM];
    memset(m_backend_list, 0, MAX_SOCKFD_NUM * sizeof(Session*));
}

Worker::~Worker()
{
    if(m_client_list)
    {
        for(int x = 0; x < MAX_SOCKFD_NUM; x++)
        {
            if(m_client_list[x] != NULL)
            {
                close(x);
                m_client_list[x]->release();
            }
        }
        delete[] m_client_list;
    }
    m_client_list = NULL;
    
    if(m_backend_list)
    {
        for(int x = 0; x < MAX_SOCKFD_NUM; x++)
        {
            if(m_backend_list[x] != NULL)
            {
                close(x);
                m_backend_list[x]->release();
            }
        }
        delete[] m_backend_list;
    }
    m_backend_list = NULL;
}

void Worker::Working()
{
	bool bQuit = false;
    
    int epoll_fd;
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)  
    {  
      perror ("epoll_create1");  
      abort ();  
    }
        
    struct epoll_event event;  
    struct epoll_event * events = new struct epoll_event[bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn]; 
    
    event.data.fd = m_sockfd;  
    event.events = EPOLLIN;
    int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, m_sockfd, &event); 
    if (s == -1)  
    {  
        perror("epoll_ctl, 1");
        abort();
        return;
    }
	while(!bQuit)
	{
        int n, i;  
  
        n = epoll_wait (epoll_fd, events, bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn, 1000);
        
        for (i = 0; i < n; i++)  
        {
            if(events[i].data.fd == m_sockfd)
            {
                int clt_sockfd;
                CLIENT_PARAM client_param;
                if(recv_sockfd(m_sockfd, &clt_sockfd, &client_param)  < 0)
                {
                    fprintf(stderr, "recv_sockfd < 0\n");
                    continue;
                }
                if(clt_sockfd < 0)
                {
                    fprintf(stderr, "recv_sockfd error, clt_sockfd = %d %s %d\n", clt_sockfd, __FILE__, __LINE__);
                    bQuit = true;
                }

                if(client_param.ctrl == SessionParamQuit)
                {
                    printf("quit\n");
                    bQuit = true;
                }
                else
                {
                    
                    event.data.fd = clt_sockfd;  
                    event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;  
                    int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, clt_sockfd, &event);  
                    if (s == -1)  
                    {  
                        perror("epoll_ctl 2");  
                        abort ();  
                    }
                    
                    try {
                        
                        Session * p_session = new Session(clt_sockfd, client_param.client_ip, client_param.backend_ip, client_param.backend_port);
                        
                        p_session->accquire();
                        
                        if(m_client_list[p_session->get_clientsockfd()] != NULL)
                        {
                            m_client_list[p_session->get_clientsockfd()]->release();
                        }
                        m_client_list[p_session->get_clientsockfd()] = p_session;
                        
                        p_session->accquire();
                        
                        if(m_backend_list[p_session->get_backendsockfd()] != NULL)
                        {
                            m_backend_list[p_session->get_backendsockfd()]->release();
                        }
                        m_backend_list[p_session->get_backendsockfd()] = p_session;
                        
                        event.data.fd = p_session->get_backendsockfd();  
                        event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR; 
                    
                        int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, p_session->get_backendsockfd(), &event);  
                        if (s == -1)  
                        {  
                             perror("epoll_ctl 3");  
                            abort ();  
                        }
                        
                    }
                    catch(string* e)
                    {
                        printf("%s\n", e->c_str());
                        delete e;
                    }
                }
            }
            else
            {
                if (events[i].events & EPOLLIN)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_client_list[events[i].data.fd];
                        if(p_session && p_session->recv_from_client() < 0)
                        {
                                struct epoll_event ev;
                                ev.events = EPOLLIN;
                                ev.data.fd = events[i].data.fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                
                                m_client_list[events[i].data.fd] = NULL;
                                
                                p_session->release(); //delete itself
                                close(events[i].data.fd);
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_backend_list[events[i].data.fd];
                        if(p_session && p_session->recv_from_backend() < 0)
                        {
                            
                            struct epoll_event ev;
                            ev.events = EPOLLIN;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);

                            m_backend_list[events[i].data.fd] = NULL;
                            p_session->release(); //delete itself
                            close(events[i].data.fd);
                           
                            
                        }
                    }
                }
                else if (events[i].events & EPOLLOUT)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_client_list[events[i].data.fd];
                        if(p_session && p_session->send_to_client() < 0)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_client_list[events[i].data.fd] = NULL;
                                
                            p_session->release(); //delete itself
                            close(events[i].data.fd);
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_backend_list[events[i].data.fd];
                        if(p_session && p_session->send_to_backend() < 0)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_backend_list[events[i].data.fd] = NULL;
                            p_session->release(); //delete itself
                            close(events[i].data.fd);
                        }
                    }
                }
                else if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_client_list[events[i].data.fd];
                        if(p_session)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);

                            m_client_list[events[i].data.fd] = NULL;
                                
                            p_session->release(); //delete itself
                            close(events[i].data.fd);
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* p_session = m_backend_list[events[i].data.fd];
                        if(p_session)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_backend_list[events[i].data.fd] = NULL;
                            
                            p_session->release(); //delete itself
                            close(events[i].data.fd);
                        }
                    }
                }
            }
        }
		
	}
    delete events;
}

//////////////////////////////////////////////////////////////////////////////////
//Service
Service::Service(Service_Type st)
{
	m_st = st;
	m_service_name = SVR_NAME_TBL[m_st];
    
    m_service_list = new service_content_t*[MAX_SOCKFD_NUM];
    memset(m_service_list, 0, MAX_SOCKFD_NUM * sizeof(service_content_t*));
}

Service::~Service()
{
    if(m_service_list)
    {
        for(int x = 0; x < MAX_SOCKFD_NUM; x++)
        {
            if(m_service_list[x] != NULL)
            {
                close(x);
                delete m_service_list[x];
            }
        }
        delete[] m_service_list;
    }
    m_service_list = NULL;
}

void Service::Stop()
{
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	m_service_qid = mq_open(strqueue.c_str(), O_RDWR);
	m_service_sid = sem_open(strsem.c_str(), O_RDWR);
	if(m_service_qid == (mqd_t)-1 || m_service_sid == SEM_FAILED)
	{
		return;
	}	
        
	stQueueMsg qMsg;
	qMsg.cmd = MSG_EXIT;
	sem_wait(m_service_sid);
	mq_send(m_service_qid, (const char*)&qMsg, sizeof(stQueueMsg), 0);
	sem_post(m_service_sid);
        if(m_service_qid)
		mq_close(m_service_qid);

	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);
        printf("Stop %s OK\n", SVR_DESP_TBL[m_st]);
}

void Service::ReloadConfig()
{
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	m_service_qid = mq_open(strqueue.c_str(), O_RDWR);
	m_service_sid = sem_open(strsem.c_str(), O_RDWR);

	if(m_service_qid == (mqd_t)-1 || m_service_sid == SEM_FAILED)
		return;

	stQueueMsg qMsg;
	qMsg.cmd = MSG_GLOBAL_RELOAD;
	sem_wait(m_service_sid);
	mq_send(m_service_qid, (const char*)&qMsg, sizeof(stQueueMsg), 0);
	sem_post(m_service_sid);
	
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);

	printf("Reload %s OK\n", SVR_DESP_TBL[m_st]);
}

void Service::ReloadAccess()
{
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	m_service_qid = mq_open(strqueue.c_str(), O_RDWR);
	m_service_sid = sem_open(strsem.c_str(), O_RDWR);

	if(m_service_qid == (mqd_t)-1 || m_service_sid == SEM_FAILED)
		return;

	stQueueMsg qMsg;
	qMsg.cmd = MSG_ACCESS_RELOAD;
	sem_wait(m_service_sid);
	mq_send(m_service_qid, (const char*)&qMsg, sizeof(stQueueMsg), 0);
	sem_post(m_service_sid);
	
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);
}

void Service::AppendReject(const char* data)
{
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	m_service_qid = mq_open(strqueue.c_str(), O_RDWR);
	m_service_sid = sem_open(strsem.c_str(), O_RDWR);

	if(m_service_qid == (mqd_t)-1 || m_service_sid == SEM_FAILED)
		return;

	stQueueMsg qMsg;
	qMsg.cmd = MSG_REJECT_APPEND;
	strncpy(qMsg.data.reject_ip, data, 255);
	qMsg.data.reject_ip[255] = '\0';

	sem_wait(m_service_sid);
	mq_send(m_service_qid, (const char*)&qMsg, sizeof(stQueueMsg), 0);
	sem_post(m_service_sid);
	
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);
}

void Service::ReloadExtension()
{
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	m_service_qid = mq_open(strqueue.c_str(), O_RDWR);
	m_service_sid = sem_open(strsem.c_str(), O_RDWR);

	if(m_service_qid == (mqd_t)-1 || m_service_sid == SEM_FAILED)
		return;

	stQueueMsg qMsg;
	qMsg.cmd = MSG_EXTENSION_RELOAD;
	sem_wait(m_service_sid);
	mq_send(m_service_qid, (const char*)&qMsg, sizeof(stQueueMsg), 0);
	sem_post(m_service_sid);
	
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);
}

int Service::create_server_socket(int& sockfd, const char* hostip, unsigned short port)
{
    CUplusTrace uTrace(LOGNAME, LCKNAME);
    int nFlag;
    struct addrinfo hints;
    struct addrinfo *server_addr, *rp;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    
    char szPort[32];
    sprintf(szPort, "%u", port);

    int s = getaddrinfo((hostip && hostip[0] != '\0') ? hostip : NULL, szPort, &hints, &server_addr);
    if (s != 0)
    {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
       return -1;
    }
    
    for (rp = server_addr; rp != NULL; rp = rp->ai_next)
    {
       sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
       if (sockfd == -1)
           return -1;
       
       nFlag = 1;
       setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&nFlag, sizeof(nFlag));
    
       if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
           break;                  /* Success */
       perror("bind");
       close(sockfd);
    }
    
    if (rp == NULL)
    {               /* No address succeeded */
          fprintf(stderr, "Could not bind\n");
          return -1;
    }

    freeaddrinfo(server_addr);           /* No longer needed */
    
    nFlag = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, nFlag|O_NONBLOCK);
    
    if(listen(sockfd, 128) == -1)
    {
        perror("listen");
        uTrace.Write(Trace_Error, "Service LISTEN error.");
        return -1;;
    }
    
    return 0;
}
int Service::create_client_socket(const char* gate, int& clt_sockfd, BOOL https, struct sockaddr_storage& clt_addr, socklen_t clt_size,
    string& client_ip, string& backhost_ip, unsigned short& backhost_port)
{
    struct sockaddr_in * v4_addr;
    struct sockaddr_in6 * v6_addr;
        
    char szclientip[INET6_ADDRSTRLEN];
    if (clt_addr.ss_family == AF_INET)
    {
        v4_addr = (struct sockaddr_in*)&clt_addr;
        if(inet_ntop(AF_INET, (void*)&v4_addr->sin_addr, szclientip, INET6_ADDRSTRLEN) == NULL)
        {    
            close(clt_sockfd);
            return 0;
        }
        m_ip = ntohl(v4_addr->sin_addr.s_addr);

    }
    else if(clt_addr.ss_family == AF_INET6)
    {
        v6_addr = (struct sockaddr_in6*)&clt_addr;
        if(inet_ntop(AF_INET6, (void*)&v6_addr->sin6_addr, szclientip, INET6_ADDRSTRLEN) == NULL)
        {    
            close(clt_sockfd);
            return 0;
        }
        m_ip = ntohl(v6_addr->sin6_addr.s6_addr32[3]); 
    }
    else
    {
        m_ip = 0; 
    }
    
    backhost_ip = m_backend_host_list[gate][m_ip%m_backend_host_list.size()].ip;
    backhost_port = m_backend_host_list[gate][m_ip% m_backend_host_list.size()].port;
    
    
    client_ip = szclientip;
    
    int access_result;
    if(bwgate_base::m_permit_list.size() > 0)
    {
        access_result = FALSE;
        for(int x = 0; x < bwgate_base::m_permit_list.size(); x++)
        {
            if(strlike(bwgate_base::m_permit_list[x].c_str(), client_ip.c_str()) == TRUE)
            {
                access_result = TRUE;
                break;
            }
        }
        
        for(int x = 0; x < bwgate_base::m_reject_list.size(); x++)
        {
            if( (strlike(bwgate_base::m_reject_list[x].ip.c_str(), (char*)client_ip.c_str()) == TRUE)
                && (time(NULL) < bwgate_base::m_reject_list[x].expire) )
            {
                access_result = FALSE;
                break;
            }
        }
    }
    else
    {
        access_result = TRUE;
        for(int x = 0; x < bwgate_base::m_reject_list.size(); x++)
        {
            if( (strlike(bwgate_base::m_reject_list[x].ip.c_str(), (char*)client_ip.c_str()) == TRUE)
                && (time(NULL) < bwgate_base::m_reject_list[x].expire) )
            {
                access_result = FALSE;
                break;
            }
        }
    }
    
    if(access_result == FALSE)
    {
        close(clt_sockfd);
        return -1;
    }
    
    return 0;
}

void Service::ReloadBackend()
{
    m_backend_host_list.clear();
    TiXmlDocument xmlBackendDoc;
    xmlBackendDoc.LoadFile(bwgate_base::m_backend_list_file.c_str());
    TiXmlElement * pRootElement = xmlBackendDoc.RootElement();
    if(pRootElement)
    {
        TiXmlNode* pChildNode = pRootElement->FirstChild("backend");
        while(pChildNode)
        {
            if(pChildNode && pChildNode->ToElement())
            {        
                backend_host_t backend_host;
                
                backend_host.ip = pChildNode->ToElement()->Attribute("ip") ? pChildNode->ToElement()->Attribute("ip") : "";
                strtrim(backend_host.ip);
                
                string str_port = pChildNode->ToElement()->Attribute("port") ? pChildNode->ToElement()->Attribute("port") : "";
                strtrim(str_port);
                backend_host.port = atoi(str_port.c_str());
                
                string str_isssl = pChildNode->ToElement()->Attribute("ssl") ? pChildNode->ToElement()->Attribute("ssl") : "";
                strtrim(str_isssl);
                backend_host.is_ssl = strncasecmp(str_isssl.c_str(), "true", 4) == 0 ? TRUE : FALSE;
                
                backend_host.protocol = pChildNode->ToElement()->Attribute("protocol") ? pChildNode->ToElement()->Attribute("protocol") : "";
                strtrim(backend_host.protocol);
                
                backend_host.gate = pChildNode->ToElement()->Attribute("gate") ? pChildNode->ToElement()->Attribute("gate") : "";
                strtrim(backend_host.gate);
                m_backend_host_list[backend_host.gate].push_back(backend_host);
            }
            pChildNode = pChildNode->NextSibling("backend");
        }
    }
}

int Service::Run(int fd)
{	
	CUplusTrace uTrace(LOGNAME, LCKNAME);

	unsigned int result = 0;
	string strqueue = "/.bwgated_";
	strqueue += m_service_name;
	strqueue += "_queue";

	string strsem = "/.bwgated_";
	strsem += m_service_name;
	strsem += "_lock";
	
	mq_attr attr;
	attr.mq_maxmsg = 8;
	attr.mq_msgsize = 1448; 
	attr.mq_flags = 0;

	m_service_qid = (mqd_t)-1;
	m_service_sid = SEM_FAILED;
	
	m_service_qid = mq_open(strqueue.c_str(), O_CREAT|O_RDWR, 0644, &attr);
	m_service_sid = sem_open(strsem.c_str(), O_CREAT|O_RDWR, 0644, 1);
	if((m_service_qid == (mqd_t)-1) || (m_service_sid == SEM_FAILED))
	{		
		if(m_service_sid != SEM_FAILED)
			sem_close(m_service_sid);
	
		if(m_service_qid != (mqd_t)-1)
			mq_close(m_service_qid);

		sem_unlink(strsem.c_str());
		mq_unlink(strqueue.c_str());

		result = 1;
		write(fd, &result, sizeof(unsigned int));
		close(fd);
		return -1;
	}
	
	clear_mqueue(m_service_qid);
	
	BOOL svr_exit = FALSE;
	int queue_buf_len = attr.mq_msgsize;
	char* queue_buf_ptr = (char*)malloc(queue_buf_len);

	m_ip = 0;
    
    int nFlag;
    
    for(int i = 0; i < bwgate_base::m_max_instance_num; i++)
	{
		char pid_file[1024];
		sprintf(pid_file, "/tmp/bwgated/%s_WORKER%d.pid", m_service_name.c_str(), i);
		unlink(pid_file);
        
		WORK_PROCESS_INFO  wpinfo;
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, wpinfo.sockfds) < 0)
			fprintf(stderr, "socketpair error, %s %d\n", __FILE__, __LINE__);
        
        nFlag = fcntl(wpinfo.sockfds[0], F_GETFL, 0);
        fcntl(wpinfo.sockfds[0], F_SETFL, nFlag|O_NONBLOCK);
    
		int work_pid = fork();
		if(work_pid == 0)
		{

			if(lock_pid_file(pid_file) == false)
			{
				exit(-1);
			}
			close(wpinfo.sockfds[0]);
            
            nFlag = fcntl(wpinfo.sockfds[1], F_GETFL, 0);
            fcntl(wpinfo.sockfds[1], F_SETFL, nFlag|O_NONBLOCK);
        
			Worker* pWorker = new Worker(m_service_name.c_str(), i, wpinfo.sockfds[1]);
			if(pWorker)
			{
				pWorker->Working();
				delete pWorker;
			}
			close(wpinfo.sockfds[1]);
			exit(0);
		}
		else if(work_pid > 0)
		{
			close(wpinfo.sockfds[1]);
			wpinfo.pid = work_pid;
			m_work_processes.push_back(wpinfo);
		}
		else
		{
			fprintf(stderr, "fork error, work_pid = %d, %S %d\n", work_pid, __FILE__, __LINE__);
		}
	}
    
    int epoll_fd;
    struct epoll_event event;  
    struct epoll_event * events = new struct epoll_event[bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn]; 
    
	while(!svr_exit)
	{
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)  
        {  
          perror ("epoll_create1");  
          abort ();  
        }
        if(m_service_list)
        {
            for(int x = 0; x < MAX_SOCKFD_NUM; x++)
            {
                if(m_service_list[x] != NULL)
                {
                    close(x);
                    delete m_service_list[x];
                }
            }
            memset(m_service_list, 0, MAX_SOCKFD_NUM * sizeof(service_content_t*));
        }
        
        TiXmlDocument xmlServicesDoc;
        xmlServicesDoc.LoadFile(bwgate_base::m_service_list_file.c_str());
        TiXmlElement * pRootElement = xmlServicesDoc.RootElement();
        if(pRootElement)
        {
            TiXmlNode* pChildNode = pRootElement->FirstChild("service");
            while(pChildNode)
            {
                if(pChildNode && pChildNode->ToElement())
                {                   
                    service_content_t* service_content = new service_content_t;
                    
                    service_content->ip = pChildNode->ToElement()->Attribute("ip") ? pChildNode->ToElement()->Attribute("ip") : "";
                    strtrim(service_content->ip);
                    
                    string str_port = pChildNode->ToElement()->Attribute("port") ? pChildNode->ToElement()->Attribute("port") : "";
                    strtrim(str_port);
                    service_content->port = atoi(str_port.c_str());
                    
                    string str_isssl = pChildNode->ToElement()->Attribute("ssl") ? pChildNode->ToElement()->Attribute("ssl") : "";
                    strtrim(str_isssl);
                    service_content->is_ssl = strncasecmp(str_isssl.c_str(), "true", 4) == 0 ? TRUE : FALSE;
                    
                    service_content->protocol = pChildNode->ToElement()->Attribute("protocol") ? pChildNode->ToElement()->Attribute("protocol") : "";
                    strtrim(service_content->protocol);
                    
                    service_content->sockfd = -1;
                    
                    create_server_socket(service_content->sockfd, service_content->ip.c_str(), service_content->port);
                    if(service_content->sockfd > 0)
                    {
                        event.data.fd = service_content->sockfd;  
                        event.events = EPOLLIN;
                        int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, service_content->sockfd, &event);
                        if(m_service_list[service_content->sockfd] != NULL)
                            delete m_service_list[service_content->sockfd];
                        m_service_list[service_content->sockfd] = service_content;
                    }
                }
                pChildNode = pChildNode->NextSibling("service");
            }
        }
        
        
        ReloadBackend();
        
		int nFlag;

		result = 0;
		write(fd, &result, sizeof(unsigned int));
		close(fd);
        struct timespec ts;
		stQueueMsg* pQMsg;
		int rc;
		while(1)
		{	
			waitpid(-1, NULL, WNOHANG);

			clock_gettime(CLOCK_REALTIME, &ts);
			rc = mq_timedreceive(m_service_qid, queue_buf_ptr, queue_buf_len, 0, &ts);

			if( rc != -1)
			{
				pQMsg = (stQueueMsg*)queue_buf_ptr;
				if(pQMsg->cmd == MSG_EXIT)
				{
                    for(int j = 0; j < m_work_processes.size(); j++)
					{
						CLIENT_PARAM client_param;
						client_param.ctrl = SessionParamQuit;
						
						send_sockfd(m_work_processes[j].sockfds[0], 0, &client_param);
					}
                    
					svr_exit = TRUE;
					break;
				}
				else if(pQMsg->cmd == MSG_GLOBAL_RELOAD)
				{
					bwgate_base::UnLoadConfig();
					bwgate_base::LoadConfig();
                    ReloadBackend();
				}
				else if(pQMsg->cmd == MSG_ACCESS_RELOAD)
				{
					bwgate_base::LoadAccessList();
				}
				else if(pQMsg->cmd == MSG_REJECT_APPEND)
				{
					//firstly erase the expire record
					vector<stReject>::iterator x;
					for(x = bwgate_base::m_reject_list.begin(); x != bwgate_base::m_reject_list.end();)
					{
						if(x->expire < time(NULL))
							bwgate_base::m_reject_list.erase(x);
					}
	
					stReject sr;
					sr.ip = pQMsg->data.reject_ip;
					sr.expire = time(NULL) + 5;
					bwgate_base::m_reject_list.push_back(sr);
				}
			}
			else
			{
				if(errno != ETIMEDOUT && errno != EINTR && errno != EMSGSIZE)
				{
					fprintf(stderr, "mq_timedreceive error, errno = %d, %S %d\n", errno, __FILE__, __LINE__);
					svr_exit = TRUE;
					break;
				}
				
			}
            
            int n, i;  
  
            n = epoll_wait (epoll_fd, events, bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn, 1000);
            
            for (i = 0; i < n; i++)  
            {  
                if(m_service_list[events[i].data.fd] != NULL)
                {
                    char sz_gate[512];
                    sprintf(sz_gate, "%s:%u", m_service_list[events[i].data.fd]->ip.c_str(), m_service_list[events[i].data.fd]->port);
                    
                    struct sockaddr_storage clt_addr;
                
                    socklen_t clt_size = sizeof(struct sockaddr_storage);
                    int clt_sockfd = accept(events[i].data.fd, (sockaddr*)&clt_addr, &clt_size);

                    if(clt_sockfd < 0)
                    {
                        continue;
                    }
                    
                    string client_ip;
                    string backend_ip;
                    unsigned short backend_port;
                    if(create_client_socket(sz_gate, clt_sockfd, false, clt_addr, clt_size, client_ip, backend_ip, backend_port) < 0)
                        continue;
                    
                    char pid_file[1024];
                    sprintf(pid_file, "/tmp/bwgated/%s_WORKER%d.pid",
                        m_service_name.c_str(), m_ip%m_work_processes.size());
                    
                    if(check_pid_file(pid_file) == true) /* The related process had crashed */
                    {
                        WORK_PROCESS_INFO  wpinfo;
                        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, wpinfo.sockfds) < 0)
                            fprintf(stderr, "socketpair error, %s %d\n", __FILE__, __LINE__);
                        
                        int work_pid = fork();
                        if(work_pid == 0)
                        {
                            if(lock_pid_file(pid_file) == false)
                            {
                                exit(-1);
                            }
                            close(wpinfo.sockfds[0]);
                            Worker * pWorker = new Worker(m_service_name.c_str(), m_ip%m_work_processes.size(),
                                wpinfo.sockfds[1]);
                            pWorker->Working();
                            delete pWorker;
                            close(wpinfo.sockfds[1]);
                            exit(0);
                        }
                        else if(work_pid > 0)
                        {
                            close(wpinfo.sockfds[1]);
                            wpinfo.pid = work_pid;
                            m_work_processes[m_ip%m_work_processes.size()] = wpinfo;
                        }
                        else
                        {
                            return 0;
                        }
                    }
        
                    CLIENT_PARAM client_param;
                    strncpy(client_param.client_ip, client_ip.c_str(), 127);
                    client_param.client_ip[127] = '\0';
                    
                    strncpy(client_param.backend_ip, backend_ip.c_str(), 127);
                    client_param.backend_ip[127] = '\0';
                    
                    client_param.backend_port = backend_port;

                    client_param.ctrl = SessionParamData;
                    send_sockfd(m_work_processes[m_ip%m_work_processes.size()].sockfds[0], clt_sockfd, &client_param);
                    close(clt_sockfd); //have been send out to another process, so close it in the current process.
                }   
            }
		}
	}
    delete[] events;
    close(epoll_fd);
    
	free(queue_buf_ptr);
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);

	mq_unlink(strqueue.c_str());
	sem_unlink(strsem.c_str());

	bwgate_base::UnLoadConfig();
	
	return 0;
}

