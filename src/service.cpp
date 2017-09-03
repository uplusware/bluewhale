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

#define MAX_EVENTS_NUM  655360
#define MAX_SOCKFD_NUM  655360

enum CLIENT_PARAM_CTRL{
	SessionParamData = 0,
	SessionParamQuit
};

void close_fd(int fd)
{
    if(fd > 0)
    {
        /* printf("close fd: %d on %u\n", fd, getpid()); */
        close(fd);
    }
}

typedef struct {
	CLIENT_PARAM_CTRL ctrl;
	char client_ip[128];
    char backend_ip[128];
    unsigned short backend_port;
    
    char backup_backend_ip1[128];
    unsigned short backup_backend_port1;
    
    char backup_backend_ip2[128];
    unsigned short backup_backend_port2;
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
    int r = 0;
    do{
        r = sendmsg(sfd, &msg, MSG_DONTWAIT);
        if(r < 0)
        {
            fprintf(stderr, "%s %u# sendmsg: %s\n", __FILE__, __LINE__, strerror(errno));
            if(errno == EAGAIN)
                continue;
        }
    }while(0);
    return r;

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
    
    do{
        nrecv = recvmsg(sfd, &msg, 0);
        if(nrecv <= 0)  
        {  
            if(errno == EAGAIN)
                continue;
            return nrecv;  
        }
    } while(0);

    cmptr = CMSG_FIRSTHDR(&msg);  
    if((cmptr != NULL) && (cmptr->cmsg_len == CMSG_LEN(sizeof(int))))  
    {  
        if(cmptr->cmsg_level != SOL_SOCKET)  
        {  
            fprintf(stderr, "control level != SOL_SOCKET/n");  
            exit(-1); 
        }  
        if(cmptr->cmsg_type != SCM_RIGHTS)  
        {  
            fprintf(stderr, "control type != SCM_RIGHTS/n");  
            exit(-1);  
        } 
        *fd_file = *((int*)CMSG_DATA(cmptr));  
    }  
    else  
    {  
        if(cmptr == NULL)
			fprintf(stderr, "null cmptr, fd not passed.\n");  
        else
			fprintf(stderr, "message len[%d] if incorrect.\n", cmptr->cmsg_len);  
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
                close_fd(x);
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
                close_fd(x);
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
        fprintf(stderr, "%s %u# epoll_create1: %s\n", __FILE__, __LINE__, strerror(errno));
        return;  
    }
        
    struct epoll_event * events = new struct epoll_event[bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn]; 
    
    struct epoll_event event;  
    event.data.fd = m_sockfd;  
    event.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, m_sockfd, &event); 
    if (s == -1)  
    {  
        fprintf(stderr, "%s %u# epoll_ctl: %s\n", __FILE__, __LINE__, strerror(errno));
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
                if(recv_sockfd(m_sockfd, &clt_sockfd, &client_param)  < 0 && clt_sockfd < 0)
                {
                    fprintf(stderr, "recv_sockfd error, clt_sockfd = %d %s %d\n", clt_sockfd, __FILE__, __LINE__);
                    continue;
                }

                if(client_param.ctrl == SessionParamQuit)
                {
                    printf("QUIT from Worker %u\n", m_process_seq);
                    bQuit = true;
                }
                else
                {
                    event.data.fd = clt_sockfd;  
                    event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;  
                    if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, clt_sockfd, &event) == -1)  
                    {  
                        fprintf(stderr, "%s %u# epoll_ctl: %s\n", __FILE__, __LINE__, strerror(errno));
                        bQuit = true;
                        break;
                    }
                    
                    Session * pSession = NULL;
                        
                    try { /* try connect 1st backend */
                        pSession = new Session(clt_sockfd, client_param.client_ip, client_param.backend_ip, client_param.backend_port);
                    }
                    catch(string* e)
                    {
                        fprintf(stderr, "%s\n", e->c_str());
                        delete e;
                        
                        try {/* try connect 2nd backend */
                            pSession = new Session(clt_sockfd, client_param.client_ip, client_param.backup_backend_ip1, client_param.backup_backend_port1);
                        }
                        catch(string* e)
                        {
                            fprintf(stderr, "%s\n", e->c_str());
                            delete e;
                            
                            try { /* try connect 3nd backend */
                                pSession = new Session(clt_sockfd, client_param.client_ip, client_param.backup_backend_ip2, client_param.backup_backend_port2);
                            }
                            catch(string* e)
                            {
                                fprintf(stderr, "%s\n", e->c_str());
                                delete e;
                            }
                        }
                    }
                    
                    if(pSession)
                    {
                        pSession->accquire();
                        
                        if(m_client_list[pSession->get_clientsockfd()] != NULL)
                        {
                            m_client_list[pSession->get_clientsockfd()]->release();
                        }
                        m_client_list[pSession->get_clientsockfd()] = pSession;
                        
                        pSession->accquire();
                        
                        if(m_backend_list[pSession->get_backendsockfd()] != NULL)
                        {
                            m_backend_list[pSession->get_backendsockfd()]->release();
                        }
                        m_backend_list[pSession->get_backendsockfd()] = pSession;
                        
                        event.data.fd = pSession->get_backendsockfd();  
                        event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR; 
                    
                        int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, pSession->get_backendsockfd(), &event);  
                        if (s == -1)  
                        {  
                            fprintf(stderr, "%s %u# epoll_ctl: %s\n", __FILE__, __LINE__, strerror(errno));
                            bQuit = true;
                        }
                    }
                }
            }
            else
            {
                if (events[i].events & EPOLLIN)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_client_list[events[i].data.fd];
                        if(pSession && pSession->recv_from_client() < 0)
                        {
                                struct epoll_event ev;
                                ev.events = EPOLLIN;
                                ev.data.fd = events[i].data.fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                
                                m_client_list[events[i].data.fd] = NULL;
                                
                                pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_backend_list[events[i].data.fd];
                        if(pSession && pSession->recv_from_backend() < 0)
                        {
                            
                            struct epoll_event ev;
                            ev.events = EPOLLIN;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);

                            m_backend_list[events[i].data.fd] = NULL;
                            pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                }
                else if (events[i].events & EPOLLOUT)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_client_list[events[i].data.fd];
                        if(pSession)
                            pSession->enable_backendsockfd();
                        
                        if(pSession && pSession->send_to_client() < 0)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_client_list[events[i].data.fd] = NULL;
                                
                            pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_backend_list[events[i].data.fd];
                        if(pSession && pSession->send_to_backend() < 0)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_backend_list[events[i].data.fd] = NULL;
                            pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                }
                else if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR)
                {
                    if(m_client_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_client_list[events[i].data.fd];
                        if(pSession)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);

                            m_client_list[events[i].data.fd] = NULL;
                                
                            pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                    else if(m_backend_list[events[i].data.fd] != NULL)
                    {
                        Session* pSession = m_backend_list[events[i].data.fd];
                        if(pSession)
                        {
                            struct epoll_event ev;
                            ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                            ev.data.fd = events[i].data.fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                            
                            m_backend_list[events[i].data.fd] = NULL;
                            
                            pSession->release(events[i].data.fd); //delete itself
                        }
                    }
                }
            }
        }
		
	}
    delete[] events;
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
                close_fd(x);
                delete m_service_list[x];
            }
        }
        delete[] m_service_list;
    }
    m_service_list = NULL;
}

void Service::Stop()
{
	string strqueue = BWGATED_POSIX_PREFIX;
	strqueue += m_service_name;
	strqueue += BWGATED_POSIX_QUEUE_SUFFIX;

	string strsem = BWGATED_POSIX_PREFIX;
	strsem += m_service_name;
	strsem += BWGATED_POSIX_SEMAPHORE_SUFFIX;
	
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
	string strqueue = BWGATED_POSIX_PREFIX;
	strqueue += m_service_name;
	strqueue += BWGATED_POSIX_QUEUE_SUFFIX;

	string strsem = BWGATED_POSIX_PREFIX;
	strsem += m_service_name;
	strsem += BWGATED_POSIX_SEMAPHORE_SUFFIX;
	
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
	string strqueue = BWGATED_POSIX_PREFIX;
	strqueue += m_service_name;
	strqueue += BWGATED_POSIX_QUEUE_SUFFIX;

	string strsem = BWGATED_POSIX_PREFIX;
	strsem += m_service_name;
	strsem += BWGATED_POSIX_SEMAPHORE_SUFFIX;
	
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
	string strqueue = BWGATED_POSIX_PREFIX;
	strqueue += m_service_name;
	strqueue += BWGATED_POSIX_QUEUE_SUFFIX;

	string strsem = BWGATED_POSIX_PREFIX;
	strsem += m_service_name;
	strsem += BWGATED_POSIX_SEMAPHORE_SUFFIX;
	
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

int Service::create_server_socket(int& sockfd, const char* hostip, unsigned short port)
{
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
       fprintf(stderr, "%s %u# bind: %s\n", __FILE__, __LINE__, strerror(errno));
       close_fd(sockfd);
    }
    
    if (rp == NULL)
    {               /* No address succeeded */
          return -1;
    }

    freeaddrinfo(server_addr);           /* No longer needed */
    
    nFlag = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, nFlag|O_NONBLOCK);
    
    if(listen(sockfd, 128) == -1)
    {
        fprintf(stderr, "%s %u# listen(%s:%u): %s\n", __FILE__, __LINE__, hostip ? hostip : "", port, strerror(errno));
        return -1;;
    }
    
    return 0;
}
int Service::create_client_socket(const char* gate, int& clt_sockfd, BOOL https, struct sockaddr_storage& clt_addr, socklen_t clt_size,
    string& client_ip, unsigned int& ip_lowbytes)
{
    struct sockaddr_in * v4_addr;
    struct sockaddr_in6 * v6_addr;
        
    char szclientip[INET6_ADDRSTRLEN];
    if (clt_addr.ss_family == AF_INET)
    {
        v4_addr = (struct sockaddr_in*)&clt_addr;
        if(inet_ntop(AF_INET, (void*)&v4_addr->sin_addr, szclientip, INET6_ADDRSTRLEN) == NULL)
        {    
            close_fd(clt_sockfd);
            return 0;
        }
        ip_lowbytes = ntohl(v4_addr->sin_addr.s_addr);

    }
    else if(clt_addr.ss_family == AF_INET6)
    {
        v6_addr = (struct sockaddr_in6*)&clt_addr;
        if(inet_ntop(AF_INET6, (void*)&v6_addr->sin6_addr, szclientip, INET6_ADDRSTRLEN) == NULL)
        {    
            close_fd(clt_sockfd);
            return 0;
        }
        ip_lowbytes = ntohl(v6_addr->sin6_addr.s6_addr32[3]); 
    }
    else
    {
        ip_lowbytes = 0; 
    }
    
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
        close_fd(clt_sockfd);
        return -1;
    }
    
    return 0;
}

void Service::ReloadBackend(CUplusTrace& uTrace)
{
    m_backend_host_list.clear();
    TiXmlDocument* xmlBackendDoc = new TiXmlDocument();
    xmlBackendDoc->LoadFile(bwgate_base::m_backend_list_file.c_str());
    TiXmlElement * pRootElement = xmlBackendDoc->RootElement();
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
                
                string str_weight;
                str_weight = pChildNode->ToElement()->Attribute("weight") ? pChildNode->ToElement()->Attribute("weight") : "";
                strtrim(str_weight);
                if(str_weight != "")
                    backend_host.weight = atoi(str_weight.c_str());
                else
                    backend_host.weight = 1;
                
                if(backend_host.ip != "" && backend_host.port > 0 && backend_host.gate != "")
                {
                    m_backend_host_list[backend_host.gate].next_one = 0;
                    m_backend_host_list[backend_host.gate].curr_weight = 0;
                    m_backend_host_list[backend_host.gate].backends.push_back(backend_host);
                    uTrace.Write(Trace_Msg, "Load backend: %s%s@[%s:%u]->%s", backend_host.protocol.c_str(),
                        backend_host.is_ssl ? "S" : "",
                        backend_host.ip.c_str(),
                        backend_host.port, backend_host.gate.c_str());
                }
            }
            pChildNode = pChildNode->NextSibling("backend");
        }
    }
    delete xmlBackendDoc;
}

int Service::Run(int fd)
{	
    CUplusTrace uTrace(BWGATED_SERVICE_LOGNAME, BWGATED_SERVICE_LCKNAME);
    
	unsigned int result = 0;
	string strqueue = BWGATED_POSIX_PREFIX;
	strqueue += m_service_name;
	strqueue += BWGATED_POSIX_QUEUE_SUFFIX;

	string strsem = BWGATED_POSIX_PREFIX;
	strsem += m_service_name;
	strsem += BWGATED_POSIX_SEMAPHORE_SUFFIX;
	
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
    
    int nFlag;  
    for(int i = 0; i < bwgate_base::m_max_instance_num; i++)
	{
		char pid_file[1024];
		sprintf(pid_file, "/tmp/bwgated/%s_WORKER%d.pid", m_service_name.c_str(), i);
		unlink(pid_file);
        
		WORK_PROCESS_INFO  wpinfo;
        wpinfo.sockfds[0] = -1;
        wpinfo.sockfds[1] = -1;
        wpinfo.pid = 0;
        if(bwgate_base::m_instance_prestart == TRUE)
        {
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, wpinfo.sockfds) < 0)
            {
                uTrace.Write(Trace_Error, "socketpair error, errno = %d, %s, %s %d", errno, strerror(errno), __FILE__, __LINE__);
            }
            
            nFlag = fcntl(wpinfo.sockfds[0], F_GETFL, 0);
            fcntl(wpinfo.sockfds[0], F_SETFL, nFlag|O_NONBLOCK);
            
            nFlag = fcntl(wpinfo.sockfds[1], F_GETFL, 0);
            fcntl(wpinfo.sockfds[1], F_SETFL, nFlag|O_NONBLOCK);
                
            int work_pid = fork();
            if(work_pid == 0)
            {
                if(lock_pid_file(pid_file) == false)
                {
                    exit(-1);
                }
                close(wpinfo.sockfds[0]);
                wpinfo.sockfds[0] = -1;
            
                Worker* pWorker = new Worker(m_service_name.c_str(), i, wpinfo.sockfds[1]);
                if(pWorker)
                {
                    pWorker->Working();
                    delete pWorker;
                }
                close(wpinfo.sockfds[1]);
                wpinfo.sockfds[1] = -1;
                exit(0);
            }
            else if(work_pid > 0)
            {
                close(wpinfo.sockfds[1]);
                wpinfo.sockfds[1] = -1;
                
                wpinfo.pid = work_pid;
                
            }
            else
            {
                uTrace.Write(Trace_Error, "fork error, work_pid = %d, errno = %d, %s, %s %d", work_pid, errno, strerror(errno), __FILE__, __LINE__);
            }
        }        
        m_work_processes.push_back(wpinfo);
	}
    
    int epoll_fd;
    struct epoll_event event;  
    struct epoll_event * events = new struct epoll_event[bwgate_base::m_instance_max_concurrent_conn > MAX_EVENTS_NUM ? MAX_EVENTS_NUM : bwgate_base::m_instance_max_concurrent_conn]; 
    
	while(!svr_exit)
	{
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)  
        {  
            uTrace.Write(Trace_Error, "epoll_create1 errno = %d, %s, %s %d", errno, strerror(errno), __FILE__, __LINE__);  
            break;  
        }
        if(m_service_list)
        {
            for(int x = 0; x < MAX_SOCKFD_NUM; x++)
            {
                if(m_service_list[x] != NULL)
                {
                    close_fd(x);
                    delete m_service_list[x];
                }
            }
            memset(m_service_list, 0, MAX_SOCKFD_NUM * sizeof(service_content_t*));
        }
        
        TiXmlDocument* xmlServicesDoc = new TiXmlDocument();
        xmlServicesDoc->LoadFile(bwgate_base::m_service_list_file.c_str());
        TiXmlElement * pRootElement = xmlServicesDoc->RootElement();
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
                        
                       uTrace.Write(Trace_Msg, "Create service: %s%s@[%s:%u]", service_content->protocol.c_str(),
                            service_content->is_ssl ? "S" : "",
                            service_content->ip.c_str(),
                            service_content->port);
                    }
                }
                pChildNode = pChildNode->NextSibling("service");
            }
        }
        delete xmlServicesDoc;
        
        ReloadBackend(uTrace);
        
		int nFlag;

		result = 0;
		write(fd, &result, sizeof(unsigned int));
		close(fd);
        struct timespec ts;
		
        int queue_buf_len = attr.mq_msgsize;
        char* queue_buf_ptr = (char*)malloc(queue_buf_len);
            
        stQueueMsg* pQMsg = NULL;
		int rc;
        m_next_process = 0;
        
		while(1)
		{	
			pid_t w = waitpid(-1, NULL, WNOHANG);
            if(w > 0)
                printf("pid %u exits\n", w);
            
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
						if(m_work_processes[j].sockfds[0] > 0)
                        {
                            send_sockfd(m_work_processes[j].sockfds[0], 0, &client_param);
                        }
					}
                    
					svr_exit = TRUE;
					break;
				}
				else if(pQMsg->cmd == MSG_GLOBAL_RELOAD)
				{
					bwgate_base::UnLoadConfig();
					bwgate_base::LoadConfig();
                    ReloadBackend(uTrace);
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
					uTrace.Write(Trace_Error, "mq_timedreceive error, errno = %d, %s, %s %d\n", errno, strerror(errno), __FILE__, __LINE__);
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
                    
                    string backup_backend_ip1;
                    unsigned short backup_backend_port1;
                    
                    string backup_backend_ip2;
                    unsigned short backup_backend_port2;
                    
                    unsigned int ip_lowbytes;
                    if(create_client_socket(sz_gate, clt_sockfd, false, clt_addr, clt_size, client_ip, ip_lowbytes) < 0)
                    {
                        close(clt_sockfd);
                        continue;
                    }
                    
                    map<string, backends_info_t>::iterator backend_host_group = m_backend_host_list.find(sz_gate);
    
                    if(backend_host_group == m_backend_host_list.end() || backend_host_group->second.backends.size() == 0)
                    {
                        close(clt_sockfd);
                        continue;
                    }
                    
                    unsigned int backend_host_index = 0;
                    unsigned int backup_backend_host_index1 = 0;
                    unsigned int backup_backend_host_index2 = 0;
                    
                    if(bwgate_base::m_instance_balance_scheme[0] == 'R')
                    {
                        if(backend_host_group->second.curr_weight == 0)
                        {
                            backend_host_group->second.curr_weight = backend_host_group->second.backends[backend_host_index].weight;
                        }
                        
                        backend_host_index = backend_host_group->second.next_one % backend_host_group->second.backends.size();
                        
                        backup_backend_host_index1 = (backend_host_index + 1) % backend_host_group->second.backends.size();
                        backup_backend_host_index2 = (backend_host_index + 2) % backend_host_group->second.backends.size();
                        
                        backend_host_group->second.curr_weight--;
                        
                        if(backend_host_group->second.curr_weight == 0)
                        {
                            backend_host_group->second.next_one++;
                        }
                        
                        m_next_process++;
                        
                    }
                    else
                    {
                        backend_host_index = ip_lowbytes % backend_host_group->second.backends.size();
                        backup_backend_host_index1 = (ip_lowbytes + 1) % backend_host_group->second.backends.size();
                        backup_backend_host_index2 = (ip_lowbytes + 2) % backend_host_group->second.backends.size();
                        
                        m_next_process = ip_lowbytes;
                    }
                    
                    m_next_process = m_next_process % m_work_processes.size();
                    
                    backend_ip = backend_host_group->second.backends[backend_host_index].ip;
                    backend_port = backend_host_group->second.backends[backend_host_index].port;
                    
                    backup_backend_ip1 = backend_host_group->second.backends[backup_backend_host_index1].ip;
                    backup_backend_port1 = backend_host_group->second.backends[backup_backend_host_index1].port;
                    
                    backup_backend_ip2 = backend_host_group->second.backends[backup_backend_host_index2].ip;
                    backup_backend_port2 = backend_host_group->second.backends[backup_backend_host_index2].port;
                        
                    char pid_file[1024];
                    sprintf(pid_file, "/tmp/bwgated/%s_WORKER%d.pid", m_service_name.c_str(), m_next_process);
                    if(check_pid_file(pid_file) == true) /* The related process had crashed */
                    {
                        WORK_PROCESS_INFO  wpinfo;
                        wpinfo.sockfds[0] = -1;
                        wpinfo.sockfds[1] = -1;
                        wpinfo.pid = 0;
        
                        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, wpinfo.sockfds) < 0)
                        {
                            fprintf(stderr, "socketpair error, %s %d, %s\n", __FILE__, __LINE__, strerror(errno));
                            continue;
                        }
                        nFlag = fcntl(wpinfo.sockfds[0], F_GETFL, 0);
                        fcntl(wpinfo.sockfds[0], F_SETFL, nFlag|O_NONBLOCK);
                        
                        nFlag = fcntl(wpinfo.sockfds[1], F_GETFL, 0);
                        fcntl(wpinfo.sockfds[1], F_SETFL, nFlag|O_NONBLOCK);
                            
                        int work_pid = fork();
                        if(work_pid == 0)
                        {
                            close_fd(clt_sockfd);
                            if(lock_pid_file(pid_file) == false)
                            {
                                exit(-1);
                            }
                            close_fd(wpinfo.sockfds[0]);
                            wpinfo.sockfds[0] = -1;
                            uTrace.Write(Trace_Msg, "Create worker process [%u]", m_next_process);
                            Worker* pWorker = new Worker(m_service_name.c_str(), m_next_process, wpinfo.sockfds[1]);
                            if(pWorker)
                            {
                                pWorker->Working();
                                delete pWorker;
                            }
                            close_fd(wpinfo.sockfds[1]);
                            wpinfo.sockfds[1] = -1;
                            uTrace.Write(Trace_Msg, "Quit from workder process [%d]\n", m_next_process);
                            exit(0);
                        }
                        else if(work_pid > 0)
                        {
                            close_fd(wpinfo.sockfds[1]);
                            wpinfo.sockfds[1] = -1;
                            
                            wpinfo.pid = work_pid;
                            
                            if(m_work_processes[m_next_process].sockfds[0] > 0)
                                close(m_work_processes[m_next_process].sockfds[0]);
                            
                            if(m_work_processes[m_next_process].sockfds[1] > 0)
                                close(m_work_processes[m_next_process].sockfds[1]);
                            
                            m_work_processes[m_next_process].sockfds[0] = wpinfo.sockfds[0];
                            m_work_processes[m_next_process].sockfds[1] = wpinfo.sockfds[1];
                            m_work_processes[m_next_process].pid = wpinfo.pid;
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
                    
                    strncpy(client_param.backup_backend_ip1, backup_backend_ip1.c_str(), 127);
                    client_param.backup_backend_ip1[127] = '\0';
                    client_param.backup_backend_port1 = backup_backend_port1;
                    
                    strncpy(client_param.backup_backend_ip2, backup_backend_ip2.c_str(), 127);
                    client_param.backup_backend_ip2[127] = '\0';
                    client_param.backup_backend_port2 = backup_backend_port2;              

                    client_param.ctrl = SessionParamData;
                    if(m_work_processes[m_next_process].sockfds[0] > 0)
                    {
                        send_sockfd(m_work_processes[m_next_process].sockfds[0], clt_sockfd, &client_param);
                    }
                    close_fd(clt_sockfd); //have been send out to another process, so close it in the current process.
                }   
            }
		}
        
        free(queue_buf_ptr);
	}
    delete[] events;
    close_fd(epoll_fd);
    
	if(m_service_qid != (mqd_t)-1)
		mq_close(m_service_qid);
	if(m_service_sid != SEM_FAILED)
		sem_close(m_service_sid);

	mq_unlink(strqueue.c_str());
	sem_unlink(strsem.c_str());

	bwgate_base::UnLoadConfig();
	
	return 0;
}

