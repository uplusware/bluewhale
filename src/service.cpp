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

enum CLIENT_PARAM_CTRL{
	SessionParamData = 0,
	SessionParamExt,
	SessionParamQuit
};

static void CLEAR_QUEUE(mqd_t qid)
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
//Service
Service::Service(Service_Type st)
{
	m_st = st;
	m_service_name = SVR_NAME_TBL[m_st];
}

Service::~Service()
{

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
       perror("listen");
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
int Service::create_client_socket(int& clt_sockfd, BOOL https, struct sockaddr_storage& clt_addr, socklen_t clt_size,
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
        m_next_process = ntohl(v4_addr->sin_addr.s_addr) % m_backend_host_list.size();

    }
    else if(clt_addr.ss_family == AF_INET6)
    {
        v6_addr = (struct sockaddr_in6*)&clt_addr;
        if(inet_ntop(AF_INET6, (void*)&v6_addr->sin6_addr, szclientip, INET6_ADDRSTRLEN) == NULL)
        {    
            close(clt_sockfd);
            return 0;
        }
        m_next_process = ntohl(v6_addr->sin6_addr.s6_addr32[3]) % m_backend_host_list.size(); 
    }
    else
    {
        m_next_process = 0; 
    }
    
    backhost_ip = m_backend_host_list[m_next_process].ip;
    backhost_port = m_backend_host_list[m_next_process].port;
    
    
    client_ip = szclientip;
    
    //printf("client_ip: %s, %s:%u, m_next_process: %d\n", client_ip.c_str(), backhost_ip.c_str(), backhost_port, m_next_process);
    
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

#define MAXEVENTS   40960

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
	
	CLEAR_QUEUE(m_service_qid);
	
	BOOL svr_exit = FALSE;
	int queue_buf_len = attr.mq_msgsize;
	char* queue_buf_ptr = (char*)malloc(queue_buf_len);

	m_next_process = 0;
    
    int epoll_fd;
    struct epoll_event event;  
    struct epoll_event *events = new struct epoll_event[bwgate_base::m_concurrent_conn > MAXEVENTS ? MAXEVENTS : bwgate_base::m_concurrent_conn]; 
        
	while(!svr_exit)
	{
        epoll_fd = epoll_create1 (0);
        if (epoll_fd == -1)  
        {  
          perror ("epoll_create");  
          abort ();  
        }
        
        m_service_list.clear();
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
                    service_content_t service_content;
                    service_content.ip = pChildNode->ToElement()->Attribute("ip");
                    strtrim(service_content.ip);
                    service_content.port = atoi(pChildNode->ToElement()->Attribute("port"));
                    
                    service_content.is_ssl = strncasecmp(pChildNode->ToElement()->Attribute("port"), "true", 4) == 0 ? TRUE : FALSE;
                    service_content.protocol = pChildNode->ToElement()->Attribute("protocol");;
                    service_content.sockfd = -1;
                    
                    create_server_socket(service_content.sockfd, service_content.ip.c_str(), service_content.port);
                    if(service_content.sockfd > 0)
                    {
                        event.data.fd = service_content.sockfd;  
                        event.events = EPOLLIN;
                        int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, service_content.sockfd, &event);  
        
                        m_service_list.insert(map<int, service_content_t>::value_type(service_content.sockfd, service_content));
                    }
                }
                pChildNode = pChildNode->NextSibling("service");
            }
        }
        
        
        m_backend_host_list.clear();
        TiXmlDocument xmlBackendDoc;
        xmlBackendDoc.LoadFile(bwgate_base::m_backend_list_file.c_str());
        pRootElement = xmlBackendDoc.RootElement();
        if(pRootElement)
        {
            TiXmlNode* pChildNode = pRootElement->FirstChild("backend");
            while(pChildNode)
            {
                if(pChildNode && pChildNode->ToElement())
                {        
                    backend_host_t backend_host;
                    
                    backend_host.ip = pChildNode->ToElement()->Attribute("ip");
                    backend_host.port = atoi(pChildNode->ToElement()->Attribute("port"));
                    m_backend_host_list.push_back(backend_host);
                }
                pChildNode = pChildNode->NextSibling("backend");
            }
        }
        
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
					svr_exit = TRUE;
					break;
				}
				else if(pQMsg->cmd == MSG_GLOBAL_RELOAD)
				{
					bwgate_base::UnLoadConfig();
					bwgate_base::LoadConfig();
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
  
            n = epoll_wait (epoll_fd, events, bwgate_base::m_concurrent_conn > MAXEVENTS ? MAXEVENTS : bwgate_base::m_concurrent_conn, 1000);
            
            for (i = 0; i < n; i++)  
            {  
                map<int, service_content_t>::iterator iter = m_service_list.find(events[i].data.fd);
                if(iter != m_service_list.end())
                {                    
                    struct sockaddr_storage clt_addr;
                
                    socklen_t clt_size = sizeof(struct sockaddr_storage);
                    int clt_sockfd = accept(events[i].data.fd, (sockaddr*)&clt_addr, &clt_size);

                    if(clt_sockfd < 0)
                    {
                        continue;
                    }
                    
                    string client_ip;
                    string backhost_ip;
                    unsigned short backhost_port;
                    if(create_client_socket(clt_sockfd, false, clt_addr, clt_size, client_ip, backhost_ip, backhost_port) < 0)
                        continue;
                    event.data.fd = clt_sockfd;  
                    event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;  
                    int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, clt_sockfd, &event);  
                    if (s == -1)  
                    {  
                        perror ("epoll_ctl");  
                        abort ();  
                    }
                    
                    try {
                        Session * p_session = new Session(clt_sockfd, client_ip.c_str(), backhost_ip.c_str(), backhost_port);
                        
                        p_session->accquire();
                        map<int, Session*>::iterator iter = m_session_list.find(clt_sockfd);
                        if(iter != m_session_list.end())
                        {
                            delete iter->second;
                            iter->second = p_session;
                        }
                        else
                        {
                            m_session_list.insert(map<int, Session*>::value_type(clt_sockfd, p_session));
                        }
                        
                        p_session->accquire();
                        
                        iter = m_backend_list.find(clt_sockfd);
                        if(iter != m_backend_list.end())
                        {
                            delete iter->second;
                            iter->second = p_session;
                        }
                        else
                        {
                            m_backend_list.insert(map<int, Session*>::value_type(p_session->get_backsockfd(), p_session));
                        }
                        
                        event.data.fd = p_session->get_backsockfd();  
                        event.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR; 
                    
                        int s = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, p_session->get_backsockfd(), &event);  
                        if (s == -1)  
                        {  
                            perror ("epoll_ctl");  
                            abort ();  
                        }
                        
                    }
                    catch(string* e)
                    {
                        printf("%s\n", e->c_str());
                        delete e;
                    }
                    
                }
                else
                {
                    if (events[i].events & EPOLLIN)
                    {
                        map<int, Session*>::iterator iter = m_session_list.find(events[i].data.fd);
                        if(iter != m_session_list.end())
                        {
                            Session* p_session = m_session_list[events[i].data.fd];
                            if(p_session && p_session->recv_from_client() < 0)
                            {
                                    struct epoll_event ev;
                                    ev.events = EPOLLIN;
                                    ev.data.fd = fd;
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                    
                                    m_session_list.erase(iter);
                                    p_session->release();
                                    close(events[i].data.fd);
                            }
                        }
                        else
                        {
                            map<int, Session*>::iterator iter = m_backend_list.find(events[i].data.fd);
                            if(iter != m_backend_list.end())
                            {
                                Session* p_session = m_backend_list[events[i].data.fd];
                                if(p_session && p_session->recv_from_backend() < 0)
                                {
                                    
                                    struct epoll_event ev;
                                    ev.events = EPOLLIN;
                                    ev.data.fd = fd;
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                    m_backend_list.erase(iter);
                                    p_session->release();
                                    close(events[i].data.fd);
                                   
                                    
                                }
                            }
                        }
                    }
                    else if (events[i].events & EPOLLOUT)
                    {
                        map<int, Session*>::iterator iter = m_session_list.find(events[i].data.fd);
                        if(iter != m_session_list.end())
                        {
                            Session* p_session = m_session_list[events[i].data.fd];
                            if(p_session && p_session->send_to_client() < 0)
                            {
                                struct epoll_event ev;
                                ev.events = EPOLLOUT;
                                ev.data.fd = fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                
                                m_session_list.erase(iter);
                                p_session->release();
                                close(events[i].data.fd);
                            }
                        }
                        else
                        {
                            map<int, Session*>::iterator iter = m_backend_list.find(events[i].data.fd);
                            if(iter != m_backend_list.end())
                            {
                                Session* p_session = m_backend_list[events[i].data.fd];
                                if(p_session && p_session->send_to_backend() < 0)
                                {
                                    struct epoll_event ev;
                                    ev.events = EPOLLOUT;
                                    ev.data.fd = fd;
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                    
                                    m_backend_list.erase(iter);
                                    p_session->release();
                                    close(events[i].data.fd);
                                }
                            }
                        }
                    }
                    else if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR)
                    {
                        map<int, Session*>::iterator iter = m_session_list.find(events[i].data.fd);
                        if(iter != m_session_list.end())
                        {
                            Session* p_session = m_session_list[events[i].data.fd];
                            if(p_session)
                            {
                                struct epoll_event ev;
                                ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                                ev.data.fd = fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);

                                m_session_list.erase(iter);
                                p_session->release();
                                close(events[i].data.fd);
                            }
                        }
                        else
                        {
                            map<int, Session*>::iterator iter = m_backend_list.find(events[i].data.fd);
                            if(iter != m_backend_list.end())
                            {
                                Session* p_session = m_backend_list[events[i].data.fd];
                                if(p_session)
                                {
                                    struct epoll_event ev;
                                    ev.events = EPOLLOUT | EPOLLIN | EPOLLHUP | EPOLLERR;
                                    ev.data.fd = fd;
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                                    
                                    m_backend_list.erase(iter);
                                    p_session->release();
                                    close(events[i].data.fd);
                                }
                            }
                        }
                    }
                }   
            }
		}
	}
    delete[] events;
    close(epoll_fd);
    
    map<int, service_content_t>::iterator it;
    for(it = m_service_list.begin(); it != m_service_list.end(); ++it)
    {
        close(it->first);
    }
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

