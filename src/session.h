/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/

#ifndef _SESSION_H_
#define _SESSION_H_
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include "base.h"
#include <sys/wait.h>
#include <netdb.h>
#include <sys/epoll.h>  
#include "util/trace.h"
enum gate_type
{
    gate_balancer = 0,
    gate_http_proxy,
    gate_sock5_proxy
};

typedef enum
{
	stGATE = 1,
} Service_Type;

#define BUF_DESC_MAX_SIZE     4096
#define BUF_DESC_REUSE_SIZE   (BUF_DESC_MAX_SIZE - BUF_DESC_MAX_SIZE/4)

typedef struct{
    char buf[BUF_DESC_MAX_SIZE];
    unsigned int len;
    unsigned int cur;
}buf_desc;

class Session
{
protected:
	int m_epoll_fd;
	int m_client_sockfd;
    int m_backend_sockfd;
    BOOL m_backend_sockfd_established;
	string m_clientip;
    
    list<buf_desc*> m_client_bufs;
    list<buf_desc*> m_backend_bufs;
    
    int m_use_count;
    //this class only could be created in heap.    
    virtual ~Session();
    
public:
	Session(int epoll_fd, int sockfd, const char* clientip, const char* backhost_ip, unsigned short backhost_port);
    int get_backend_sockfd() { return m_backend_sockfd; }
    int get_client_sockfd() { return m_client_sockfd; }
    
    void set_backend_sockfd_established() { m_backend_sockfd_established = TRUE; }
    
    int recv_from_client();
    int recv_from_backend();
    
    int send_to_client();
    int send_to_backend();
    
	void append_client_buf(const char* buf, int len);
	void append_backend_buf(const char* buf, int len);
	
    void accquire()
    {
        m_use_count++;
    }
    
    void release(int sockfd = -1)
    {
        if(sockfd > 0)
        {
            if(m_client_sockfd == sockfd)
            {
                close(m_client_sockfd);
                m_client_sockfd = -1;
            }
            else if(m_backend_sockfd == sockfd)
            {
                close(m_backend_sockfd);
                m_backend_sockfd = -1;
            }
        }
        m_use_count--;
        if(m_use_count <= 0)
            delete this;
    }
};
#endif /* _SESSION_H_*/

