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
#include "base.h"
#include <sys/wait.h>
#include <netdb.h>
#include "util/trace.h"

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
	Session(int sockfd, const char* clientip, const char* backhost_ip, unsigned short backhost_port);
    
    int get_backendsockfd() { return m_backend_sockfd; }
    int get_clientsockfd() { return m_client_sockfd; }
    void  enable_backendsockfd() { m_backend_sockfd_established = TRUE; }
    int recv_from_client();
    int recv_from_backend();
    
    int send_to_client();
    int send_to_backend();
    
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

