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
	stHTTP = 1,
} Service_Type;

typedef struct{
    char buf[4096];
    unsigned int len;
    unsigned int cur;
}buf_desc;

class Session
{
protected:
	int m_sockfd;
    int m_back_sockfd;
    SSL * m_ssl;
	string m_clientip;
    X509* m_client_cert;
    
    list<buf_desc*> m_client_bufs;
    list<buf_desc*> m_backend_bufs;
    
    unsigned long m_use_count;
public:
	Session(int sockfd, SSL* ssl, const char* clientip, X509* client_cert, const char* backhost_ip, unsigned short backhost_port);
	virtual ~Session();
    
    int get_backsockfd() { return m_back_sockfd; }
    
    int recv_from_client();
    int recv_from_backend();
    
    int send_to_client();
    int send_to_backend();
    
    void accquire()
    {
        m_use_count++;
    }
    
    void release()
    {
        m_use_count--;
        if(m_use_count == 0)
            delete this;
    }
};
#endif /* _SESSION_H_*/

