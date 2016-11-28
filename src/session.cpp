/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/

#include "session.h"

Session::Session(int sockfd, const char* clientip, const char* backhost_ip, unsigned short backhost_port)
{
    m_client_bufs.clear();
     
    m_use_count = 0;
    m_client_sockfd = sockfd;
	m_clientip = clientip;
    
    m_backend_sockfd = -1;
    
    struct addrinfo hints;      
    struct addrinfo *servinfo, *curr;  
    struct sockaddr_in *sa;
    struct sockaddr_in6 *sa6;
    
	int res; 
	
	/* struct addrinfo hints; */
    struct addrinfo *server_addr, *rp;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    
    char sz_port[32];
    sprintf(sz_port, "%u", backhost_port);
    int s = getaddrinfo((backhost_ip && backhost_ip[0] != '\0') ? backhost_ip : NULL, sz_port, &hints, &server_addr);
    if (s != 0)
    {
       throw(new string("getaddrinfo error"));
       return;
    }
    
    for (rp = server_addr; rp != NULL; rp = rp->ai_next)
    {
       m_backend_sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
       if (m_backend_sockfd == -1)
           continue;
       
	    int flags = fcntl(m_backend_sockfd, F_GETFL, 0); 
	    fcntl(m_backend_sockfd, F_SETFL, flags | O_NONBLOCK);
	
        connect(m_backend_sockfd, rp->ai_addr, rp->ai_addrlen);
        break;
    }

    freeaddrinfo(server_addr);           /* No longer needed */
    
}

Session::~Session()
{
    while(send_to_backend() > 0)
    {
        continue;
    }
    
    while(send_to_client() > 0)
    {
        continue;
    }
    
    list<buf_desc*>::iterator itor;
    
    for(itor = m_client_bufs.begin(); itor != m_client_bufs.end(); ++itor)
    {
        delete *itor;
    } 
    
    for(itor = m_backend_bufs.begin(); itor != m_backend_bufs.end(); ++itor)
    {
        delete *itor;
    }
    
    if(m_backend_sockfd > 0)
    {
        close(m_backend_sockfd);
        m_backend_sockfd = -1;
    }
    if(m_client_sockfd > 0)
    {
        close(m_client_sockfd);
        m_client_sockfd = -1;
    }
}

int Session::recv_from_client()
{
    if(m_client_bufs.size() < 10)
    {
        if(m_client_bufs.size() > 0)
        {
            buf_desc * bd = m_client_bufs.back();
            if(bd->len <= BUF_DESC_REUSE_SIZE)
            {
                int r = recv(m_client_sockfd, bd->buf + bd->len, BUF_DESC_MAX_SIZE - bd->len, 0);
                if(r > 0)
                {
                    bd->len += r;
                    return bd->len;
                }
                else
                {
                    close(m_client_sockfd);
                    m_client_sockfd = -1;
                    return -1;
                }
            }
        }
        //continue
        buf_desc * bd = new buf_desc;
        bd->len = recv(m_client_sockfd, bd->buf, BUF_DESC_MAX_SIZE, 0);
        if(bd->len > 0)
        {
            bd->cur = 0;
            m_client_bufs.push_back(bd);
            send_to_backend();
            return bd->len;
        }
        else
        {
            close(m_client_sockfd);
            m_client_sockfd = -1;
            delete bd;
            return -1;
        }
    }
    else
        send_to_backend();
    return 0;
}

int Session::recv_from_backend()
{
    if(m_backend_bufs.size() < 10)
    {
        if(m_backend_bufs.size() > 0)
        {
            buf_desc * bd = m_backend_bufs.back();
            if(bd->len <= BUF_DESC_REUSE_SIZE)
            {
                int r = recv(m_backend_sockfd, bd->buf + bd->len, BUF_DESC_MAX_SIZE - bd->len, 0);
                if(r > 0)
                {
                    bd->len += r;
                    return bd->len;
                }
                else
                {
                    close(m_backend_sockfd);
                    m_backend_sockfd = -1;
                    return -1;
                }
            }
        }
        //continue
        buf_desc * bd = new buf_desc;
        bd->len = recv(m_backend_sockfd, bd->buf, BUF_DESC_MAX_SIZE, 0);
        if(bd->len > 0)
        {
            bd->cur = 0;
            m_backend_bufs.push_back(bd);
            send_to_client();
            return bd->len;
        }
        else
        {
            delete bd;
            close(m_backend_sockfd);
            m_backend_sockfd = -1;
            return -1;
        }
    }
    else
        send_to_client();
    return 0;
}

int Session::send_to_client()
{
    if(m_backend_bufs.size() > 0)
    {
        buf_desc * bd = m_backend_bufs.front();
        
        int s = send(m_client_sockfd, bd->buf + bd->cur, bd->len - bd->cur, 0);
        if(s > 0)
        {
            
            bd->cur += s;
            if(bd->cur == bd->len)
            {
                delete bd;
                m_backend_bufs.pop_front();
            }
            
            return s;
        }
        else
        {
            close(m_client_sockfd);
            m_client_sockfd = -1;
            return -1;
        }
    }
    else
    {
        if(m_backend_sockfd == -1)
        {
            close(m_client_sockfd);
            m_client_sockfd = -1;
            return -1;
        }
    }
    
    return 0;
}

int Session::send_to_backend()
{
    if(m_client_bufs.size() > 0)
    {
        buf_desc * bd = m_client_bufs.front();
        int s = send(m_backend_sockfd, bd->buf + bd->cur, bd->len - bd->cur, 0);
        if(s > 0)
        {
            bd->cur += s;
            if(bd->cur == bd->len)
            {
                delete bd;
                m_client_bufs.pop_front();
            }
            return s;
        }
        else
        {
            close(m_backend_sockfd);
            m_backend_sockfd = -1;
            return -1;
        }
    }
    else
    {
        if(m_client_sockfd == -1)
        {
            close(m_backend_sockfd);
            m_backend_sockfd = -1;
            return -1;
        }
    }
    return 0;
}
