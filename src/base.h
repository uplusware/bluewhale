/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/
#ifndef _MAILSYS_H_
#define _MAILSYS_H_

#define CONFIG_FILTER_PATH	"/etc/bwgated/mfilter.xml"
#define CONFIG_FILE_PATH	"/etc/bwgated/bwgated.conf"
#define PERMIT_FILE_PATH	"/etc/bwgated/permit.list"
#define REJECT_FILE_PATH	"/etc/bwgated/reject.list"
#define SERVICE_LIST_FILE_PATH	"/etc/bwgated/services.xml"
#define BACKEND_LIST_FILE_PATH	"/etc/bwgated/backends.xml"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <mqueue.h>
#include <semaphore.h>
#include <fstream>
#include <list>
#include <map>
#include <pthread.h>

#include "util/general.h"
#include "util/base64.h"

using namespace std;

#define ERISE_DES_KEY	"1001101001"

#define MAX_USERNAME_LEN	16
#define MAX_PASSWORD_LEN	16
#define MAX_EMAIL_LEN	5000 //about 5M attachment file

#define MSG_EXIT				0xFF
#define MSG_GLOBAL_RELOAD		0xFE
#define MSG_REJECT_APPEND   	0xFC
#define MSG_ACCESS_RELOAD		0xFB
#define MSG_EXTENSION_RELOAD	0xFA

typedef struct
{
	unsigned char aim;
	unsigned char cmd;
	union
	{
		char spool_uid[256];
		char reject_ip[256];
	} data;
}stQueueMsg;

typedef struct
{
	string ip;
	time_t expire;
}stReject;

class linesock
{
public:
	linesock(int fd)
	{
		dbufsize = 0;
		sockfd = fd;
		dbuf = (char*)malloc(4096);
		if(dbuf)
		{
			dbufsize = 4096;
		}
		dlen = 0;
	}
	
	virtual ~linesock()
	{
		if(dbuf)
			free(dbuf);
	}

	int drecv(char* pbuf, int blen)
	{
		int rlen = 0;
		
		if(blen <= dlen)
		{
			memcpy(pbuf, dbuf, blen);

			memmove(dbuf + blen, dbuf, dlen - blen);
			dlen = dlen - blen;
			
			rlen = blen;
		}
		else
		{
			
			memcpy(pbuf, dbuf, dlen);
			rlen = dlen;
			dlen = 0;
			
			int len = _Recv_(sockfd, pbuf + dlen, blen - dlen);
			if(len > 0)
			{
				rlen = rlen + len;	
			}
		}

		return rlen;
	}
	
	int lrecv(char* pbuf, int blen)
	{
		int taketime = 0;
		int res;
		fd_set mask; 
		struct timeval timeout; 
		char* p = NULL;
		int len;
		unsigned int nRecv = 0;

		int left;
		int right;
		p = dlen > 0 ? (char*)memchr(dbuf, '\n', dlen) : NULL;
		if(p != NULL)
		{
			left = p - dbuf + 1;
			right = dlen - left;
		
			if(blen >= left)
			{
				memcpy(pbuf, dbuf, left);
				memmove(dbuf, p + 1, right);
				dlen = right;
				pbuf[left] = '\0';
				return left;
			}
			else
			{
				memcpy(pbuf, dbuf, blen);
				memmove(dbuf, dbuf + blen, dlen - blen);
				dlen = dlen - blen;
				return -2;
			}
		}
		else
		{
			if(blen >= dlen)
			{
				memcpy(pbuf, dbuf, dlen);
				nRecv = dlen;
				dlen = 0;
			}
			else
			{
				memcpy(pbuf, dbuf, blen);
				memmove(dbuf, dbuf + blen, dlen - blen);
				dlen = dlen - blen;
				return -2;
			}
		}

		p = NULL;
		FD_ZERO(&mask);		
		while(1)
		{
			if(nRecv >= blen)
				return -2;
			
			timeout.tv_sec = 1; 
			timeout.tv_usec = 0;
					
			FD_SET(sockfd, &mask);
			res = select(sockfd + 1, &mask, NULL, NULL, &timeout);
			//printf("%d %d\n", sockfd, res);
			if( res == 1) 
			{
				taketime = 0;
				len = recv(sockfd, pbuf + nRecv, blen - nRecv, 0);
				//printf("len: %d\n", len);
                if(len == 0)
                {
                    close(sockfd);
                    return -1;
                }
				else if(len < 0)
				{
                    if( errno == EAGAIN)
                        continue;
					close(sockfd);
					return -1;
				}
				nRecv = nRecv + len;
				p = (char*)memchr(pbuf, '\n', nRecv);
				if(p != NULL)
				{
					left = p - pbuf + 1;
					right = nRecv - left;
				
					if(right > dbufsize)
					{
						if(dbuf)
							free(dbuf);
						dbuf = (char*)malloc(right);
						dbufsize = right;
					}
					memcpy(dbuf, p + 1, right);
					dlen = right;
					nRecv = left;
					pbuf[nRecv] = '\0';
					break;
				}
			}
			else if(res == 0)
			{
				taketime = taketime + 1;
                //printf("%p: %d %d\n", this, sockfd, taketime);
				if(taketime > MAX_TRY_TIMEOUT)
				{
					close(sockfd);
					return -1;
				}
				continue;
			}
			else
			{
                //printf("%p: closed\n", this);
				return -1;
			}
			
		}
		
		return nRecv;
	}

private:
	int sockfd;
public:
	char* dbuf;
	int dlen;
	int dbufsize;
};

class bwgate_base
{
public:
	static string	m_sw_version;

	static string	m_localhostname;
	static string	m_encoding;
	static string	m_hostip;
	
	static unsigned int	m_concurrent_conn;

	static string	m_config_file;
	static string	m_permit_list_file;
	static string	m_reject_list_file;
	
    static string	m_service_list_file;
    static string	m_backend_list_file;
    
	static vector<stReject> m_reject_list;
	static vector<string> m_permit_list;
public:	
	bwgate_base();
	virtual ~bwgate_base();
	
	static void SetConfigFile(const char* config_file, const char* permit_list_file, const char* reject_list_file);

	static BOOL LoadConfig();
	static BOOL UnLoadConfig();

	static BOOL LoadAccessList();
	
	/* Pure virual function	*/
	virtual BOOL LineParse(char* text) = 0;
	virtual int ProtRecv(char* buf, int len) = 0;

private:
	static void _load_permit_();
	static void _load_reject_();
};

#endif /* _MAILSYS_H_ */

