/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/

#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/select.h>

#include "util/general.h"
#include "base.h"
#include "session.h"
#include <mqueue.h>
#include <semaphore.h>

#define DEFAULT_WORK_PROCESS_NUM 1

static char LOGNAME[256] = "/var/log/bwgated/service.log";
static char LCKNAME[256] = "/.bwgated_sys.lock";

static const char* SVR_NAME_TBL[] = {NULL, "bwgated", NULL};
static const char* SVR_DESP_TBL[] = {NULL, "bwgated", NULL};

#define write_lock(fd, offset, whence, len) lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)   

static int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)   
{   
	struct   flock   lock;   
	lock.l_type = type;   
	lock.l_start = offset;   
	lock.l_whence = whence;   
	lock.l_len = len;
	return (fcntl(fd,cmd, &lock));   
}   

static bool lock_pid_file(const char* pflag)   
{
	int fd, val;   
	char buf[12];   
	
    if((fd = open(pflag, O_WRONLY|O_CREAT, 0644)) < 0)
	{
		return false;  
	}
	/* try and set a write lock on the entire file   */   
	if(write_lock(fd, 0, SEEK_SET, 0) < 0)
	{   
		if((errno == EACCES) || (errno == EAGAIN))
		{   
		    return false;   
		}
		else
		{   
		    close(fd);   
			return false;
		}   
	}   
	
	/* truncate to zero length, now that we have the lock   */   
	if(ftruncate(fd, 0) < 0)
	{   
	    close(fd);               
		return false;
	}   
	
	/*   write   our   process   id   */   
	sprintf(buf, "%d\n", ::getpid());   
	if(write(fd, buf, strlen(buf)) != strlen(buf))
	{   
	    close(fd);               
		return false;
	}   
	
	/*   set close-on-exec flag for descriptor   */   
	if((val = fcntl(fd, F_GETFD, 0) < 0 ))
	{   
	    close(fd);   
		return false;
	}   
	val |= FD_CLOEXEC;   
	if(fcntl(fd, F_SETFD, val) <0 )
	{   
	    close(fd);   
		return false;
	}
	/* leave file open until we terminate: lock will be held   */  
	return true;   
} 

static bool check_pid_file(const char* pflag)   
{
	int fd, val;   
	char buf[12];   
	
    if((fd = open(pflag, O_WRONLY|O_CREAT, 0644)) < 0)
	{
	    return false;  
	}
	/* try and set a write lock on the entire file   */   
	if(write_lock(fd, 0, SEEK_SET, 0) < 0)
	{   
		if((errno == EACCES) || (errno == EAGAIN))
		{   
		    return false;   
		}
		else
		{   
		    close(fd);   
			return false;
		}   
	}   
	
	/* truncate to zero length, now that we have the lock   */   
	if(ftruncate(fd, 0) < 0)
	{   
	    close(fd);               
		return false;
	}   
	
	/*   write   our   process   id   */   
	sprintf(buf, "%d\n", ::getpid());   
	if(write(fd, buf, strlen(buf)) != strlen(buf))
	{   
	    close(fd);               
		return false;
	}   
	
	/*   set close-on-exec flag for descriptor   */   
	if((val = fcntl(fd, F_GETFD, 0) < 0 ))
	{   
	    close(fd);   
		return false;
	}   
	val |= FD_CLOEXEC;   
	if(fcntl(fd, F_SETFD, val) <0 )
	{   
	    close(fd);   
		return false;
	}
	
	close(fd);
	return true;   
} 

typedef std::pair<std::string, unsigned short> service_key_t;

typedef struct{
    //from xml configuration
    string ip;
    unsigned short port;
    BOOL is_ssl;
    string protocol;
    
    int sockfd;
} service_content_t;

typedef struct{
    string ip;
    BOOL is_ssl;    
    int sockfd;
} session_content_t;

typedef struct
{
	string ip;
	unsigned short port;
    BOOL is_ssl;
    string protocol;
    string gate;
}backend_host_t;

typedef struct {
	int pid;
	int sockfds[2];
} WORK_PROCESS_INFO;

class Worker
{
public:
	Worker(const char* service_name, int process_seq, int sockfd);
	virtual ~Worker();

	void Working();
private:	
	int m_sockfd;
	int m_thread_num;
	int m_process_seq;
	string m_service_name;
    
    Session** m_client_list;
    Session** m_backend_list;
    
};

class Service
{
public:
	Service(Service_Type st);
	virtual ~Service();
	int Run(int fd);
	void Stop();
	void ReloadConfig();
	void ReloadAccess();
	void ReloadExtension();
	void AppendReject(const char* data);
    void ReloadBackend(CUplusTrace& uTrace);

protected:
    int create_client_socket(const char* gate, int& clt_sockfd, BOOL https, struct sockaddr_storage& clt_addr, socklen_t clt_size,
        string& client_ip, string& backhost_ip, unsigned short& backhost_port);

    int create_server_socket(int& sockfd, const char* hostip, unsigned short port);
    
	mqd_t m_service_qid;
	sem_t* m_service_sid;
	string m_service_name;

	Service_Type m_st;
	
    list<pid_t> m_child_list;
	vector<WORK_PROCESS_INFO> m_work_processes;
    
    service_content_t** m_service_list;
   
    
    map<string, vector<backend_host_t> > m_backend_host_list;
    
    unsigned int m_ip;
};

#endif /* _SERVICE_H_ */

