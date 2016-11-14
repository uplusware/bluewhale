/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <mqueue.h>
#include <time.h>
#include <string>
#include <iostream>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/param.h> 
#include <sys/stat.h> 
#include <iostream>
#include <fstream>
#include <sstream>
#include <iterator>
#include <streambuf>
#include <semaphore.h>
#include "service.h"
#include "base.h"

using namespace std;

static void usage()
{
	printf("Usage:bwgated start | stop | status | reload | access | reject [ip] | extension | version\n");
}

//set to daemon mode
static void daemon_init()
{
	setsid();
	chdir("/");
	umask(0);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

char PIDFILE[256] = "/tmp/bwgated/bwgated.pid";

static int Run()
{
	int retVal = 0;
	int http_pid = -1;

	do
	{
		int pfd[2];
		pipe(pfd);
		
		pipe(pfd);
        http_pid = fork();
        if(http_pid == 0)
        {
            char szFlag[128];
            sprintf(szFlag, "/tmp/bwgated/%s.pid", SVR_NAME_TBL[stGATE]);
            if(lock_pid_file(szFlag) == false)  
            {   
                printf("%s is aready runing.\n", SVR_DESP_TBL[stGATE]);   
                exit(-1);  
            }
            
            close(pfd[0]);
            daemon_init();
            Service gate_srv(stGATE);
            gate_srv.Run(pfd[1]);
            exit(0);
        }
        else if(http_pid > 0)
        {
            unsigned int result;
            close(pfd[1]);
            read(pfd[0], &result, sizeof(unsigned int));
            if(result == 0)
                printf("Start bwgated service OK \t\t\t[%u]\n", http_pid);
            else
            {
                printf("Start bwgated service error. \t\t\t[Error]\n");
            }
            close(pfd[0]);
        }
        else
        {
            close(pfd[0]);
            close(pfd[1]);
            retVal = -1;
            break;
        }
		
	}while(0);
	
	bwgate_base::UnLoadConfig();
	
	return retVal;
}

static int Stop()
{
	printf("Stop bwgated service ...\n");
	
	Service gate_srv(stGATE);
	gate_srv.Stop();	
}

static void Version()
{
	printf("v%s\n", bwgate_base::m_sw_version.c_str());
}

static int Reload()
{
	printf("Reload bwgated configuration ...\n");

	Service gate_srv(stGATE);
	gate_srv.ReloadConfig();
}

static int ReloadAccess()
{
	printf("Reload bwgated access list ...\n");

	Service gate_srv(stGATE);
	gate_srv.ReloadAccess();
}

static int AppendReject(const char* data)
{
	printf("Append bwgated reject list ...\n");

	Service gate_srv(stGATE);
	gate_srv.AppendReject(data);
}

static int processcmd(const char* cmd, const char* conf, const char* permit, const char* reject, const char* data)
{
	bwgate_base::SetConfigFile(conf, permit, reject);
	if(!bwgate_base::LoadConfig())
	{
		printf("Load Configure File Failed.\n");
		return -1;
	}
	
	if(strcasecmp(cmd, "stop") == 0)
	{
		Stop();
	}
	else if(strcasecmp(cmd, "start") == 0)
	{
		Run();
	}
	else if(strcasecmp(cmd, "reload") == 0)
	{
		Reload();
	}
	else if(strcasecmp(cmd, "access") == 0)
	{
		ReloadAccess();
	}
	else if(strcasecmp(cmd, "reject") == 0 && data != NULL)
	{
		AppendReject(data);
	}
	else if(strcasecmp(cmd, "status") == 0)
	{
		char szFlag[128];
		sprintf(szFlag, "/tmp/bwgated/%s.pid", SVR_NAME_TBL[stGATE]);
		if(check_pid_file(szFlag) == false)    
		{   
			printf("%s is runing.\n", SVR_DESP_TBL[stGATE]);   
		}
		else
		{
			printf("%s stopped.\n", SVR_DESP_TBL[stGATE]);   
		}
		
	}
	else if(strcasecmp(cmd, "version") == 0)
	{
		Version();
	}
	else
	{
		usage();
	}
	bwgate_base::UnLoadConfig();
	return 0;	

}

static void handle_signal(int sid) 
{ 
	signal(SIGPIPE, handle_signal);
}

int main(int argc, char* argv[])
{
    mkdir("/tmp/bwgated", 0777);
    chmod("/tmp/bwgated", 0777);

    mkdir("/var/log/bwgated/", 0744);
    
    // Set up the signal handler
    signal(SIGPIPE, SIG_IGN);
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGPIPE);
    sigprocmask(SIG_BLOCK, &signals, NULL);
    
    if(argc == 2)
    {
        processcmd(argv[1], CONFIG_FILE_PATH, PERMIT_FILE_PATH, REJECT_FILE_PATH, NULL);
    }
    else if(argc == 3)
    {
        processcmd(argv[1], CONFIG_FILE_PATH, PERMIT_FILE_PATH, REJECT_FILE_PATH, argv[2]);
    }
    else
    {
        usage();
        return -1;
    }
    return 0;
}

