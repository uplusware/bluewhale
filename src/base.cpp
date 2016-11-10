/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/
#include <dlfcn.h>
#include "base.h"
#include "util/security.h"

//////////////////////////////////////////////////////////////////////////
//bwgate_base
//
//Software Version
string bwgate_base::m_sw_version = "0.1";

//Global
string bwgate_base::m_encoding = "UTF-8";

string bwgate_base::m_localhostname = "localhost";
string bwgate_base::m_hostip = "";

unsigned int bwgate_base::m_concurrent_conn = 20480;
string	bwgate_base::m_config_file = CONFIG_FILE_PATH;
string	bwgate_base::m_permit_list_file = PERMIT_FILE_PATH;
string	bwgate_base::m_reject_list_file = REJECT_FILE_PATH;

string	bwgate_base::m_service_list_file = SERVICE_LIST_FILE_PATH;
string	bwgate_base::m_backend_list_file = BACKEND_LIST_FILE_PATH;

vector<stReject> bwgate_base::m_reject_list;
vector<string> bwgate_base::m_permit_list;

bwgate_base::bwgate_base()
{

}

bwgate_base::~bwgate_base()
{
	UnLoadConfig();
}

void bwgate_base::SetConfigFile(const char* config_file, const char* permit_list_file, const char* reject_list_file)
{
	m_config_file = config_file;
	m_permit_list_file = permit_list_file;
	m_reject_list_file = reject_list_file;
}

BOOL bwgate_base::LoadConfig()
{	

	m_permit_list.clear();
	m_reject_list.clear();
	
	ifstream configfilein(m_config_file.c_str(), ios_base::binary);
	string strline = "";
	if(!configfilein.is_open())
	{
		printf("%s is not exist.", m_config_file.c_str());
		return FALSE;
	}
	while(getline(configfilein, strline))
	{
		strtrim(strline);
		
		if(strline == "")
			continue;
			
		if(strncasecmp(strline.c_str(), "#", strlen("#")) != 0)
		{	
			if(strncasecmp(strline.c_str(), "LocalHostName", strlen("LocalHostName")) == 0)
			{
				strcut(strline.c_str(), "=", NULL, m_localhostname );
				strtrim(m_localhostname);
			}
			else if(strncasecmp(strline.c_str(), "HostIP", strlen("HostIP")) == 0)
			{
				strcut(strline.c_str(), "=", NULL, m_hostip );
				strtrim(m_hostip);
			}
            else if(strncasecmp(strline.c_str(), "CocurrentConnect", strlen("CocurrentConnect")) == 0)
			{
                string concurrent_conn;
				strcut(strline.c_str(), "=", NULL, concurrent_conn );
				strtrim(concurrent_conn);
                m_concurrent_conn = atoi(concurrent_conn.c_str());
			}
			strline = "";
		}
		
	}
	configfilein.close();

	_load_permit_();
	_load_reject_();
    
	return TRUE;
}

BOOL bwgate_base::LoadAccessList()
{
	string strline;
	sem_t* plock = NULL;
	///////////////////////////////////////////////////////////////////////////////
	// GLOBAL_REJECT_LIST
	plock = sem_open("/.BWGATED_GLOBAL_REJECT_LIST.sem", O_CREAT | O_RDWR, 0644, 1);
	if(plock != SEM_FAILED)
	{
		sem_wait(plock);

		_load_permit_();

		sem_post(plock);
		sem_close(plock);
	}
	/////////////////////////////////////////////////////////////////////////////////
	// GLOBAL_PERMIT_LIST
	plock = sem_open("/.BWGATED_GLOBAL_PERMIT_LIST.sem", O_CREAT | O_RDWR, 0644, 1);
	if(plock != SEM_FAILED)
	{
		sem_wait(plock);

		_load_reject_();

		sem_post(plock);
		sem_close(plock);
	}
}

void bwgate_base::_load_permit_()
{
	string strline;
	m_permit_list.clear();
	ifstream permitfilein(m_permit_list_file.c_str(), ios_base::binary);
	if(!permitfilein.is_open())
	{
		printf("%s is not exist. please creat it", m_permit_list_file.c_str());
		return;
	}
	while(getline(permitfilein, strline))
	{
		strtrim(strline);
		if((strline != "")&&(strncmp(strline.c_str(), "#", 1) != 0))
			m_permit_list.push_back(strline);
	}
	permitfilein.close();
}

void bwgate_base::_load_reject_()
{
	string strline;
	m_reject_list.clear();
	ifstream rejectfilein(m_reject_list_file.c_str(), ios_base::binary);
	if(!rejectfilein.is_open())
	{
		printf("%s is not exist. please creat it", m_reject_list_file.c_str());
		return;
	}
	while(getline(rejectfilein, strline))
	{
		strtrim(strline);
		if((strline != "")&&(strncmp(strline.c_str(), "#", 1) != 0))
		{
			stReject sr;
			sr.ip = strline;
			sr.expire = 0xFFFFFFFFU;
			m_reject_list.push_back(sr);
		}
	}
	rejectfilein.close();
}

BOOL bwgate_base::UnLoadConfig()
{
	return TRUE;
}