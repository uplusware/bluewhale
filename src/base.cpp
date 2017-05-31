/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/
#include <dlfcn.h>
#include "base.h"
#include "util/security.h"
#include "posixname.h"

//////////////////////////////////////////////////////////////////////////
//bwgate_base
//
//Software Version
string bwgate_base::m_sw_version = "0.1";

//Global
BOOL bwgate_base::m_close_stderr = TRUE;
string bwgate_base::m_encoding = "UTF-8";

string bwgate_base::m_localhostname = "localhost";
string bwgate_base::m_hostip = "";

unsigned int bwgate_base::m_instance_max_concurrent_conn = 4096;
unsigned int bwgate_base::m_max_instance_num = 8;
BOOL bwgate_base::m_instance_prestart = FALSE;
string bwgate_base::m_instance_balance_scheme = "R";

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
			
		if(strncasecmp(strline.c_str(), "#", sizeof("#") - 1) != 0)
		{	
			if(strncasecmp(strline.c_str(), "CloseStderr", sizeof("CloseStderr") - 1) == 0)
			{
				string close_stderr;
				strcut(strline.c_str(), "=", NULL, close_stderr );
				strtrim(close_stderr);
				m_close_stderr = (strcasecmp(close_stderr.c_str(), "yes")) == 0 ? TRUE : FALSE;
			}
            else if(strncasecmp(strline.c_str(), "LocalHostName", sizeof("LocalHostName") - 1) == 0)
			{
				strcut(strline.c_str(), "=", NULL, m_localhostname );
				strtrim(m_localhostname);
			}
			else if(strncasecmp(strline.c_str(), "HostIP", sizeof("HostIP") - 1) == 0)
			{
				strcut(strline.c_str(), "=", NULL, m_hostip );
				strtrim(m_hostip);
			}
            else if(strncasecmp(strline.c_str(), "InstanceMaxCocurrentConNum", sizeof("InstanceMaxCocurrentConNum") - 1) == 0)
			{
                string concurrent_conn;
				strcut(strline.c_str(), "=", NULL, concurrent_conn );
				strtrim(concurrent_conn);
                m_instance_max_concurrent_conn = atoi(concurrent_conn.c_str());
			}
            else if(strncasecmp(strline.c_str(), "MaxInstanceNum", sizeof("MaxInstanceNum") - 1) == 0)
			{
                string max_instance_num;
				strcut(strline.c_str(), "=", NULL, max_instance_num );
				strtrim(max_instance_num);
                m_max_instance_num = atoi(max_instance_num.c_str());
			}
            else if(strncasecmp(strline.c_str(), "InstancePrestart", sizeof("InstancePrestart") - 1) == 0)
			{
				string instance_prestart;
				strcut(strline.c_str(), "=", NULL, instance_prestart );
				strtrim(instance_prestart);
				m_instance_prestart = (strcasecmp(instance_prestart.c_str(), "yes")) == 0 ? TRUE : FALSE;
			}
            else if(strncasecmp(strline.c_str(), "InstanceBalanceScheme", sizeof("InstanceBalanceScheme") - 1) == 0)
			{
				strcut(strline.c_str(), "=", NULL, m_instance_balance_scheme );
				strtrim(m_instance_balance_scheme);
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
	plock = sem_open(BWGATED_GLOBAL_REJECT_LIST, O_CREAT | O_RDWR, 0644, 1);
	if(plock != SEM_FAILED)
	{
		sem_wait(plock);

		_load_permit_();

		sem_post(plock);
		sem_close(plock);
	}
	/////////////////////////////////////////////////////////////////////////////////
	// GLOBAL_PERMIT_LIST
	plock = sem_open(BWGATED_GLOBAL_PERMIT_LIST, O_CREAT | O_RDWR, 0644, 1);
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
		fprintf(stderr, "%s is not exist. please creat it", m_permit_list_file.c_str());
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
		fprintf(stderr, "%s is not exist. please creat it", m_reject_list_file.c_str());
		return;
	}
	while(getline(rejectfilein, strline))
	{
		strtrim(strline);
		if((strline != "") && (strncmp(strline.c_str(), "#", 1) != 0))
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