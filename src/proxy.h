/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/
#ifndef _NET_PROXY_H_
#define _NET_PROXY_H_

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "util/general.h"

using namespace std;

class net_proxy
{
public:
    net_proxy() {};
    
    virtual ~net_proxy() {};
    
    virtual BOOL parse(const char* text) = 0 ;
};

#endif /* _NET_PROXY_H_ */