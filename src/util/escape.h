/*
	Copyright (c) openheap, uplusware
	uplusware@gmail.com
*/

#ifndef _ESCAPE_H_
#define _ESCAPE_H_

#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

using namespace std;

void escape(const unsigned char* src, string & dst);
void unescape(const unsigned char* src, string & dst);

void encodeURI(const unsigned char* src, string & dst);
void decodeURI(const unsigned char* src, string & dst);
	
#endif /* _ESCAPE_H_ */

