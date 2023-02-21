#include <string.h>
#include <vector>
#include <stdlib.h>
#include "Platform.h"
#include "Buffer.h"

const char *hex="0123456789abcdef";
void ToHex(Buffer *data)
{
	Buffer bf(data->Len() * 2+128);

	while (data->Len())
	{
		char *a = data->Ptr();
		unsigned char b = (unsigned char)*a;
		bf.Append(&hex[b/16],1);
		bf.Append(&hex[b%16],1);
		data->Consume(1);
	}
	data->Clear();
	data->Append(bf.Ptr(), bf.Len());
}
void FromHex(Buffer *data)
{
	char buff[3];
	buff[2] = 0;
	Buffer out(data->Len());

	while (data->Len())
	{
		if (data->Len()<2)
			break;

		memcpy(buff, data->Ptr(), 2);
		_strlwr(buff);

		char *s1, *s2;
		s1 = (char *)strchr(hex, buff[0]);
		s2 = (char *)strchr(hex, buff[1]);

		if (!s1 || !s2)
			break;

		buff[0] = (char)((s1 - hex)*16 + (s2-hex));
		out.Append(buff,1);
		data->Consume(2);
	}
	data->Clear();
	data->Append(out.Ptr(), out.Len());
}

void *CreateCS(void)
{
#ifdef _WIN32
	CRITICAL_SECTION *c = new CRITICAL_SECTION;
	InitializeCriticalSection(c);
#else
	pthread_mutex_t t = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t *c = new pthread_mutex_t;
	memcpy(c, &t, sizeof(pthread_mutex_t));
#endif

	return c;
}

void DeleteCS(void *cs)
{
#ifdef _WIN32
	CRITICAL_SECTION *c = (CRITICAL_SECTION *)cs;
	DeleteCriticalSection(c);
	delete c;
#else
	pthread_mutex_t *c = (pthread_mutex_t *)cs;
	pthread_mutex_destroy(c);
#endif
}

void LockCS(void *cs)
{
#ifdef _WIN32
	CRITICAL_SECTION *c = (CRITICAL_SECTION *)cs;
	EnterCriticalSection(c);
#else
	pthread_mutex_t *c = (pthread_mutex_t *)cs;
	pthread_mutex_lock(c);
#endif
}

void UnlockCS(void *cs)
{
#ifdef _WIN32
	CRITICAL_SECTION *c = (CRITICAL_SECTION *)cs;
	LeaveCriticalSection(c);
#else
	pthread_mutex_t *c = (pthread_mutex_t *)cs;
	pthread_mutex_unlock(c);
#endif
}

#ifndef _WIN32
#include <ctype.h>
char* strlwr( char* s )
{
	while (*s) 
	{ 
		*s = tolower((unsigned char) *s); 
		s++; 
	} 
	return s;
}
int Sleep(unsigned long milliseconds)
{
	usleep((useconds_t)(milliseconds * 1000));
	return 0;
}
time_t timeGetTime(void)
{
	struct timeval start;
	gettimeofday(&start, NULL);

	time_t d = start.tv_sec * 1000 + start.tv_usec/1000;
	if (d<0)
		d +=  0x7FFFFFFF;
	return d;
}
#endif

#ifdef _WIN32
void StartThread(LPTHREAD_START_ROUTINE proc, void *param)
#else
void StartThread( void *(*proc) (void *), void *param)
#endif
{
#ifdef _WIN32
	DWORD did;
	CloseHandle(CreateThread(NULL, 0, proc, param, 0, &did));
#else
	pthread_attr_t threadAttr;
	pthread_attr_init(&threadAttr);
	pthread_attr_setstacksize(&threadAttr, 1024*1024);
	pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
	pthread_t did;
	pthread_create(&did, &threadAttr, proc, (void *)param);
	pthread_detach(did);
	pthread_attr_destroy(&threadAttr);
#endif
}


#ifndef _WIN32
char* strupr(char* s)
{
	char* tmp = s;

	for (; *tmp; ++tmp) {
		*tmp = toupper((unsigned char)*tmp);
	}

	return s;
}
#endif