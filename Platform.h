#ifndef PLATFORM_H
#define PLATFORM_H
#include <stdio.h>

#define _CRT_SECURE_NO_WARNINGS

#ifdef ANDROID_NDK
#ifdef FD_SETSIZE
#undef FD_SETSIZE
#endif
#endif

#ifdef _WIN32
#ifdef VERSIONOS
	#undef VERSIONOS
#endif
#define VERSIONOS "Windows"
#include <winsock.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <Iphlpapi.h>

void StartThread(LPTHREAD_START_ROUTINE proc, void *param);

#define socklen_t int
#define int64 __int64
#define uint64 unsigned __int64
#define in_addr_t unsigned long
#pragma warning(disable: 4996)
#define THREADRETVAL DWORD
#define ThisThread GetCurrentThreadId()
#else // unix

void StartThread( void *(*proc) (void *), void *param);

#define THREADRETVAL void *
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <fcntl.h>

#if defined (__FreeBSD__)
#include <pthread_np.h>
#endif 

#ifdef __linux__
#ifdef VERSIONOS
	#undef VERSIONOS
#endif
#define VERSIONOS "Linux"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/syscall.h>
#endif

#ifdef ANDROID_NDK
#ifdef VERSIONOS
	#undef VERSIONOS
#endif
#define VERSIONOS "Android"
#include "../jni/ifaddrs.h"
#ifndef S_IREAD
#define S_IREAD S_IRUSR
#endif
#ifndef S_IWRITE
#define S_IWRITE S_IWUSR
#endif
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(TARGET_OS_IPHONE)
#ifdef VERSIONOS
	#undef VERSIONOS
#endif
#define VERSIONOS "Mac OSX"
#include <net/if.h>
#include <net/if_dl.h>
#endif

#include <ctype.h>
#define _strlwr strlwr
#define _stricmp strcasecmp
char* strupr(char* s);
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define int64 int64_t
#define uint64 uint64_t
#define _open open
#define _close close
#define _read read
#define _write write
#if defined(__APPLE__) || defined(__CYGWIN__) || defined(__FreeBSD__)
#define _lseeki64 lseek
#else
#define _lseeki64 lseek64
#endif

#if defined(__CYGWIN__)
	#ifdef VERSIONOS
		#undef VERSIONOS
	#endif
	#define VERSIONOS "Cygwin" 
#endif

#if defined(__FreeBSD__)
	#ifdef VERSIONOS
		#undef VERSIONOS
	#endif
	#define VERSIONOS "FreeBSD"
#endif

#define SOCKET int
#define closesocket close
time_t timeGetTime(void);
int Sleep(unsigned long milisec);
#ifndef __CYGWIN__
char* strlwr( char* s );
#endif
typedef void *(*PTHREAD_START_ROUTINE)(void *lpThreadParameter);
typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;
#define INVALID_SOCKET -1
#if defined(__FreeBSD__)
		#define ThisThread (unsigned long)pthread_getthreadid_np()
	#else
		#if defined(__APPLE__)
			#define ThisThread (unsigned long)pthread_self()
		#else
			#define ThisThread (unsigned long)syscall(__NR_gettid)
		#endif
	#endif
#endif

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#define ADD_SET(sock, set) {FD_SET(sock, set); if (fd_max < sock) fd_max = sock;}

#ifndef VERSIONOS
#define VERSIONOS "OS unknown"
#endif

#if defined (__i386__) || defined(_M_X86) || defined(_M_IX86)
	#define VERSIONARCH "x86"
#else
	#define VERSIONARCH "x64"
#endif


class Buffer;
void ToHex(Buffer* data);
void FromHex(Buffer* data);

void* CreateCS(void);
void DeleteCS(void* cs);
void LockCS(void* cs);
void UnlockCS(void* cs);

#endif // PLATFORM_H
