#include "Platform.h" 
#include "Errors.h"

typedef struct ErrTable
{
	int code;
	const char* msg;
} ErrTable;

ErrTable ErrLookupTable[] =
{
	{ SOCKERR_SOCKET_FAILED, "Socket failed" },
	{ SOCKERR_WSASTARTUP_FAILED, "WSAStartup failed" },
	{ SOCKERR_UNABLE_TO_RESOLVE_HOSTNAME, "Unable to resolve hostname" },
	{ SOCKERR_UNABLE_TO_USE_HOSTNAME, "Unable to use hostname" },
	{ SOCKERR_CONNECT_FAILED, "Connect failed" },
	{ SOCKERR_UNABLE_TO_INITIALIZE_SSL, "Unable to initialize SSL" },
	{ SOCKERR_SSL_ERROR, "SSL error" },
	{ SOCKERR_SSL_CERTIFICATE_EXPIRED, "SSL Certificate expired" },
	{ SOCKERR_SSL_CERTIFICATE_VERIFICATION, "SSL Certificate verification" },
	{ SOCKERR_SSL_SEND_ERROR, "SSL send error" },
	{ SOCKERR_SSL_RECEIVE_ERROR, "SSL receive error" },

	{ KEYERR_NAME_NOT_SET, "Key name not specified" },
	{ KEYERR_FAILED_TO_LOAD_KEY , "Failed to load key" },

	{ HTTP_ALREADY_EXECUTED, "HTTP already executed"},
	{ HTTP_INVALID_URL, "HTTP invalid URL" },

	{ MEMERR_OUT_OF_MEMORY, "Out of memory" },

	{ 0, "No Error"}
};

const char *GetErrorString(int err)
{
	ErrTable* p = ErrLookupTable;

	while (p->code)
	{
		if (p->code == err)
			return p->msg;
		p++;
	}
	return NULL;
}
