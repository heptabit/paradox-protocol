#ifndef HASH_H
#define HASH_H

#include "Platform.h"
#include <openssl/sha.h>

#include "Errors.h"
#include "Buffer.h"

class Buffer;

class Hash
{
protected:
	Hash()
	{
		Name = NULL;
		HashLen = 0;
	}

public:
	virtual ~Hash()
	{
	}

	virtual void Update(const char* data, size_t len) = 0;
	void Update(Buffer* data)
	{
		Update(data->Ptr(), data->Len());
	}
	
	virtual const char* Final(const char* data, size_t len) = 0;
	const char* Final(void)
	{
		return Final(NULL, 0);
	}
	const char *Final(Buffer* data)
	{
		return Final(data->Ptr(), data->Len());
	}

	const char* Name;
	int HashLen;
};

class OpenSSLHash : public Hash
{
protected:
	OpenSSLHash()
	{
	}

public:
	virtual ~OpenSSLHash()
	{
	}
};

class Hash_SHA1 : public Hash
{
public:
	Hash_SHA1()
	{
		Name = "sha1";
		SHA1_Init(&context);
		md[0] = 0;
		HashLen = 20;
	}
	~Hash_SHA1()
	{
		memset(md, 0xfb, HashLen);
	}

	virtual void Update(const char* data, size_t len)
	{
		if (data && len)
			SHA1_Update(&context, (unsigned char*)data, len);
	}

	virtual const char* Final(const char* data, size_t len)
	{
		Update(data, len);

		SHA1_Final((unsigned char*)md, &context);
		return md;
	}


protected:
	SHA_CTX context;
	char md[20];
}; 

class Hash_SHA256 : public Hash
{
public:
	Hash_SHA256()
	{
		Name = "sha256";
		SHA256_Init(&context);
		md[0] = 0;
		HashLen = SHA256_DIGEST_LENGTH;
	}
	~Hash_SHA256()
	{
		memset(md, 0xfb, HashLen);
	}

	virtual void Update(const char* data, size_t len)
	{
		if (data && len)
			SHA256_Update(&context, (unsigned char*)data, len);
	}
	
	virtual const char *Final(const char* data, size_t len)
	{
		Update(data, len);

		SHA256_Final((unsigned char *)md, &context);
		return md;
	}


protected:
	SHA256_CTX context;
	char md[SHA256_DIGEST_LENGTH];
};

class Hash_SHA384 : public Hash
{
public:
	Hash_SHA384()
	{
		Name = "sha384";
		SHA384_Init(&context);
		md[0] = 0;
		HashLen = SHA384_DIGEST_LENGTH;
	}
	~Hash_SHA384()
	{
		memset(md, 0xfb, HashLen);
	}


	virtual void Update(const char* data, size_t len)
	{
		if (data && len)
			SHA384_Update(&context, (unsigned char*)data, len);
	}

	virtual const char* Final(const char* data, size_t len)
	{
		Update(data, len);

		SHA384_Final((unsigned char*)md, &context);
		return md;
	}


protected:
	SHA512_CTX context;
	char md[SHA384_DIGEST_LENGTH];
};

class Hash_SHA512 : public Hash
{
public:
	Hash_SHA512()
	{
		Name = "sha512";
		SHA512_Init(&context);
		md[0] = 0;
		HashLen = SHA512_DIGEST_LENGTH;
	}
	~Hash_SHA512()
	{
		memset(md, 0xfb, HashLen);
	}
	virtual void Update(const char* data, size_t len)
	{
		if (data && len)
			SHA512_Update(&context, (unsigned char*)data, len);
	}

	virtual const char* Final(void)
	{
		return Final(NULL, 0);
	}
	virtual const char* Final(const char* data, size_t len)
	{
		if (data && len)
			Update(data, len);

		SHA512_Final((unsigned char*)md, &context);
		return md;
	}


protected:
	SHA512_CTX context;
	char md[SHA512_DIGEST_LENGTH];
};

#endif
