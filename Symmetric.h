#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "Platform.h"
#include <openssl/evp.h>

#include "Errors.h"
#include "Buffer.h"

class Buffer;
#define MAX_BLOCK_SIZE	128
#define MAX_KEY_SIZE	128

class Symmetric
{
protected:
	Symmetric()
	{
		Name = NULL;
	}
public:

	virtual ~Symmetric()
	{
	}

	virtual int Init(const char* key, const char* iv) = 0;
	virtual int KeySize(void)
	{
		return 0;
	}
	virtual int IVSize(void)
	{
		return 0;
	}
	virtual int BlockSize(void)
	{
		return 0;
	}


	const char* Name;
};

class SymmetricEncrypt : public Symmetric
{
protected:
	SymmetricEncrypt()
	{
	}
public:

	virtual ~SymmetricEncrypt()
	{
	}

	virtual int Encrypt(const char* indata, int inlen, char* outdata, int outlen) = 0;
};

class SymmetricDecrypt : public Symmetric
{
protected:
	SymmetricDecrypt()
	{
	}
public:

	virtual ~SymmetricDecrypt()
	{
	}

	virtual int Decrypt(const char* indata, int inlen, char* outdata, int outlen) = 0;
};

class OpenSSL_SymmetricEncrypt : public SymmetricEncrypt
{
protected:
	OpenSSL_SymmetricEncrypt(const EVP_CIPHER* cipher)
	{
		this->cipher = cipher;
		ctx = EVP_CIPHER_CTX_new();

		KeySize = EVP_CIPHER_key_length(cipher);
		IVSize = EVP_CIPHER_iv_length(cipher);
		BlockSize = EVP_CIPHER_block_size(cipher);
	}
	OpenSSL_SymmetricEncrypt(const EVP_CIPHER* cipher, const char* key, const char* iv) : OpenSSL_SymmetricEncrypt(cipher)
	{
		Init(key, iv);
	}

	virtual ~OpenSSL_SymmetricEncrypt()
	{
		if (ctx)
			EVP_CIPHER_CTX_free(ctx);
	}
public:

	virtual int Init(const char* key, const char* iv)
	{
		if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key, (const unsigned char*)iv) == 1)
			if (EVP_CIPHER_CTX_set_padding(ctx, 0))
			return ERROR_NONE;

		return CIPHER_FAILED_TO_INITIALIZE;
	}

	virtual int Encrypt(const char* indata, int inlen, char* outdata, int outlen)
	{
		//int ciphertext_len = outlen;
		if (EVP_EncryptUpdate(ctx, (unsigned char*)outdata, &outlen, (const unsigned char*)indata, inlen) == 1)
		{
/*
			ciphertext_len = outlen;
			int len = 0;
			if (EVP_EncryptFinal_ex(ctx, (unsigned char *)outdata + ciphertext_len, &len) == 1)
			{
				ciphertext_len += len;
				return ciphertext_len;
			}
*/
			return outlen;
		}

		return CIPHER_FAILED_TO_CRYPT;
	}

	int KeySize, IVSize, BlockSize;

protected:
	const EVP_CIPHER* cipher;
	EVP_CIPHER_CTX* ctx;
};
class OpenSSL_SymmetricDecrypt : public SymmetricDecrypt
{
protected:
	OpenSSL_SymmetricDecrypt(const EVP_CIPHER* cipher)
	{
		this->cipher = cipher;
		ctx = EVP_CIPHER_CTX_new();

		KeySize = EVP_CIPHER_key_length(cipher);
		IVSize = EVP_CIPHER_iv_length(cipher);
		BlockSize = EVP_CIPHER_block_size(cipher);

	}
	OpenSSL_SymmetricDecrypt(const EVP_CIPHER* cipher, const char* key, const char* iv) : OpenSSL_SymmetricDecrypt(cipher)
	{
		Init(key, iv);
	}

	virtual ~OpenSSL_SymmetricDecrypt()
	{
		if (ctx)
			EVP_CIPHER_CTX_free(ctx);
	}
public:

	virtual int Init(const char* key, const char* iv)
	{
		if (EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)key, (const unsigned char*)iv) == 1)
			if (EVP_CIPHER_CTX_set_padding(ctx, 0))
				return ERROR_NONE;

		return CIPHER_FAILED_TO_INITIALIZE;
	}

	virtual int Decrypt(const char* indata, int inlen, char* outdata, int outlen)
	{
		//int ciphertext_len = outlen;
		if (EVP_DecryptUpdate(ctx, (unsigned char*)outdata, &outlen, (const unsigned char*)indata, inlen) == 1)
		{
			/*
						ciphertext_len = outlen;
						int len = 0;
						if (EVP_DecryptFinal_ex(ctx, (unsigned char *)outdata + ciphertext_len, &len) == 1)
						{
							ciphertext_len += len;
							return ciphertext_len;
						}
			*/
			return outlen;
		}

		return CIPHER_FAILED_TO_CRYPT;
	}

	int KeySize, IVSize, BlockSize;

protected:
	const EVP_CIPHER* cipher;
	EVP_CIPHER_CTX* ctx;
};

#define SYMMETRICALG(x, y) \
	class x##Enc : public OpenSSL_SymmetricEncrypt { public: x##Enc() : OpenSSL_SymmetricEncrypt(y()) {} x##Enc(const char* key, const char* iv) : OpenSSL_SymmetricEncrypt(y(), key, iv) {}}; \
	class x##Dec : public OpenSSL_SymmetricDecrypt { public: x##Dec() : OpenSSL_SymmetricDecrypt(y()) {} x##Dec(const char* key, const char* iv) : OpenSSL_SymmetricDecrypt(y(), key, iv) {}}; 

SYMMETRICALG(Aes128Ecb, EVP_aes_128_ecb)
SYMMETRICALG(Aes128Cbc, EVP_aes_128_cbc)
SYMMETRICALG(Aes128Ctr, EVP_aes_128_ctr)
SYMMETRICALG(Aes128Gcm, EVP_aes_128_gcm)

SYMMETRICALG(Aes192Ecb, EVP_aes_192_ecb)
SYMMETRICALG(Aes192Cbc, EVP_aes_192_cbc)
SYMMETRICALG(Aes192Ctr, EVP_aes_192_ctr)
SYMMETRICALG(Aes192Gcm, EVP_aes_192_gcm)

SYMMETRICALG(Aes256Ecb, EVP_aes_256_ecb)
SYMMETRICALG(Aes256Cbc, EVP_aes_256_cbc)
SYMMETRICALG(Aes256Ctr, EVP_aes_256_ctr)
SYMMETRICALG(Aes256Gcm, EVP_aes_256_gcm)

#endif
