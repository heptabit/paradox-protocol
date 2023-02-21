#ifndef KEY_H
#define KEY_H

#include "Platform.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include "Errors.h"
#include "Buffer.h"
#include "Base64.h"
#include "Rand.h"

extern "C"
{
	#include "dep/c25519/sha512.h"
	#include "dep/c25519/edsign.h"
	#include "dep/c25519/morph25519.h"
}

#define AUTH_PUBLIC_MAGIC "paradox-pubkey-v1"
#define AUTH_PRIVATE_MAGIC "paradox-privkey-v1"
#define AUTH_BEGIN "BEGIN"
#define AUTH_END "END"
#define AUTH_PRIVATE "PRIVATE"
#define AUTH_PUBLIC "PUBLIC"
#define AUTH_KEY_STR "-----%s %s %s KEY-----"

class Buffer;
class Hash;
#define BUFFER_MAX_ECPOINT_LEN ((528*2 / 8) + 1)

class PublicKey
{
protected:
	PublicKey()
	{
		Name = NULL;
		PublicExportBuffer = NULL;
		PublicHashBuffer = NULL;
		PublicHashBase64Buffer = NULL;
	}

public:
	virtual ~PublicKey()
	{
		if (PublicExportBuffer)
			delete PublicExportBuffer;
		if (PublicHashBuffer)
			delete PublicHashBuffer;
		if (PublicHashBase64Buffer)
			delete PublicHashBase64Buffer;
	}

	static const char* Detect(const char* data)
	{
		static Buffer b;
		b.Clear();
		if (data)
			b.Append(data);
		char* line = b.GetNextLine();
		if (line)
		{
			if (!strncmp(line, "-----BEGIN ", 11))
			{
				line += 11;
				const char* start = line;
				while (*line && *line != ' ')
					line++;
				if (*line == ' ')
				{
					*line = 0;
					return start;
				}
			}
		}
		return NULL;
	}

	int PublicLoad(const char* filename)
	{
		Buffer b;
		if (b.Load(filename))
			if (b.Len())
				return PublicImport(&b);

		return KEYERR_FAILED_TO_LOAD_KEY;
	}

	virtual int PublicSave(const char* filename)
	{
		int ret = KEYERR_FAILED_TO_SAVE_KEY;
		Buffer* b = PublicExport();
		if (b && b->Len())
		{
			if (b->Save(filename))
				ret = ERROR_NONE;
			//delete b;
		}

		return ret;
	}
	
	virtual Buffer* PublicExport()
	{
		return NULL;
	}
	
	virtual int PublicImport(Buffer* data)
	{
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}

	static int PublicMagicImport(Buffer* data, const char* name, Buffer* publicData)
	{
		char MARK_BEGIN[1024], MARK_END[1024];
		if (strlen(name) > 128)
			return KEYERR_FAILED_TO_IMPORT_KEY;
		sprintf(MARK_BEGIN, AUTH_KEY_STR, AUTH_BEGIN, name, AUTH_PUBLIC);strupr(MARK_BEGIN);
		sprintf(MARK_END, AUTH_KEY_STR, AUTH_END, name, AUTH_PUBLIC);strupr(MARK_END);
		size_t MARK_BEGIN_LEN = strlen(MARK_BEGIN);
		size_t MARK_END_LEN = strlen(MARK_END);


		int ret = KEYERR_FAILED_TO_IMPORT_KEY;
		char* line;
		do
		{
			line = data->GetNextLine();
			if (line)
			{
				if (!strcmp(line, MARK_BEGIN))
					break;
			}
			else
				if (!strcmp(data->Ptr(), MARK_BEGIN))
					break;

		} while (line);

		Buffer data1;
		if (line)
		{
			do
			{
				line = data->GetNextLine();
				if (line)
				{
					if (!strcmp(line, MARK_END))
						break;

					data1.Append(line);
				}
				else
				{
					if (!strcmp(data->Ptr(), MARK_END))
						break;

					data1.Append(data->Ptr());
				}
			} while (line);
		}
		if (line && data1.Len())
		{
			Buffer data2;
			Base64::Decode(&data1, &data2);

			if (!strncmp(data2.Ptr(), AUTH_PUBLIC_MAGIC, sizeof(AUTH_PUBLIC_MAGIC)))
			{
				data2.Consume(sizeof(AUTH_PUBLIC_MAGIC));
				int pubkeystrlen = 0;
				char* pubkeystr = data2.GetString(&pubkeystrlen);
				if (pubkeystr && pubkeystrlen)
				{
					Buffer pubkey;
					pubkey.Append(pubkeystr, pubkeystrlen);

					int name1len = 0;
					char* name1 = pubkey.GetString(&name1len);
					if (name1 && name1len == strlen(name) && !strcmp(name1, name))
					{
						int ppublen = 0;
						char* ppub = pubkey.GetString(&ppublen);
						if (ppublen && ppub)
						{
							if (publicData)
								publicData->Append(ppub, ppublen);

							ret = ERROR_NONE;
						}
					}
				}
			}
		}

		return ret;
	}
	
	static void PublicMagicExport(Buffer* data, const char* name, Buffer* publicData)
	{
		PublicMagicExport(data, name, publicData->Ptr(), publicData->Len());
	}
	
	static void PublicMagicExport(Buffer* data, const char* name, const char * publicData, size_t publicDataLen)
	{
		Buffer encoded;
		encoded.Append(AUTH_PUBLIC_MAGIC, sizeof(AUTH_PUBLIC_MAGIC));

		Buffer bpub;
		bpub.PutString(name);
		bpub.PutString(publicData, (unsigned int)publicDataLen);
		encoded.PutString(bpub.Ptr(), (unsigned int)bpub.Len());

		char MARK_BEGIN[1024], MARK_END[1024];
		if (strlen(name) > 128)
			return /*KEYERR_FAILED_TO_IMPORT_KEY*/;
		sprintf(MARK_BEGIN, AUTH_KEY_STR, AUTH_BEGIN, name, AUTH_PUBLIC);strupr(MARK_BEGIN);
		sprintf(MARK_END, AUTH_KEY_STR, AUTH_END, name, AUTH_PUBLIC);strupr(MARK_END);
		size_t MARK_BEGIN_LEN = strlen(MARK_BEGIN);
		size_t MARK_END_LEN = strlen(MARK_END);

		data->Append(MARK_BEGIN, MARK_BEGIN_LEN); data->Append("\r\n", 2);
		Base64::Encode(&encoded, data, 70);
		data->Append(MARK_END, MARK_END_LEN); data->Append("\r\n", 2);
	}

	virtual Buffer* PublicHash(void);

	Buffer* PublicHashBase64(void);

	const char* Name;
protected:
	Buffer* PublicExportBuffer;
	Buffer* PublicHashBuffer;
	Buffer *PublicHashBase64Buffer;
};

class PublicSignKey
{
protected:
	PublicSignKey()
	{
	}

public:
	virtual ~PublicSignKey()
	{
	}


	virtual int Verify(const char* data, size_t len, const char* sig, size_t siglen) = 0;
};

class Key : public PublicKey
{
protected:
	Key()
	{
		ExportBuffer = NULL;
	}

public:
	virtual ~Key()
	{
		if (ExportBuffer)
			delete ExportBuffer;
	}

	virtual int Import(Buffer* data)
	{
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}
	
	virtual Buffer* Export()
	{
		return NULL;
	}

	virtual int Load(const char* filename)
	{
		Buffer b;
		if (b.Load(filename))
			if (b.Len())
				return Import(&b);
		return KEYERR_FAILED_TO_LOAD_KEY;
	}

	virtual int Save(const char* filename)
	{
		int ret = KEYERR_FAILED_TO_SAVE_KEY;
		Buffer* b = Export();
		if (b && b->Len())
		{
			if (b->Save(filename))
				ret = ERROR_NONE;

			//delete b;
		}

		return ret;
	}


	virtual int Generate(void)
	{
		return KEYERR_INIT_FAILED;
	}

	virtual int MagicImport(Buffer* data, const char* name, Buffer* publicData, Buffer* privateData)
	{
		char MARK_BEGIN[1024], MARK_END[1024];
		if (strlen(name) > 128)
			return KEYERR_FAILED_TO_IMPORT_KEY;
		sprintf(MARK_BEGIN, AUTH_KEY_STR, AUTH_BEGIN, name, AUTH_PRIVATE);strupr(MARK_BEGIN);
		sprintf(MARK_END, AUTH_KEY_STR, AUTH_END, name, AUTH_PRIVATE);strupr(MARK_END);
		size_t MARK_BEGIN_LEN = strlen(MARK_BEGIN);
		size_t MARK_END_LEN = strlen(MARK_END);


		int ret = KEYERR_FAILED_TO_IMPORT_KEY;
		char* line;
		do
		{
			line = data->GetNextLine();
			if (line)
			{
				if (!strcmp(line, MARK_BEGIN))
					break;
			}
			else
				if (!strcmp(data->Ptr(), MARK_BEGIN))
					break;

		} while (line);

		Buffer data1;
		if (line)
		{
			do
			{
				line = data->GetNextLine();
				if (line)
				{
					if (!strcmp(line, MARK_END))
						break;

					data1.Append(line);
				}
				else
				{
					if (!strcmp(data->Ptr(), MARK_END))
						break;

					data1.Append(data->Ptr());
				}
			} while (line);
		}
		if (line && data1.Len())
		{
			Buffer data2;
			Base64::Decode(&data1, &data2);

			if (!strncmp(data2.Ptr(), AUTH_PRIVATE_MAGIC, sizeof(AUTH_PRIVATE_MAGIC)))
			{
				data2.Consume(sizeof(AUTH_PRIVATE_MAGIC));
				int pubkeystrlen = 0;
				char* pubkeystr = data2.GetString(&pubkeystrlen);
				if (pubkeystr && pubkeystrlen)
				{
					Buffer pubkey;
					pubkey.Append(pubkeystr, pubkeystrlen);
					int name1len = 0;
					char* name1 = pubkey.GetString(&name1len);
					if (name1 && name1len == strlen(name) && !strcmp(name1, name))
					{
						int ppublen = 0;
						char* ppub = pubkey.GetString(&ppublen);
						if (ppublen && ppub)
						{
							if (publicData)
								publicData->Append(ppub, ppublen);


							int privkeystrlen = 0;
							char* privkeystr = data2.GetString(&privkeystrlen);
							if (privkeystr && privkeystrlen)
							{
								Buffer privkey;
								privkey.Append(privkeystr, privkeystrlen);
								int name2len = 0;
								char* name2 = privkey.GetString(&name2len);
								if (name2 && name2len == strlen(name) && !strcmp(name2, name))
								{
									int pprivlen = 0;
									char* ppriv = privkey.GetString(&pprivlen);
									if (pprivlen && ppriv)
									{
										if (privateData)
											privateData->Append(ppriv, pprivlen);
										ret = ERROR_NONE;
									}
								}
							}
						}
					}
				}
			}
		}

		return ret;
	}
	virtual void MagicExport(Buffer* data, const char* name, Buffer* publicData, Buffer* privateData)
	{
		MagicExport(data, name, publicData->Ptr(), (unsigned int)publicData->Len(), privateData->Ptr(), (unsigned int)privateData->Len());
	}
	virtual void MagicExport(Buffer *data, const char *name, const char *publicData, unsigned int publicDataLen, const char *privateData, unsigned int privateDataLen)
	{
		Buffer encoded;
		encoded.Append(AUTH_PRIVATE_MAGIC, sizeof(AUTH_PRIVATE_MAGIC));

		Buffer bpub;
		bpub.PutString(name);
		bpub.PutString(publicData, publicDataLen);
		encoded.PutString(bpub.Ptr(), (unsigned int)bpub.Len());

		Buffer bpriv;
		bpriv.PutString(name);
		bpriv.PutString(privateData, privateDataLen);
		encoded.PutString(bpriv.Ptr(), (unsigned int)bpriv.Len());

		char MARK_BEGIN[1024], MARK_END[1024];
		if (strlen(name) > 128)
			return/*KEYERR_FAILED_TO_IMPORT_KEY*/;
		sprintf(MARK_BEGIN, AUTH_KEY_STR, AUTH_BEGIN, name, AUTH_PRIVATE); strupr(MARK_BEGIN);
		sprintf(MARK_END, AUTH_KEY_STR, AUTH_END, name, AUTH_PRIVATE); strupr(MARK_END);
		size_t MARK_BEGIN_LEN = strlen(MARK_BEGIN);
		size_t MARK_END_LEN = strlen(MARK_END);

		data->Append(MARK_BEGIN, MARK_BEGIN_LEN); data->Append("\r\n", 2);
		Base64::Encode(&encoded, data, 70);
		data->Append(MARK_END, MARK_END_LEN); data->Append("\r\n", 2);
	}

protected:
	Buffer* ExportBuffer;
};

class SignKey : /*public Key, */public PublicSignKey
{
protected:
	SignKey()
	{
	}

public:
	virtual ~SignKey()
	{
	}


	virtual int Sign(const char* data, size_t len, char* sigdata, size_t* siglen) = 0;
};


class _OpenSSLPublicKey
{
protected:
	_OpenSSLPublicKey()
	{
		pkey = NULL;
		PublicExportBuffer = NULL;

	}

public:
	~_OpenSSLPublicKey()
	{
		if (pkey)
			EVP_PKEY_free(pkey);
		if (PublicExportBuffer)
			delete PublicExportBuffer;
	}

	int _PublicLoad(const char* filename)
	{
		Buffer b;
		if (b.Load(filename))
			if (b.Len())
				return _PublicImport(&b);

		return KEYERR_FAILED_TO_LOAD_KEY;
	}

	virtual int _PublicImport(Buffer *data)
	{
		BIO* bufio;
		bufio = BIO_new_mem_buf((void*)data->Ptr(), (int)data->Len());
		if (PEM_read_bio_PUBKEY(bufio, &pkey, NULL, NULL))
		{
			BIO_free(bufio);
			return ERROR_NONE;
		}
		BIO_free(bufio);

		return KEYERR_FAILED_TO_IMPORT_KEY;
	}
	Buffer* _PublicExport()
	{
		BIO* bio;
		const BIO_METHOD* mem = BIO_s_mem();
		bio = BIO_new(mem);
		if (PEM_write_bio_PUBKEY(bio, pkey))
		{
			char* pp = NULL;
			long len = BIO_get_mem_data(bio, &pp);
			if (len > 0)
			{
				if (PublicExportBuffer)
					delete PublicExportBuffer;

				PublicExportBuffer = new Buffer(16384);
				PublicExportBuffer->Append(pp, len);
				BIO_free(bio);
				return PublicExportBuffer;
			}
		}
		BIO_free(bio);
		return NULL;
	}

	int _Verify(const char* data, size_t len, const char* sigdata, size_t siglen)
	{
		int ret = ERROR_NONE;

		if (pkey)
		{
			EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new(pkey, NULL);
			if (EVP_PKEY_verify_init(pkctx) > 0)
			{
				if (EVP_PKEY_verify(pkctx, (unsigned char*)sigdata, siglen, (unsigned char*)data, len) > 0)
				{
					// all is ok
				}
				else
					ret = SIGNERR_GENERAL_FAILURE;
				EVP_PKEY_CTX_free(pkctx);
			}
			else
				ret = KEYERR_INIT_FAILED;
		}
		else
			ret = KEYERR_INIT_FAILED;

		return ret;
	}
	virtual int _Verify2(const char* data, size_t len, const char* sigdata, size_t siglen)
	{
		int ret = SIGNERR_VERIFY_FAILURE;

		if (pkey)
		{
			EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

			if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1)
			{
				if (EVP_DigestVerify(md_ctx, (unsigned char*)sigdata, siglen, (const unsigned char*)data, len) == 1)
				{
					ret = ERROR_NONE;
				}
			}
			EVP_MD_CTX_free(md_ctx);
		}
		else
			ret = KEYERR_INIT_FAILED;

		return ret;
	}


protected:
	EVP_PKEY* pkey;

	Buffer *PublicExportBuffer;
};

class OpenSSLPublicKey : public PublicSignKey, public _OpenSSLPublicKey
{
protected:
	OpenSSLPublicKey()
	{
	}

public:
	virtual ~OpenSSLPublicKey()
	{
	}

	virtual int PublicLoad(const char* filename)
	{
		return _PublicLoad(filename);
	}
	
	virtual int PublicImport(Buffer* data)
	{
		return _PublicImport(data);
	}
		
	virtual Buffer* PublicExport()
	{
		return _PublicExport();
	}

	virtual int Verify(const char* data, size_t len, const char* sigdata, size_t siglen)
	{
		return _Verify(data, len, sigdata, siglen);
	}

};

class _OpenSSLKey : public _OpenSSLPublicKey
{
protected:
	_OpenSSLKey()
	{
		ExportBuffer = NULL;
	}

public:
	virtual ~_OpenSSLKey()
	{
		if (ExportBuffer)
			delete ExportBuffer;
	}

protected:
	virtual int _Generate_ex(EVP_PKEY_CTX* pctx)
	{
		return ERROR_NONE;
	}

public:
	virtual int _Generate(int keytype)
	{
		if (pkey)
			EVP_PKEY_free(pkey);
		pkey = NULL;


		EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(keytype, NULL);

		if (EVP_PKEY_keygen_init(pctx) <= 0)
			return KEYERR_INIT_FAILED;

		if (_Generate_ex(pctx) != ERROR_NONE)
			return KEYERR_INIT_EX_FAILED;

		if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
			return KEYERR_INIT_FAILED;

		EVP_PKEY_CTX_free(pctx);

		return ERROR_NONE;
	}

	virtual int _Load(const char* filename)
	{
		Buffer b;
		if (b.Load(filename))
			if (b.Len())
				return _Import(&b);
		return KEYERR_FAILED_TO_LOAD_KEY;
	}
	virtual int _Import(Buffer* data)
	{
		BIO* bufio;
		bufio = BIO_new_mem_buf((void*)data->Ptr(), (int)data->Len());
		if (PEM_read_bio_PrivateKey(bufio, &pkey, NULL, NULL))
		{
			BIO_free(bufio);
			return ERROR_NONE;
		}
		BIO_free(bufio);
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}

	virtual Buffer* _Export()
	{
		BIO* bio;
		const BIO_METHOD* mem = BIO_s_mem();
		bio = BIO_new(mem);
		if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
		{
			char* pp = NULL;
			long len = BIO_get_mem_data(bio, &pp);
			if (len > 0)
			{
				if (ExportBuffer)
					delete ExportBuffer;
				ExportBuffer = new Buffer(16384);
				ExportBuffer->Append(pp, len);
				BIO_free(bio);
				return ExportBuffer;
			}
		}
		BIO_free(bio);
		return NULL;
	}

	virtual int _Sign(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		int ret = ERROR_NONE;

		if (pkey)
		{
			size_t lentmp = (size_t)EVP_PKEY_size(pkey);
			if (!sigdata)
			{
				if (siglen)
					*siglen = lentmp;
				return ERROR_NONE;
			}

			if (siglen && *siglen >= lentmp)
			{
				EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new(pkey, NULL);
				if (EVP_PKEY_sign_init(pkctx) > 0)
				{
					if (EVP_PKEY_sign(pkctx, (unsigned char*)sigdata, &lentmp, (unsigned char*)data, len) > 0)
					{
						*siglen = lentmp;
					}
					else
						ret = SIGNERR_GENERAL_FAILURE;
					EVP_PKEY_CTX_free(pkctx);
				}
				else
					ret = KEYERR_INIT_FAILED;
			}
			else
				ret = ERROR_BUFFER_TOO_SMALL;
		}
		else
			ret = KEYERR_INIT_FAILED;

		return ret;
	}

	virtual int _Sign2(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		int ret = KEYERR_SIGN_FAILED;

		if (pkey)
		{
			EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

			size_t sig_len = 0;
			if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1)
			{
				if (EVP_DigestSign(md_ctx, NULL, &sig_len, (const unsigned char*)data, len) == 1)
				{
					if (*siglen >= sig_len)
					{
						if (EVP_DigestSign(md_ctx, (unsigned char*)sigdata, &sig_len, (const unsigned char*)data, len) == 1)
						{
							*siglen = sig_len;
							ret = ERROR_NONE;
						}
					}
					else
						ret = ERROR_BUFFER_TOO_SMALL;
				}
			}
			EVP_MD_CTX_free(md_ctx);
		}
		else
			ret = KEYERR_INIT_FAILED;

		return ret;
	}


protected:
	Buffer* ExportBuffer;
};


class OpenSSLKey : public SignKey, public _OpenSSLKey
{
protected:
	OpenSSLKey()
	{
	}

public:
	virtual ~OpenSSLKey()
	{
	}



public:

	virtual int PublicLoad(const char* filename)
	{
		return _PublicLoad(filename);
	}

	virtual int Load(const char* filename)
	{
		return _Load(filename);
	}

	virtual int PublicImport(Buffer* data)
	{
		return _PublicImport(data);
	}

	virtual Buffer* PublicExport()
	{
		return _PublicExport();
	}

	virtual int Import(Buffer* data)
	{
		return _Import(data);
	}
	virtual Buffer* Export(void)
	{
		return _Export();
	}

	virtual int Sign(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		return _Sign(data, len, sigdata, siglen);
	}
	virtual int Verify(const char* data, size_t len, const char* sigdata, size_t siglen)
	{
		return _Verify2(data, len, sigdata, siglen);
	}

};


class Key_RSA : public OpenSSLKey, public Key
{
public:
	Key_RSA()
	{
		Name = "rsa";
	}

protected:
	virtual int _Generate_ex(EVP_PKEY_CTX *pctx)
	{
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
			return KEYERR_INIT_FAILED;

		return ERROR_NONE;
	}

public:
	virtual int Generate(void)
	{
		return _Generate(EVP_PKEY_RSA);
	}
};

class Key_ECDSA256 : public OpenSSLKey, public Key
{
public:
	Key_ECDSA256()
	{
		Name = "ecdsa256";
	}

protected:
	virtual int _Generate_ex(EVP_PKEY_CTX* pctx)
	{
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
			return KEYERR_INIT_FAILED;

		return ERROR_NONE;
	}

public:
	virtual int Generate()
	{
		return _Generate(EVP_PKEY_EC);
	}
};

class Key_ECDSA384 : public OpenSSLKey, public Key
{
public:
	Key_ECDSA384()
	{
		Name = "ecdsa384";
	}

protected:
	virtual int _Generate_ex(EVP_PKEY_CTX* pctx)
	{
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0)
			return KEYERR_INIT_FAILED;

		return ERROR_NONE;
	}

public:
	virtual int Generate()
	{
		return _Generate(EVP_PKEY_EC);
	}
};

class Key_ECDSA521 : public OpenSSLKey, public Key
{
public:
	Key_ECDSA521()
	{
		Name = "ecdsa521";
	}

protected:
	virtual int _Generate_ex(EVP_PKEY_CTX* pctx)
	{
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1) <= 0)
			return KEYERR_INIT_FAILED;

		return ERROR_NONE;
	}

public:
	virtual int Generate()
	{
		return _Generate(EVP_PKEY_EC);
	}
};

/*
class Key_ED25519 : public OpenSSLKey
{
public:
	Key_ED25519()
	{
		Name = "ed25519";
	}

	virtual ~Key_ED25519()
	{
	}
	virtual int Generate(void)
	{
		return _Generate(EVP_PKEY_ED25519);
	}

	virtual int Sign(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		return _Sign2(data, len, sigdata, siglen);
	}

	virtual Buffer* Export(void)
	{
		if (pkey)
		{
			char buff[32768];
			size_t len = sizeof(buff);
			EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)buff, &len);
			len = 0;
		}
		return NULL;
	}


};
*/
class Key_ED448 : public OpenSSLKey, public Key
{
public:
	Key_ED448()
	{
		Name = "ed448";
	}

	virtual ~Key_ED448()
	{
	
	}
	virtual int Generate(void)
	{
		return _Generate(EVP_PKEY_ED448);
	}
};

class Key_KEX 
{
protected:
	Key_KEX()
	{
	
	}

public:
	virtual ~Key_KEX()
	{
	
	}

	virtual int Compute(Buffer* remotepubkey, Buffer* secret)
	{
		return false;
	}
};

class Key_DH : public Key_KEX, public OpenSSLKey, public Key
{
public:
	Key_DH()
	{
		Name = "dh";
		dh = NULL;
		PublicExportBuffer = NULL;
	}

	virtual ~Key_DH()
	{
		if (dh)
			DH_free(dh);
		if (PublicExportBuffer)
			delete PublicExportBuffer;
	}
	virtual int Generate(void)
	{
		if (dh)
			DH_free(dh);

		dh = DH_new();

		const char* gen = "2", * group14 =
			"FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
			"29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
			"EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
			"E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
			"EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
			"C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
			"83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
			"670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
			"E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
			"DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
			"15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF";

		BIGNUM *p = BN_new();
		BN_hex2bn(&p, group14);

		BIGNUM* g = BN_new();
		BN_hex2bn(&g, gen);
		DH_set0_pqg(dh, p, NULL, g);

		//if (DH_generate_parameters_ex(dh, 64, DH_GENERATOR_5, 0))
		{
			int dh_code = 0;
			if (DH_check(dh, &dh_code))
			{
				if (DH_generate_key(dh))
				{
					return ERROR_NONE;
				}
			}
		}
		return KEYERR_INIT_FAILED;
	}

	virtual int Compute(Buffer* remotepubkey, Buffer* secret)
	{
		int ret = KEYERR_INIT_FAILED;
		if (remotepubkey)
		{
			char* a = remotepubkey->GetString();
			if (a)
			{
				if (!strcmp(a, Name))
				{
					int len = remotepubkey->GetInt();
					if (len)
					{
						BIGNUM* pub = BN_bin2bn((const unsigned char*)remotepubkey->Ptr(), len, NULL);
						if (pub)
						{
							if (secret)
							{
								int alen = DH_size(dh);
								char* keyp;
								secret->AppendSpace(&keyp, alen);
								int sharedlen = DH_compute_key((unsigned char *)keyp, pub, dh);
								if (sharedlen > 0)
									ret = ERROR_NONE;
							}
							else
								ret = ERROR_BUFFER_TOO_SMALL;
						}
						else
							ret = KEYERR_INVALID_KEY_TYPE;
						BN_clear_free(pub);
					}
					else
						ret = KEYERR_INVALID_KEY_TYPE;
				}
				else
					ret = KEYERR_INVALID_KEY_TYPE;
			}
			else
				ret = KEYERR_INVALID_KEY_TYPE;
		}
		return ret;
	}

	virtual int Load(const char* filename)
	{
		int ret = _Load(filename);
		if (ret == ERROR_NONE)
		{
			if (dh)
				DH_free(dh);
			dh = NULL;
			if (pkey)
			{
				dh = EVP_PKEY_get1_DH(pkey);
				EVP_PKEY_free(pkey);
				pkey = NULL;

			}
			else
				return KEYERR_FAILED_TO_LOAD_KEY;
		}
		return ret;
	}

	virtual Buffer* PublicExport(void)
	{
		if (dh)
		{
			if (PublicExportBuffer)
				delete PublicExportBuffer;
			PublicExportBuffer = new Buffer();
			PublicExportBuffer->PutString(Name);
			const BIGNUM* dhp = DH_get0_pub_key(dh);
			int plen = BN_num_bytes(dhp);
			PublicExportBuffer->PutInt(plen);
			unsigned char* pdata;
			PublicExportBuffer->AppendSpace((char **) & pdata, plen);
			BN_bn2bin(dhp, pdata);
			return PublicExportBuffer;
		}
		return NULL;
	}

	virtual int Import(Buffer* data)
	{

		return -1;
	}

	virtual Buffer* Export()
	{
		if (pkey)
			EVP_PKEY_free(pkey);

		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_DH(pkey, dh);
		Buffer* out = _Export();

		EVP_PKEY_free(pkey);
		pkey = NULL;

		return out;
	}

protected:
	DH* dh;
	Buffer* PublicExportBuffer;
};

class Key_ECDH : public Key_KEX, public OpenSSLKey, public Key
{
protected:
	Key_ECDH(int nid)
	{
		Name = "ecdh";
		ec = NULL;
		this->nid = nid;
	}

	virtual ~Key_ECDH()
	{
		if (ec)
			EC_KEY_free(ec);
	}

public:
	virtual int Generate(void)
	{
		if (ec)
			EC_KEY_free(ec);

		ec = EC_KEY_new_by_curve_name(nid);
		if (ec)
		{
			if (EC_KEY_generate_key(ec) == 1)
			{
				return ERROR_NONE;
			}
		}
		return KEYERR_INIT_FAILED;
	}

	virtual int Compute(Buffer* remotepubkey, Buffer* secret)
	{
		int ret = KEYERR_INIT_FAILED;
		if (remotepubkey)
		{
			char* a = remotepubkey->GetString();
			if (a)
			{
				if (!strcmp(a, Name))
				{
					int len = remotepubkey->GetInt();
					if (len)
					{
						if (len <= BUFFER_MAX_ECPOINT_LEN)
						{
							char* pkey = remotepubkey->Ptr();
							if (pkey[0] == POINT_CONVERSION_UNCOMPRESSED)
							{
								EC_KEY *tempkey = EC_KEY_new_by_curve_name(nid);
								EC_GROUP* curve = (EC_GROUP *)EC_KEY_get0_group(tempkey);
								EC_POINT *point = EC_POINT_new(curve);
								BN_CTX* bnctx = BN_CTX_new();
								if (EC_POINT_oct2point(curve, point, (const unsigned char *)pkey, len, bnctx) == 1)
								{
									if (secret)
									{
										int field_size = EC_GROUP_get_degree(curve);
										int sharedlen = (field_size + 7) / 8;
										char* keyp;
										secret->AppendSpace(&keyp, sharedlen);
										sharedlen = ECDH_compute_key(keyp, sharedlen, point, ec, NULL);
										if (sharedlen > 0)
											ret = ERROR_NONE;
									}
									else
										ret = ERROR_BUFFER_TOO_SMALL;
								}
								else
									ret = KEYERR_INVALID_KEY_TYPE;
								EC_POINT_clear_free(point);
								EC_KEY_free(tempkey);
								BN_CTX_free(bnctx);
							}
							else
								ret = KEYERR_INVALID_KEY_TYPE;
						}
						else
							ret = ERROR_BUFFER_TOO_SMALL;
					}
					else
						ret = KEYERR_INVALID_KEY_TYPE;
				}
				else
					ret = KEYERR_INVALID_KEY_TYPE;
			}
			else
				ret = KEYERR_INVALID_KEY_TYPE;
		}
		return ret;
	}

	virtual int Load(const char* filename)
	{
		int ret = _Load(filename);
		if (ret == ERROR_NONE)
		{
			if (ec)
				EC_KEY_free(ec);
			ec = NULL;
			if (pkey)
			{
				ec = EVP_PKEY_get1_EC_KEY(pkey);
				EVP_PKEY_free(pkey);
				pkey = NULL;

			}
			else
				return KEYERR_FAILED_TO_LOAD_KEY;
		}
		return ret;
	}

	virtual Buffer* PublicExport(void)
	{
		if (ec)
		{
/*

			char buff[BUFFER_MAX_ECPOINT_LEN];

			Buffer* b = new Buffer();
			b->PutString(Name);

			BN_CTX* bnctx = BN_CTX_new();
			size_t len = EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec), POINT_CONVERSION_UNCOMPRESSED, (unsigned char *)buff, sizeof(buff), bnctx);
			BN_CTX_free(bnctx);
			b->PutString(buff, (int)len);
			return b;
*/
			BIO * bio;
			const BIO_METHOD* mem = BIO_s_mem();
			bio = BIO_new(mem);
			if (PEM_write_bio_PUBKEY(bio, pkey))
			{
				char* pp = NULL;
				long len = BIO_get_mem_data(bio, &pp);
				if (len > 0)
				{
					if (PublicKey::PublicExportBuffer)
						delete PublicKey::PublicExportBuffer;

					PublicKey::PublicExportBuffer = new Buffer(16384);
					PublicKey::PublicExportBuffer->Append(pp, len);
					BIO_free(bio);
					return PublicKey::PublicExportBuffer;
				}
			}
			BIO_free(bio);
			return NULL;			
		}
		return NULL;
	}

	virtual Buffer* Export()
	{
		if (pkey)
			EVP_PKEY_free(pkey);

		pkey = EVP_PKEY_new();
		if (ec)
			EVP_PKEY_set1_EC_KEY(pkey, ec);
		Buffer* out = _Export();

		EVP_PKEY_free(pkey);
		pkey = NULL;

		return out;
	}

protected:
	EC_KEY* ec;
	int nid;
};

extern "C"
{
#include "dep/c25519/c25519.h"
#include "dep/c25519/ed25519.h"

}

class Key_ED25519 : public SignKey, public Key
{
public:
	Key_ED25519()
	{
		Name = "ed25519";
		ExportBuffer = NULL;
		PublicExportBuffer = NULL;

		memset(priv, 0, ED25519_EXPONENT_SIZE);
		memset(pub, 0, F25519_SIZE);
	}

	virtual ~Key_ED25519()
	{
		if (ExportBuffer)
			delete ExportBuffer;
		if (PublicExportBuffer)
			delete PublicExportBuffer;

		memset(priv, 0, ED25519_EXPONENT_SIZE);
		memset(pub, 0, F25519_SIZE);
	}
	virtual Buffer* Export()
	{
		if (ExportBuffer)
			delete ExportBuffer;
		ExportBuffer = new Buffer();
		MagicExport(ExportBuffer, Name, (const char*)pub, F25519_SIZE, (const char *)priv, ED25519_EXPONENT_SIZE);
		return ExportBuffer;
	}
	virtual int Import(Buffer* data)
	{
		Buffer pubdata, privdata;
		int ret = MagicImport(data, Name, &pubdata, &privdata);
		if (ret == ERROR_NONE)
		{
			if (pubdata.Len() == F25519_SIZE)
			{
				if (privdata.Len() == ED25519_EXPONENT_SIZE)
				{
					memcpy(pub, pubdata.Ptr(), pubdata.Len());
					memcpy(priv, privdata.Ptr(), privdata.Len());

					return ERROR_NONE;
				}
			}
		}
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}

	virtual int Generate(void)
	{
		if (ExportBuffer)
			delete ExportBuffer;
		ExportBuffer = NULL;
		if (PublicExportBuffer)
			delete PublicExportBuffer;
		PublicExportBuffer = NULL;
		RAND_bytes(priv, ED25519_EXPONENT_SIZE);

#define EXPANDED_SIZE	64
		unsigned char expanded[EXPANDED_SIZE];

		struct sha512_state s1;
		sha512_init(&s1);
		sha512_final(&s1, priv, ED25519_EXPONENT_SIZE);
		sha512_get(&s1, expanded, 0, EXPANDED_SIZE);

		ed25519_prepare((uint8_t *)expanded);

		struct ed25519_pt p;
		ed25519_smult(&p, &ed25519_base, (const uint8_t*)expanded);

		uint8_t x[F25519_SIZE], y[F25519_SIZE];
		ed25519_unproject(x, y, &p);
		ed25519_pack(pub, x, y);

		return ERROR_NONE;
	}

	virtual int Sign(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		int ret = ERROR_NONE;
		if (siglen)
			*siglen = 64;
		if (sigdata)
			edsign_sign((uint8_t *)sigdata, pub, priv, (uint8_t*)data, len);


		return ret;
	}

	virtual Buffer* PublicExport()
	{
		if (PublicExportBuffer)
			delete PublicExportBuffer;
		PublicExportBuffer = new Buffer();
		PublicMagicExport(PublicExportBuffer, Name, (const char *)pub, F25519_SIZE);
		return PublicExportBuffer;
	}
	virtual int PublicImport(Buffer* data)
	{
		Buffer d;
		int ret = PublicMagicImport(data, Name, &d);
		if (ret == ERROR_NONE)
		{
			if (d.Len() == F25519_SIZE)
				memcpy(pub, d.Ptr(), d.Len());
			return ERROR_NONE;
		}

		return KEYERR_FAILED_TO_IMPORT_KEY;
	}

	virtual int Verify(const char* data, size_t datalen, const char* sig, size_t siglen)
	{
		if (edsign_verify((const uint8_t *)sig, pub, (const uint8_t*)data, datalen) == 1)
			return ERROR_NONE;

		return SIGNERR_VERIFY_FAILURE;
	}



protected:
	unsigned char priv[ED25519_EXPONENT_SIZE], pub[F25519_SIZE];
	Buffer* ExportBuffer;
	Buffer* PublicExportBuffer;
};


class Key_ECDH25519 : public Key_KEX, public Key_ED25519
{
public:
	Key_ECDH25519() : Key_KEX(), Key_ED25519()
	{
		Name = "x25519";
	}

	virtual int Compute(Buffer* remotepubkey, Buffer* secret)
	{
		int ret = COMPUTEERR_GENERAL_FAILURE;

		unsigned char tmp_priv[ED25519_EXPONENT_SIZE], tmp_pub[F25519_SIZE];
		memcpy(tmp_priv, priv, ED25519_EXPONENT_SIZE);
		memcpy(tmp_pub, pub, F25519_SIZE);

		if (PublicImport(remotepubkey) == ERROR_NONE)
		{
			char priv2[32];

			uint8_t x1[F25519_SIZE];
			uint8_t y1[F25519_SIZE];
			ed25519_try_unpack(x1, y1, pub);
			morph25519_e2m(x1, y1);
			morph25519_secret_e2m((uint8_t *)priv2, tmp_priv);

			unsigned char secret1[EDSIGN_SECRET_KEY_SIZE];
			c25519_smult(secret1, x1, (uint8_t *)priv2);

			secret->Append((const char *)secret1, EDSIGN_SECRET_KEY_SIZE);
			ret = ERROR_NONE;
		}

		memcpy(priv, tmp_priv, ED25519_EXPONENT_SIZE);
		memcpy(pub, tmp_pub, F25519_SIZE);
		return ret;
	}

protected:

	Key_ED25519 ked;
};
class Key_ECDH256 : public Key_ECDH
{
public:
	Key_ECDH256() : Key_ECDH(NID_X9_62_prime256v1)
	{
		Name = "ecdh256";
	}
};
class Key_ECDH384 : public Key_ECDH
{
public:
	Key_ECDH384() : Key_ECDH(NID_secp384r1)
	{
		Name = "ecdh384";
	}
};
class Key_ECDH521 : public Key_ECDH
{
public:
	Key_ECDH521() : Key_ECDH(NID_secp521r1)
	{
		Name = "ecdh521";
	}
};


#endif
