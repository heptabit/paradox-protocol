#ifndef QKEY_H
#define QKEY_H

#include "Platform.h"
#include "Errors.h"
#include "Buffer.h"
#include "Base64.h"
#include "Rand.h"
#include "Key.h"
#include <oqs/oqs.h>


class Buffer;
class Hash;


class QKey : public Key
{
protected:
	QKey()
	{
		PublicKeySize = 0;
		PrivateKeySize = 0;
		privateKeyData = NULL;
		publicKeyData = NULL;
	}

public:
	virtual ~QKey()
	{
		free(publicKeyData);
		free(privateKeyData);
	}

	virtual Buffer* PublicExport()
	{
		if (ExportBuffer)
			delete ExportBuffer;
		ExportBuffer = new Buffer();
		PublicMagicExport(ExportBuffer, Name, publicKeyData, PublicKeySize);
		return ExportBuffer;
	}
	virtual int PublicImport(Buffer* data)
	{
		Buffer pubkey;
		int ret = PublicMagicImport(data, Name, &pubkey);
		if (ret == ERROR_NONE)
		{
			if (pubkey.Len() == PublicKeySize)
			{
				if (!publicKeyData)
					publicKeyData = (char*)malloc(PublicKeySize);
				if (publicKeyData)
					memcpy(publicKeyData, pubkey.Ptr(), pubkey.Len());
				return ERROR_NONE;
			}
		}
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}


	virtual int Import(Buffer* data)
	{
		Buffer pubkey, privkey;
		int ret = MagicImport(data, Name, &pubkey, &privkey);
		if (ret == ERROR_NONE)
		{
			if (pubkey.Len() == PublicKeySize && privkey.Len() == PrivateKeySize)
			{
				if (!publicKeyData)
					publicKeyData = (char*)malloc(PublicKeySize);
				if (publicKeyData)
					memcpy(publicKeyData, pubkey.Ptr(), pubkey.Len());
				if (!privateKeyData)
					privateKeyData = (char*)malloc(PrivateKeySize);
				if (privateKeyData)
					memcpy(privateKeyData, privkey.Ptr(), privkey.Len());

				return ERROR_NONE;
			}
		}
		return KEYERR_FAILED_TO_IMPORT_KEY;
	}

	virtual Buffer* Export()
	{
		if (ExportBuffer)
			delete ExportBuffer;
		ExportBuffer = new Buffer();
		MagicExport(ExportBuffer, Name, publicKeyData, PublicKeySize, privateKeyData, PrivateKeySize);
		return ExportBuffer;
	}

	virtual int Generate(void)
	{
		if (!publicKeyData)
			publicKeyData = (char*)malloc(PublicKeySize);
		Rand::Bytes((unsigned char *)publicKeyData, PublicKeySize);
		if (!privateKeyData)
			privateKeyData = (char*)malloc(PrivateKeySize);
		Rand::Bytes((unsigned char *)privateKeyData, PrivateKeySize);

		return ERROR_NONE;
	}


	int PublicKeySize, PrivateKeySize;

protected:
	char* publicKeyData;
	char* privateKeyData;
};

class EncapsQKey : public QKey
{
protected:
	EncapsQKey()
	{
		CipherSize = 0;
		SecretSize = 0;

		SecretData = 0;
		CipherData = NULL;
	}

public:
	virtual ~EncapsQKey()
	{
		free(CipherData);
		free(SecretData);
	}

	virtual int Encapsulate(Buffer* publicKey) = 0;
	virtual int Decapsulate(char* cipherData) = 0;

	int CipherSize, SecretSize;
	char* CipherData, * SecretData;

};

class LibOQSEncapsQKey : public EncapsQKey
{
public:
	LibOQSEncapsQKey(const char *name, int cipherSize, int privateKeySize, int publicKeySize, int secretSize, OQS_STATUS (*generate)(uint8_t* public_key, uint8_t* secret_key), OQS_STATUS (*encaps)(uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key), OQS_STATUS (*decaps)(uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key))
	{
		Name = name;
		CipherSize = cipherSize;
		PrivateKeySize = privateKeySize;
		PublicKeySize = publicKeySize;
		SecretSize = secretSize;

		_generate = generate;
		_encaps = encaps;
		_decaps = decaps;
	}

	virtual ~LibOQSEncapsQKey()
	{
	}


	virtual int Generate(void)
	{
		if (!publicKeyData)
			publicKeyData = (char*)malloc(PublicKeySize);
		if (!privateKeyData)
			privateKeyData = (char*)malloc(PrivateKeySize);

		if (_generate)
			if (_generate((uint8_t*)publicKeyData, (uint8_t*)privateKeyData) == OQS_SUCCESS)
				return ERROR_NONE;

		return KEYERR_INIT_FAILED;
	}
	virtual int Encapsulate(Buffer* remotepubkey)
	{
		Buffer pubkey;
		int ret = PublicMagicImport(remotepubkey, Name, &pubkey);
		if (ret == ERROR_NONE)
		{
			if (pubkey.Len() == PublicKeySize)
			{
				if (!CipherData)
					CipherData = (char*)malloc(CipherSize);
				if (!SecretData)
					SecretData = (char*)malloc(SecretSize);
				if (CipherData && SecretData && _encaps)
				{
					if (_encaps((uint8_t*)CipherData, (uint8_t*)SecretData, (uint8_t*)pubkey.Ptr()) == OQS_SUCCESS)
						return ERROR_NONE;
				}
			}
		}

		return KEYERR_COMPUTE_FAILED;
	};
	virtual int Encapsulate(void)
	{
		if (publicKeyData)
		{
			if (!CipherData)
				CipherData = (char*)malloc(CipherSize);
			if (!SecretData)
				SecretData = (char*)malloc(SecretSize);
			if (CipherData && SecretData && _encaps)
			{
				if (_encaps((uint8_t*)CipherData, (uint8_t*)SecretData, (uint8_t *) publicKeyData) == OQS_SUCCESS)
					return ERROR_NONE;
			}
		}

		return KEYERR_COMPUTE_FAILED;
	};
	virtual int Decapsulate(char* cipherData)
	{
		if (privateKeyData)
		{
			if (!SecretData)
				SecretData = (char*)malloc(SecretSize);
			if (cipherData && SecretData && _decaps)
			{
				if (_decaps((uint8_t*)SecretData, (uint8_t*)cipherData, (uint8_t*)privateKeyData) == OQS_SUCCESS)
					return ERROR_NONE;
			}
		}
		return KEYERR_COMPUTE_FAILED;
	}

protected:
	OQS_STATUS (*_generate)(uint8_t* public_key, uint8_t* secret_key);
	OQS_STATUS (*_encaps)(uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key);
	OQS_STATUS (*_decaps)(uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key);
};

class SignQKey : public SignKey
{
public:
	SignQKey()
	{
		SignatureSize = 0;
		signatureData = NULL;
	}

	virtual ~SignQKey()
	{
		free(signatureData);
	}

	int SignatureSize;
	char* signatureData;
};

class LibOQSSignQKey : public SignQKey, public QKey
{
public:
	LibOQSSignQKey(const char* name, int privateKeySize, int publicKeySize, int signatureSize, OQS_STATUS(*generate)(uint8_t* public_key, uint8_t* secret_key), OQS_STATUS(*sign)(uint8_t* signature, size_t* signature_len, const uint8_t* message, size_t message_len, const uint8_t* secret_key), OQS_STATUS(*verify)(const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len, const uint8_t* public_key))
	{
		Name = name;
		PrivateKeySize = privateKeySize;
		PublicKeySize = publicKeySize;
		SignatureSize = signatureSize;

		_generate = generate;
		_sign = sign;
		_verify = verify;
	}

	virtual ~LibOQSSignQKey()
	{
	}


	virtual int Generate(void)
	{
		if (!publicKeyData)
			publicKeyData = (char*)malloc(PublicKeySize);
		if (!privateKeyData)
			privateKeyData = (char*)malloc(PrivateKeySize);

		if (_generate)
			if (_generate((uint8_t*)publicKeyData, (uint8_t*)privateKeyData) == OQS_SUCCESS)
				return ERROR_NONE;

		return KEYERR_INIT_FAILED;
	}

	virtual int Sign(const char* data, size_t len, char* sigdata, size_t* siglen)
	{
		if (_sign((uint8_t *)sigdata, siglen, (const uint8_t*)data, len, (const uint8_t *)privateKeyData) == OQS_SUCCESS)
		{
			return ERROR_NONE;
		}

		return SIGNERR_GENERAL_FAILURE;
	}
	virtual int Verify(const char* data, size_t len, const char* sig, size_t siglen)
	{
		if (_verify((const uint8_t*)data, len, (const uint8_t*)sig, siglen, (const uint8_t*)publicKeyData) == OQS_SUCCESS)
			return ERROR_NONE;

		return VERIFYERR_GENERAL_FAILURE;
	}


protected:

	OQS_STATUS(*_generate)(uint8_t* public_key, uint8_t* secret_key);
	OQS_STATUS(*_sign)(uint8_t* signature, size_t* signature_len, const uint8_t* message, size_t message_len, const uint8_t* secret_key);
	OQS_STATUS(*_verify)(const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len, const uint8_t* public_key);
};

class QKey_FrodoKem640Aes : public LibOQSEncapsQKey
{
public:
	QKey_FrodoKem640Aes() : LibOQSEncapsQKey(
		"frodokem640aes", 
		OQS_KEM_frodokem_640_aes_length_ciphertext, 
		OQS_KEM_frodokem_640_aes_length_secret_key, 
		OQS_KEM_frodokem_640_aes_length_public_key,
		OQS_KEM_frodokem_640_aes_length_shared_secret,
		OQS_KEM_frodokem_640_aes_keypair, 
		OQS_KEM_frodokem_640_aes_encaps,
		OQS_KEM_frodokem_640_aes_decaps
	)
	{
	}

	virtual ~QKey_FrodoKem640Aes()
	{
	}
};

class QKey_FrodoKem640Shake : public LibOQSEncapsQKey
{
public:
	QKey_FrodoKem640Shake() : LibOQSEncapsQKey(
		"frodokem640shake",
		OQS_KEM_frodokem_640_shake_length_ciphertext,
		OQS_KEM_frodokem_640_shake_length_secret_key,
		OQS_KEM_frodokem_640_shake_length_public_key,
		OQS_KEM_frodokem_640_shake_length_shared_secret,
		OQS_KEM_frodokem_640_shake_keypair,
		OQS_KEM_frodokem_640_shake_encaps,
		OQS_KEM_frodokem_640_shake_decaps
	)
	{
	}

	virtual ~QKey_FrodoKem640Shake()
	{
	}
};

class QKey_NTRU_hps2048509 : public LibOQSEncapsQKey
{
public:
	QKey_NTRU_hps2048509() : LibOQSEncapsQKey(
		"ntru_hps2048509",
		OQS_KEM_ntru_hps2048509_length_ciphertext,
		OQS_KEM_ntru_hps2048509_length_secret_key,
		OQS_KEM_ntru_hps2048509_length_public_key,
		OQS_KEM_ntru_hps2048509_length_shared_secret,
		OQS_KEM_ntru_hps2048509_keypair,
		OQS_KEM_ntru_hps2048509_encaps,
		OQS_KEM_ntru_hps2048509_decaps
	)
	{
	}

	virtual ~QKey_NTRU_hps2048509()
	{
	}
};

class QKey_NTRU_hps2048677 : public LibOQSEncapsQKey
{
public:
	QKey_NTRU_hps2048677() : LibOQSEncapsQKey(
		"ntru_hps2048677",
		OQS_KEM_ntru_hps2048677_length_ciphertext,
		OQS_KEM_ntru_hps2048677_length_secret_key,
		OQS_KEM_ntru_hps2048677_length_public_key,
		OQS_KEM_ntru_hps2048677_length_shared_secret,
		OQS_KEM_ntru_hps2048677_keypair,
		OQS_KEM_ntru_hps2048677_encaps,
		OQS_KEM_ntru_hps2048677_decaps
	)
	{
	}

	virtual ~QKey_NTRU_hps2048677()
	{
	}
};

class QKey_Kyber1024 : public LibOQSEncapsQKey
{
public:
	QKey_Kyber1024() : LibOQSEncapsQKey(
		"kyber_1024",
		OQS_KEM_kyber_1024_length_ciphertext,
		OQS_KEM_kyber_1024_length_secret_key,
		OQS_KEM_kyber_1024_length_public_key,
		OQS_KEM_kyber_1024_length_shared_secret,
		OQS_KEM_kyber_1024_keypair,
		OQS_KEM_kyber_1024_encaps,
		OQS_KEM_kyber_1024_decaps
	)
	{
	}

	virtual ~QKey_Kyber1024()
	{
	}
};


class QKey_Dilithium2 : public LibOQSSignQKey
{
public:
	QKey_Dilithium2() : LibOQSSignQKey(
		"dilithium2",
		OQS_SIG_dilithium_2_length_secret_key,
		OQS_SIG_dilithium_2_length_public_key,
		OQS_SIG_dilithium_2_length_signature,
		OQS_SIG_dilithium_2_keypair,
		OQS_SIG_dilithium_2_sign,
		OQS_SIG_dilithium_2_verify
	)
	{
	}

	virtual ~QKey_Dilithium2()
	{
	}
};

class QKey_Dilithium3 : public LibOQSSignQKey
{
public:
	QKey_Dilithium3() : LibOQSSignQKey(
		"dilithium3",
		OQS_SIG_dilithium_3_length_secret_key,
		OQS_SIG_dilithium_3_length_public_key,
		OQS_SIG_dilithium_3_length_signature,
		OQS_SIG_dilithium_3_keypair,
		OQS_SIG_dilithium_3_sign,
		OQS_SIG_dilithium_3_verify
	)
	{
	}

	virtual ~QKey_Dilithium3()
	{
	}
};


#endif
