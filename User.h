#ifndef USER_H
#define USER_H

#include <vector>

#include "Key.h"
#include "QKey.h"
#include "Hash.h"
#include "Symmetric.h"

#define SHARED_SECRET_SIZE	32
#define INIT_VECTOR_SIZE	32

class SenderUser;
class ReceiverUser;

typedef enum MessageType
{
	MessageTypeKeyExchange = 21,
	MessageTypeEncryptedMessageWithLen = 30,
	MessageTypeSignature = 40,
	//MessageTypeExchangeEncapsBundle = 50,
	MessageTypeExchangeEncapsOneTimeWithId = 51,
	MessageTypeExchangeEncapsAuthentication = 52,
	MessageTypeExchangeEphemeralPublicKeyWithId = 53,
	PayloadTypeUnknown = 100,
	PayloadTypeText = 101,
	PayloadTypeThumbsUp = 102,
	PayloadTypeMedia = 103,
	PayloadTypeFile = 104,
} MessageType;


class User
{
public:

protected:
	User(const char *name)
	{
		Name = strdup(name);
		shared_secret = NULL;
		init_vector = NULL;
		shared_index = 0;
	}

public:
	virtual ~User()
	{
		if (shared_secret)
			free(shared_secret);
		if (init_vector)
			free(init_vector);

	}

	char* Name;
	char* shared_secret;
	char* init_vector;
	unsigned int shared_index;

/*
	static int LoadAndVerifyData(SignKey* signkey, Buffer* data, const char* folder, const char* name)
	{
		Buffer sig;
		char buff[8192];
		sprintf(buff, "%s\\%s.sig", folder, name);
		if (sig.Load(buff))
		{
			Hash_SHA256 sha256;
			const char* d = sha256.Final(data->Ptr(), data->Len());
			return signkey->Verify(d, sha256.HashLen, sig.Ptr(), sig.Len());
		}
		return ERROR_FILE_IS_NOT_FOUND;
	}
*/

	static int LoadOrGenerateKey(Key* key, const char* name, unsigned int id = 0)
	{
		char buff[8192];
		if (strlen(name) > 8000)
			return KEYERR_FAILED_TO_LOAD_KEY;
		sprintf(buff, "private\\%s.%d", name, id);
		if (key->Load(buff) != ERROR_NONE)
		{
			key->Generate();
			if (name && *name)
				key->Save(buff);
		}

		if (name && *name)
		{
			sprintf(buff, "public\\%s.%d", name, id);
			if (!Buffer::Exists(buff))
				key->PublicSave(buff);
		}

		return ERROR_NONE;
	}

	template<typename T>
	static T* LoadPublicKey(T* key, const char* name, unsigned int id = 0)
	{
		char buff[8192];
		if (strlen(name) > 8000)
			return NULL/*KEYERR_FAILED_TO_LOAD_KEY*/;
		sprintf(buff, "public\\%s.%d", name, id);
		Buffer b;
		b.Load(buff);
		if (key->PublicImport(&b) == ERROR_NONE)
			return key;

		delete key;
		return NULL;
	}
};

class SenderUser : public User
{
public:

	SenderUser(const char* name, LibOQSSignQKey *identity) : User(name)
	{
		this->identity_private = identity;
		authentication_public = NULL;
		onetime_public = NULL;
		prekey_public = NULL;
	}
	~SenderUser()
	{
		if (authentication_public)
			delete authentication_public;
		if (onetime_public)
			delete onetime_public;
		if (prekey_public)
			delete prekey_public;
	}

	// local identity for signing data
	LibOQSSignQKey* identity_private;

	// remote encaps key
	LibOQSEncapsQKey* authentication_public;

	// remote onetime key
	LibOQSEncapsQKey* onetime_public;

	// remote prekey key
	Key* prekey_public;

	int X3DHCalculateShared(Buffer* sharedPrivateSecret, Buffer* sharedPublicEncapsText);

	Buffer* SendText(const char* text, const char *topic = NULL)
	{
		Buffer payload;
		payload.PutChar(MessageType::PayloadTypeText); 
		payload.PutInt64(time(NULL));
		if (topic)
			payload.PutString(topic);
		else
			payload.PutInt(0);
		payload.PutString(text);
		return Send(&payload);
	}
	Buffer* SendFileInfo(const char* name, int size, char guid[16], const char *password, int passwordlen, const char *iv, int ivlen, const char* topic = NULL)
	{
		Buffer payload;
		payload.PutChar(MessageType::PayloadTypeFile);
		payload.PutInt64(time(NULL));
		if (topic)
			payload.PutString(topic);
		else
			payload.PutInt(0);
		payload.PutString(name);
		payload.Append(guid, 16);
		payload.PutString(password, passwordlen);
		payload.PutString(iv, ivlen);
		payload.PutInt(size);
		return Send(&payload);
	}
	Buffer* SendMedia(const char* name, int size, char guid[16], const char* password, int passwordlen, const char* iv, int ivlen, const char* topic = NULL)
	{
		Buffer payload;
		payload.PutChar(MessageType::PayloadTypeMedia);
		payload.PutInt64(time(NULL));
		if (topic)
			payload.PutString(topic);
		else
			payload.PutInt(0);
		payload.PutString(name);
		payload.Append(guid, 16);
		payload.PutString(password, passwordlen);
		payload.PutString(iv, ivlen);
		payload.PutInt(size);
		return Send(&payload);
	}
	Buffer* SendThumbsUp(const char* topic = NULL)
	{
		Buffer payload;
		payload.PutChar(MessageType::PayloadTypeThumbsUp);
		payload.PutInt64(time(NULL));
		if (topic)
			payload.PutString(topic);
		else
			payload.PutInt(0);
		return Send(&payload);
	}

	Buffer* Send(Buffer* payload);
};

class ReceiverUser : public User
{
public:
	// local encaps key
	LibOQSSignQKey* identity_public;

	// local encaps key
	LibOQSEncapsQKey* authentication_private;

	ReceiverUser(const char* name, LibOQSEncapsQKey *authentication/*, bool (*OnPrekeyRequire)(int id, Key_ED25519** prekey) = NULL, bool (*OnOnetimeRequire)(int id, LibOQSEncapsQKey** onetime) = NULL*/) : User(name)
	{
		this->authentication_private = authentication;
		identity_public = NULL;
		//this->OnPrekeyRequire = ImpOnPrekeyRequire;
		//if (OnPrekeyRequire)
		//	this->OnPrekeyRequire = OnPrekeyRequire;
		//this->OnOnetimeRequire = ImpOnOnetimeRequire;
		//if (OnOnetimeRequire)
		//	this->OnOnetimeRequire = OnOnetimeRequire;
	}
	~ReceiverUser()
	{
		if (identity_public)
			delete identity_public;
	}

	int X3DHCalculateShared(Buffer* sharedPrivateSecret, Buffer* sharedPublicEncapsText);
	int Receive(Buffer* transferData, Buffer *outdata);

protected:
	virtual bool OnPrekeyRequire(const char *id, int idlen, Key_ED25519** prekey) { return false; }
	virtual bool OnOnetimeRequire(const char *id, int idlen, LibOQSEncapsQKey** onetime) { return false; }

//	static bool ImpOnPrekeyRequire(int id, Key_ED25519** prekey) { return false; }
//	static bool ImpOnOnetimeRequire(int id, LibOQSEncapsQKey** onetime) { return false; }


};

#endif

