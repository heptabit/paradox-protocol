#include <assert.h>
#include "Key.h"
#include "QKey.h"
#include "Hash.h"
#include "Rand.h"
#include "Symmetric.h"
#include "User.h"

#include <sys/stat.h>


// Windows build
#if defined (_WIN32)
#if defined (PARADOXAPILIBRARY_DLL_EXPORTS)
#define PARADOXAPILIBRARY_CPP_CLASS __declspec(dllexport)
#define PARADOXAPILIBRARY_CPP_FUNCTION __declspec(dllexport)
#define PARADOXAPILIBRARY_C_FUNCTION extern "C" __declspec(dllexport)
#else
#define PARADOXAPILIBRARY_CPP_CLASS __declspec(dllimport)
#define PARADOXAPILIBRARY_CPP_FUNCTION __declspec(dllimport)
#define PARADOXAPILIBRARY_C_FUNCTION extern "C" __declspec(dllimport)
#endif // PARADOXAPILIBRARY_DLL_EXPORTS
#endif // _WIN32

// Apple build
#if defined(__APPLE__)
#define PARADOXAPILIBRARY_CPP_CLASS __attribute__ ((visibility ("default")))
#define PARADOXAPILIBRARY_CPP_FUNCTION __attribute__ ((visibility ("default")))
#define PARADOXAPILIBRARY_C_FUNCTION extern "C" __attribute__ ((visibility ("default")))
#endif // __APPLE__


// Sample C Exports
typedef int (__stdcall* FetchKeyCallback)(const char *keyID, int idlen, char* buffer, int bufflen);

PARADOXAPILIBRARY_C_FUNCTION
void DoWork(FetchKeyCallback fetchKeyCallback)
{
	char buff[32768] = {0};
	fetchKeyCallback("test key", 8, buff, 32768);
}

Key* CreateKeyByType(const char* type)
{
	Key* key = NULL;

	if (type)
	{
		if (!strcmp(type, "KYBER_1024"))
			key = new QKey_Kyber1024();

		if (!strcmp(type, "X25519"))
			key = new Key_ECDH25519();
	}

	return key;
}

LibOQSSignQKey* CreateOQSSignKeyByType(const char* type)
{
	LibOQSSignQKey* key = NULL;
	if (type)
	{
		if (!strcmp(type, "DILITHIUM3"))
			key = new QKey_Dilithium3();
	}

	return key;
}


PARADOXAPILIBRARY_C_FUNCTION
int GenerateKey(const char* type, char* buffer, int bufferlen)
{
	Key* key = NULL;
	if (type)
	{
		key = CreateKeyByType(type);
		if (!key)
			key = CreateOQSSignKeyByType(type);
		if (key)
		{
			key->Generate();
			Buffer* e = key->Export();
			if (e->Len() <= bufferlen)
				memcpy(buffer, e->Ptr(), e->Len());
			return (int)e->Len();
		}
	}

	return 0;
}

PARADOXAPILIBRARY_C_FUNCTION
void *UseKey(const char* data)
{
	Key* key = NULL;
	const char* type = PublicKey::Detect(data);
	if (type)
	{
		key = CreateKeyByType(type);
		if (key)
		{
			Buffer b;
			b.Append(data);
			if (key->Import(&b) == ERROR_NONE)
				return key;

			delete key;
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
void* UseOQSSignKey(const char* data)
{
	LibOQSSignQKey* key = NULL;
	const char* type = PublicKey::Detect(data);
	if (type)
	{
		key = CreateOQSSignKeyByType(type);
		if (key)
		{
			Buffer b;
			b.Append(data);
			if (key->Import(&b) == ERROR_NONE)
				return key;

			delete key;
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int Sign(void* key, char* buffer, int bufferlen, char *signature, int signaturelen)
{
	LibOQSSignQKey* k = (LibOQSSignQKey*)key;
	if (k)
	{
		size_t siglen = signaturelen;
		if (k->Sign(buffer, bufferlen, signature, &siglen) == ERROR_NONE)
			return (int)siglen;
	}
	return 0;
}

PARADOXAPILIBRARY_C_FUNCTION
bool Verify(const char *identpub, char* buffer, int bufferlen, char* signature, int signaturelen)
{
	bool result = false;
	LibOQSSignQKey *key = CreateOQSSignKeyByType(PublicKey::Detect(identpub));
	if (key)
	{
		Buffer identpubbuff;
		identpubbuff.Append(identpub);
		if (key->PublicImport(&identpubbuff) == ERROR_NONE)
		{
			if (key->Verify(buffer, bufferlen, signature, signaturelen) == ERROR_NONE)
				result = true;
		}
		delete key;
	}
	return result;
}


PARADOXAPILIBRARY_C_FUNCTION
int GetPublicKey(void *key, char* buffer, int bufferlen)
{
	Key* _key = (Key*)key;
	Buffer* e = _key->PublicExport();
	if (e->Len() <= bufferlen)
		memcpy(buffer, e->Ptr(), e->Len());
	return (int)e->Len();
}

PARADOXAPILIBRARY_C_FUNCTION
int GetPublicKeyHash(void* key, char* buffer, int bufferlen)
{
	Key* _key = (Key*)key;
	Buffer* e = _key->PublicHash();
	if (e->Len() <= bufferlen)
		memcpy(buffer, e->Ptr(), e->Len());
	return (int)e->Len();
}

PARADOXAPILIBRARY_C_FUNCTION
int GetPublicOQSSignKey(void* key, char* buffer, int bufferlen)
{
	LibOQSSignQKey* _key = (LibOQSSignQKey*)key;
	Buffer* e = _key->PublicExport();
	if (e->Len() <= bufferlen)
		memcpy(buffer, e->Ptr(), e->Len());
	return (int)e->Len();
}

PARADOXAPILIBRARY_C_FUNCTION
int GetPublicOQSSignKeyHash(void* key, char* buffer, int bufferlen)
{
	LibOQSSignQKey* _key = (LibOQSSignQKey*)key;
	Buffer* e = _key->PublicHash();
	if (e->Len() <= bufferlen)
		memcpy(buffer, e->Ptr(), e->Len());
	return (int)e->Len();
}

PARADOXAPILIBRARY_C_FUNCTION
void FreeKey(void *key)
{
	Key* _key = (Key *)key;
	delete _key;
}

PARADOXAPILIBRARY_C_FUNCTION
void *PrepareSendSession(void *identpriv, const char *authpub, const char *onetimepub, const char *prekeypub)
{
	SenderUser *sender = new SenderUser("alice", (LibOQSSignQKey *)(identpriv));
	if (sender)
	{
		sender->authentication_public = (LibOQSEncapsQKey *)CreateKeyByType(PublicKey::Detect(authpub));
		if (sender->authentication_public)
		{
			Buffer authpubbuff;
			authpubbuff.Append(authpub);
			if (sender->authentication_public->PublicImport(&authpubbuff) == ERROR_NONE)
			{
				sender->onetime_public = (LibOQSEncapsQKey*)CreateKeyByType(PublicKey::Detect(onetimepub));
				if (sender->onetime_public)
				{
					Buffer onetimepubbuff;
					onetimepubbuff.Append(onetimepub);
					if (sender->onetime_public->PublicImport(&onetimepubbuff) == ERROR_NONE)
					{
						sender->prekey_public = CreateKeyByType(PublicKey::Detect(prekeypub));
						if (sender->prekey_public)
						{
							Buffer prekeypubbuf;
							prekeypubbuf.Append(prekeypub);
							if (sender->prekey_public->PublicImport(&prekeypubbuf) == ERROR_NONE)
							{
								return sender;
							}
						}
					}
				}
			}
		}

		delete sender;
	}
	return NULL;
}

class ReceiverUserExt : public ReceiverUser
{
public:
	ReceiverUserExt(const char* name, LibOQSEncapsQKey* authentication, FetchKeyCallback preKeyCallback, FetchKeyCallback onetimeCallback) : ReceiverUser(name, authentication)
	{
		_preKeyCallback = preKeyCallback;
		_onetimeCallback = onetimeCallback;
	}

	bool OnPrekeyRequire(const char* id, int idlen, Key_ED25519** prekey)
	{
		char buff[65535];
		memset(buff, 0, sizeof(buff));

		if (_preKeyCallback(id, idlen, buff, sizeof(buff)) > 0)
		{
			*prekey = new Key_ECDH25519();
			Buffer b;
			b.Append(buff);
			(*prekey)->Import(&b);
			return true;
		}
		return false;
	}
	bool virtual OnOnetimeRequire(const char* id, int idlen, LibOQSEncapsQKey** onetime)
	{ 
		char buff[65535];
		memset(buff, 0, sizeof(buff));

		if (_onetimeCallback(id, idlen, buff, sizeof(buff)) > 0)
		{
			if (onetime)
			{
				*onetime = (LibOQSEncapsQKey*)UseKey(buff);
				return true;
			}
		}
		return false;
	}

protected:
	FetchKeyCallback _preKeyCallback, _onetimeCallback;

};

PARADOXAPILIBRARY_C_FUNCTION
void* PrepareReceiveSession(void* authpriv, const char* identpub, FetchKeyCallback preKeyCallback, FetchKeyCallback onetimeCallback)
{
	ReceiverUser* receiver = new ReceiverUserExt("bob", (LibOQSEncapsQKey*)(authpriv), preKeyCallback, onetimeCallback);
	if (receiver)
	{
		receiver->identity_public = (LibOQSSignQKey*)CreateOQSSignKeyByType(PublicKey::Detect(identpub));
		if (receiver->identity_public)
		{
			Buffer identpubbuff;
			identpubbuff.Append(identpub);
			if (receiver->identity_public->PublicImport(&identpubbuff) == ERROR_NONE)
			{
				return receiver;
			}
		}

		delete receiver;
	}
	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int SendText(void *user, const char* text, const char *topic, char* buffer, int bufferlen)
{
	if (user)
	{
		SenderUser* s = (SenderUser*)user;
		Buffer *b = s->SendText(text, topic);
		if (b->Len() <= bufferlen)
		{
			memcpy(buffer, b->Ptr(), b->Len());
			return (int)b->Len();
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int SendFileInfo(void* user, const char* name, int size, char guid[16], const char *b64password, const char *b64iv, const char* topic, char* buffer, int bufferlen)
{
	if (user)
	{
		SenderUser* s = (SenderUser*)user;
		Base64 base64;
		Buffer pin, pout, ivin, ivout;
		pin.Append(b64password);
		base64.Decode(&pin, &pout);
		ivin.Append(b64iv);
		base64.Decode(&ivin, &ivout);

		Buffer* b = s->SendFileInfo(name, size, guid, pout.Ptr(), (int)pout.Len(), ivout.Ptr(), (int)ivout.Len(), topic);
		if (b->Len() <= bufferlen)
		{
			memcpy(buffer, b->Ptr(), b->Len());
			return (int)b->Len();
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int SendMedia(void* user, const char* name, int size, char guid[16], const char* b64password, const char* b64iv, const char* topic, char* buffer, int bufferlen)
{
	if (user)
	{
		SenderUser* s = (SenderUser*)user;
		Base64 base64;
		Buffer pin, pout, ivin, ivout;
		pin.Append(b64password);
		base64.Decode(&pin, &pout);
		ivin.Append(b64iv);
		base64.Decode(&ivin, &ivout);

		Buffer* b = s->SendMedia(name, size, guid, pout.Ptr(), (int)pout.Len(), ivout.Ptr(), (int)ivout.Len(), topic);
		if (b->Len() <= bufferlen)
		{
			memcpy(buffer, b->Ptr(), b->Len());
			return (int)b->Len();
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int SendThumbsUp(void* user, const char* topic, char* buffer, int bufferlen)
{
	if (user)
	{
		SenderUser* s = (SenderUser*)user;
		Buffer* b = s->SendThumbsUp(topic);
		if (b->Len() <= bufferlen)
		{
			memcpy(buffer, b->Ptr(), b->Len());
			return (int)b->Len();
		}
	}

	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
int Receive(void* user, char* inbuffer, int inbufferlen, char *outbuffer, int outbufferlen)
{
	if (user)
	{
		Buffer indata, outdata;
		indata.Append(inbuffer, inbufferlen);
		ReceiverUser* r = (ReceiverUser*)user;
		if (r->Receive(&indata, &outdata) == ERROR_NONE)
		{
			if (outdata.Len() <= outbufferlen)
			{
				memcpy(outbuffer, outdata.Ptr(), outdata.Len());
				return (int)outdata.Len();
			}
		}
	}
	return NULL;
}

PARADOXAPILIBRARY_C_FUNCTION
void FreeSendSession(void* session)
{
	if (session)
	{
		SenderUser* s = (SenderUser*)session;
		delete s;
	}


}

PARADOXAPILIBRARY_C_FUNCTION
void FreeReceiveSession(void* session)
{
	if (session)
	{
		ReceiverUser* r = (ReceiverUser*)session;
		delete r;
	}


}

PARADOXAPILIBRARY_C_FUNCTION
int GetSecret(void* user, char* buffer, int bufferlen)
{
	if (user)
	{
		User* u = (User*)user;
		if (u->shared_secret && u->init_vector)
		{
			Buffer b;
			b.Append(u->shared_secret, SHARED_SECRET_SIZE);
			b.Append(u->init_vector, INIT_VECTOR_SIZE);
			b.PutInt(u->shared_index);

			if (b.Len() <= bufferlen)
			{
				memcpy(buffer, b.Ptr(), b.Len());
				return (int)b.Len();
			}
		}
	}
	return 0;
}

PARADOXAPILIBRARY_C_FUNCTION
bool SetSecret(void* user, char* buffer, int bufferlen)
{
	if (user)
	{
		User* u = (User*)user;
		if (bufferlen >= SHARED_SECRET_SIZE + INIT_VECTOR_SIZE + sizeof(unsigned int))
		{
			Buffer b;
			b.Append(buffer, bufferlen);
			
			if (!u->shared_secret)
				u->shared_secret = (char*)malloc(SHARED_SECRET_SIZE);
			if (u->shared_secret)
				memcpy(u->shared_secret, b.Ptr(), SHARED_SECRET_SIZE);
			b.Consume(SHARED_SECRET_SIZE);

			if (!u->init_vector)
				u->init_vector = (char*)malloc(INIT_VECTOR_SIZE);
			if (u->init_vector)
				memcpy(u->init_vector, b.Ptr(), INIT_VECTOR_SIZE);
			b.Consume(INIT_VECTOR_SIZE);

			u->shared_index = b.GetInt();
			return true;
		}
	}
	return false;
}

/*
int main(void)
{

	CreateDirectoryA("public", NULL);
	CreateDirectoryA("private", NULL);

	// alice keys - static since it's reused
	QKey_Dilithium3 alice_identity; User::LoadOrGenerateKey(&alice_identity, "alice_identity");

	// bob keys - static since it's reused
	QKey_Kyber1024 bob_authentication; User::LoadOrGenerateKey(&bob_authentication, "bob_authentication");
	QKey_Kyber1024 bob_onetime; User::LoadOrGenerateKey(&bob_onetime, "bob_onetime");
	Key_ECDH25519 bob_prekey; User::LoadOrGenerateKey(&bob_prekey, "bob_prekey");

	// alice - dynamic keys
	SenderUser alice("alice", &alice_identity);
	alice.authentication_public = alice.LoadPublicKey<QKey_Kyber1024>(new QKey_Kyber1024(), "bob_authentication");
	alice.onetime_public = alice.LoadPublicKey<QKey_Kyber1024>(new QKey_Kyber1024(), "bob_onetime");
	alice.prekey_public = alice.LoadPublicKey<Key_ECDH25519>(new Key_ECDH25519(), "bob_prekey");

	
	// bob
	ReceiverUser bob("bob", &bob_authentication);
	//bob.onetime_private.push_back(new ReceiverUserEncapsKey(&bob_onetime, 0));
	//bob.prekey_private.push_back(new ReceiverUserDHKey(&bob_prekey, 0));
	bob.identity_public = bob.LoadPublicKey<QKey_Dilithium3>(new QKey_Dilithium3, "alice_identity");

	Buffer* transport = alice.SendText("this is a text");
	bob.Receive(transport, NULL);

	transport = alice.SendText("this is a another text");
	bob.Receive(transport, NULL);


//	assert(aliceSharedSecret.Len() == bobSharedSecret.Len() && !memcmp(aliceSharedSecret.Ptr(), bobSharedSecret.Ptr(), aliceSharedSecret.Len()));
	return 0;
}
*/
