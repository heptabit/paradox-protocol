#include <assert.h>
#include "Platform.h"
#include <string.h>
#include "Key.h"
#include "QKey.h"
#include "Hash.h"
#include "Rand.h"
#include "Symmetric.h"
#include "User.h"

#include <sys/stat.h>

int myRandBytes(unsigned char* buf, int num)
{
	static unsigned char t = 0;

	for (int i = 0; i < num; i++)
		buf[i] = t++;
	return 1;
}

int myPseudoRandBytes(unsigned char* buf, int num)
{
	static unsigned char t = 0;

	for (int i = 0; i < num; i++)
		buf[i] = t++;
	return 1;
}

char* fullname(char* buffer, const char* dir, const char* name)
{
#ifdef _WIN32
	CreateDirectoryA(dir, NULL);
#else
	mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
	sprintf(buffer, "%s\\%s", dir, name);
	return buffer;
}

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#if 0
int LoadPublicKey(Key* key, const char* folder, const char* name)
{
	char buff[8192];
	sprintf(buff, "%s\\%s.pub", folder, name);
	return key->PublicLoad(buff);
}

void LoadOrGenerateKey(Key* key, const char* folder, const char* name)
{
	char buff[8192];
	sprintf(buff, "%s\\%s.priv", folder, name);
	if (key->Load(buff) != ERROR_NONE)
	{
		key->Generate();
		key->Save(buff);
	}

	sprintf(buff, "%s\\%s.pub", folder, name);
	if (!Buffer::Exists(buff))
		key->PublicSave(buff);
}

void SignAndSaveData(SignKey* signkey, Buffer* data, const char* folder, const char* name)
{
	Buffer sig;
	char buff[4096], signbuff[4096];
	sprintf(buff, "%s\\%s.sig", folder, name);
	if (!sig.Load(buff))
	{
		size_t signlen = sizeof(signbuff);

		Hash_SHA256 sha256;
		signkey->Sign(sha256.Final(data->Ptr(), data->Len()), sha256.HashLen, signbuff, &signlen);

		sig.Append(signbuff, signlen);
		sig.Save(buff);
	}
}

int LoadAndVerifyData(SignKey* signkey, Buffer* data, const char* folder, const char* name)
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

#endif

#if 0
int main1(int argc, char **argv)
{
#ifdef _WIN32
	CreateDirectoryA("bob", NULL);
#else
	mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif

/*
	Rand::Set("ovo je neki tekst");
*/

	{
		Key_RSA key;
		LoadOrGenerateKey(&key, "rsa");
	}



	{
		Key_ED25519 key;
		LoadOrGenerateKey(&key, "ed25519");
	}


	{
		Key_ECDSA521 key;
		LoadOrGenerateKey(&key, "ecdsa521");
	}

	{
		Key_ECDH521 key1;
		LoadOrGenerateKey(&key1, "ecdh1");

		Key_ECDH521 key2;
		LoadOrGenerateKey(&key2, "ecdh2");

		Buffer secret1;
		if (!key1.Compute(key2.PublicExport(), &secret1))
		{
/*
			Buffer secret2;
			if (!key2.Compute(key1.PublicExport(), &secret2))
			{
				if (secret1.Len() == secret2.Len())
				{
					if (!memcmp(secret1.Ptr(), secret2.Ptr(), secret1.Len()))
						MessageBeep(-1);
	
				}
			}
*/
			char buff1[8192], buff2[8192];

			Aes128GcmEnc aesenc(secret1.Ptr(), secret1.Ptr());
			aesenc.Encrypt("1234567890123456", 16, buff1, sizeof(buff1));

			Aes128GcmDec aesdec(secret1.Ptr(), secret1.Ptr());
			aesdec.Decrypt(buff1, 16, buff2, sizeof(buff2));

			aesenc.Encrypt("9876543210987654", 16, buff1, sizeof(buff1));

			aesdec.Decrypt(buff1, 16, buff2, sizeof(buff2));
		}
	}

/*
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();

	unsigned int signum = 0;
	int r = 1;

	size_t sltmp = (size_t)EVP_PKEY_size(key.pkey);
	EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(key.pkey, NULL);
	if (EVP_PKEY_sign_init(pkctx) <= 0)
	{
		r = 0; 
	}
	if (EVP_PKEY_sign(pkctx, (unsigned char*)buff, &sltmp, (unsigned char*)"1234567890", 10) <= 0)
	{
		r = 0;
	}
	EVP_PKEY_CTX_free(pkctx);
	r = 0;


	sltmp = (size_t)EVP_PKEY_size(key.pkey);
	pkctx = EVP_PKEY_CTX_new(key.pkey, NULL);
	if (EVP_PKEY_verify_init(pkctx) <= 0)
	{
		r = 0;
	}
	int rr = EVP_PKEY_verify(pkctx, (unsigned char*)buff, sltmp, (unsigned char*)"1234567890", 10);
	EVP_PKEY_CTX_free(pkctx);
	r = 0;
*/

/*
	Key_RSA key;
//	key.Generate();
//	key.Save(fullname(buff, dir, "rsa"));
	key.Load(fullname(buff, dir, "rsa"));

	size_t buflen = sizeof(buff);
	int ret = key.Sign("1234567890", 10, buff, &buflen);


	ret = 0;


*/


	return 0;
}
#endif

#if 0
int main(int argc, char** argv)
{
	Key_ED25519 identity;
	LoadOrGenerateKey(&identity, "bob", "identity");
	Key_ED25519 peer_identity;
	LoadPublicKey(&peer_identity, "bob", "identity");

	Buffer data;
	data.Append("data");

	SignAndSaveData(&identity, &data, "bob", "prekey");
	int ret = LoadAndVerifyData(&peer_identity, &data, argv[1], "prekey");
	ret++;



	return 0;
}
#endif

#if 0
int main(int argc, char** argv)
{
	Key_ED25519 key;
	key.Generate();

	char sig[64];

	size_t siglen = 64;

	key.Sign("1234512345", 10, sig, &siglen);
	if (key.Verify("1234512345", 10, sig, siglen) != ERROR_NONE)
	{
		printf("Failed");
	}

	return 0;
}
#endif

#if 0
int main(int argc, char** argv)
{
	Key_ECDH25519 bob;
	bob.Generate();

	Key_ECDH25519 alice;
	alice.Generate();

	Buffer secret1, secret2;
	bob.Compute(alice.PublicExport(), &secret1);
	alice.Compute(bob.PublicExport(), &secret2);

}
#endif

#if 0
int main(int argc, char** argv)
{
	Key_ED25519 identity, prekey, peer_identity, peer_prekey;

	LoadOrGenerateKey(&identity, "test", "identity");
	LoadOrGenerateKey(&prekey, "test", "prekey");

	//LoadOrGenerateKey(&peer_identity, "test", "peer_identity");
	//LoadOrGenerateKey(&peer_prekey, "test", "peer_prekey");

	Buffer* b1 = prekey.PublicExport();
	SignAndSaveData(&identity, prekey.PublicExport(), "test", "prekey");

	//Buffer* b2 = prekey.PublicExport();
	//SignAndSaveData(&identity, prekey.PublicExport(), "test", "prekey");
	LoadPublicKey(&peer_prekey, "test", "prekey");
	Buffer* b2 = peer_prekey.PublicExport();

	b1->Save("test\\b1");
	b2->Save("test\\b2");

}
#endif
/*
void LoadGeneratePrivateKeys(X3DH::Keys *keys, const char* name)
{
	printf("Generating %s private identity key", name);
	LoadOrGenerateKey(&keys->identity, name, "identity");
	printf(". Success.\r\n");

	printf("Generating %s private ephemereal key", name);
	LoadOrGenerateKey(&keys->ephemereal, name, "ephemereal");
	printf(". Success.\r\n");

	printf("Generating %s private prekey key", name);
	LoadOrGenerateKey(&keys->prekey, name, "prekey");
	printf(". Success.\r\n");
	SignAndSaveData(&keys->identity, keys->prekey.PublicExport(), name, "prekey");

	printf("Generating %s private onetime key", name);
	LoadOrGenerateKey(&keys->onetime, name, "onetime");
	printf(". Success.\r\n");
}

bool LoadPublicKeys(X3DH::Keys * keys, const char* name)
{
	printf("Loading %s public identity key", name);
	if (LoadPublicKey(&keys->identity, name, "identity") == ERROR_NONE)
		printf(". Success.\r\n");

	printf("Loading %s public ephemereal key", name);
	if (LoadPublicKey(&keys->ephemereal, name, "ephemereal") == ERROR_NONE)
		printf(". Success.\r\n");

	printf("Loading %s public prekey key", name);
	if (LoadPublicKey(&keys->prekey, name, "prekey") == ERROR_NONE)
		printf(". Success.\r\n");

	printf("Loading %s public onetime key", name);
	if (LoadPublicKey(&keys->onetime, name, "onetime") == ERROR_NONE)
		printf(". Success.\r\n");

	printf("Checking %s public prekey key signature", name);
	if (LoadAndVerifyData(&keys->identity, keys->prekey.PublicExport(), name, "prekey") == ERROR_NONE)
		printf(". Success.\r\n");
	else
	{
		printf(". FAIL!.\r\n");
		return false;
	}

	return true;
}
*/
#if 1

class ReceiverUserWithKey : public ReceiverUser
{
public:
	ReceiverUserWithKey(const char* name, LibOQSEncapsQKey* authentication, Key_ED25519* prekey, LibOQSEncapsQKey* onetime) : ReceiverUser(name, authentication)
	{
		_prekey = prekey;
		_onetime = onetime;
	}


	bool OnPrekeyRequire(const char* id, int idlen, Key_ED25519** prekey) {
		*prekey = _prekey;
		return true;
	}

	bool OnOnetimeRequire(const char* id, int idlen, LibOQSEncapsQKey** onetime) {
		*onetime = _onetime;
		return true;
	}
private:
	Key_ED25519* _prekey;
	LibOQSEncapsQKey* _onetime;
};

int main(void)
{
#ifdef _WIN32
	CreateDirectoryA("public", NULL);
	CreateDirectoryA("private", NULL);
#else
	mkdir("public", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	mkdir("private", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif

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
	ReceiverUserWithKey bob("bob", &bob_authentication, &bob_prekey, &bob_onetime);
	//bob.onetime_private.push_back(new ReceiverUserEncapsKey(&bob_onetime, 0));
	//bob.prekey_private.push_back(new ReceiverUserDHKey(&bob_prekey, 0));
	bob.identity_public = bob.LoadPublicKey<QKey_Dilithium3>(new QKey_Dilithium3, "alice_identity");

	Buffer* transport = alice.SendText("this is a text");
	bob.Receive(transport, NULL);

	transport = alice.SendText("this is a another text");
	bob.Receive(transport, NULL);

	transport = alice.SendText("this is a yet another text");
	bob.Receive(transport, NULL);

//	assert(aliceSharedSecret.Len() == bobSharedSecret.Len() && !memcmp(aliceSharedSecret.Ptr(), bobSharedSecret.Ptr(), aliceSharedSecret.Len()));


/*
	
	LocalUser bob("bob");

	//bob.identity = new QKey_Dilithium2();
	//bob.LoadOrGenerateKey(bob.identity, "bob", "identity");

	bob.authentication = new QKey_NTRU_hps2048509();
	bob.LoadOrGenerateKey(bob.authentication, "bob", "authentication");

	LibOQSEncapsQKey *onetime = new QKey_NTRU_hps2048509();
	bob.LoadOrGenerateKey(onetime, "bob", "onetime");
	bob.onetime.push_back(onetime);
	bob.onetime_id.push_back(123);

	Key_ECDH25519* prekey = new Key_ECDH25519();
	bob.LoadOrGenerateKey(prekey, "bob", "prekey");
	bob.prekey.push_back(prekey);
	bob.prekey_id.push_back(123);


	CreateDirectoryA("alice", NULL);
	LocalUser alice("alice");
	alice.LoadOrGenerateKey(alice.identity, "alice", "identity"); // needed for signature
	alice.LoadPublicKey(&alice.onetime, "bob", "onetime");
*/
	// local PC
//	Identity alive_local_private("alice"), bob_remote_private("bob");
//	bob_remote_private.LoadGeneratePrivateKeys();

//	Peer alice_local_public("bob");
//	if (alice_local_public.LoadPublicKeys())
	{
//		Buffer* transfer = alice_local_public.SendText(&bob_local_public, "ovo je neki test");
	}
/*
	// remote PC
	Identity bob_remote_private("bob");
	Peer alice_remote_public("alice");

	if (bob_local_public.LoadPublicKeys())
	{
		Buffer *transfer = alice_local_private.SendText(&bob_local_public, "ovo je neki test");
		if (transfer)
		{
			bob_remote_private.Receive(&alice_remote_public, transfer);
			delete transfer;
		}

	}

*/
	//Buffer cipherText, aliceSharedSecret;
	// local PC

/*
	if (bob_local_public.LoadPublicKeys())
	{
		if (alice_local_private.X3DHCalculateSharedAsSender(&bob_local_public, &aliceSharedSecret , &cipherText) == ERROR_NONE)
		{

			// remote PC
			Buffer bobSharedSecret = NULL;
			if (alice_remote_public.LoadPublicKeys())
				if (bob_remote_private.X3DHCalculateSharedAsReceiver(&alice_remote_public, &bobSharedSecret, &cipherText) == ERROR_NONE)
				{

					assert(aliceSharedSecret.Len() == bobSharedSecret.Len() && !memcmp(aliceSharedSecret.Ptr(), bobSharedSecret.Ptr(), aliceSharedSecret.Len()));
				}
		}
	}
*/
	return 0;
}

#endif

#if 0
int main(void)
{
	Rand::Set();
	NTRU_hps2048509 receiver;
	receiver.Generate();
	//receiver.Save("testq");
	//receiver.Load("testq");

	char cipherText[10][16384] = { 0 };
	char secret[10][16384] = { 0 };

	NTRU_hps2048509 sender; // does not generate private key
	Buffer* receiverpubkey = receiver.PublicExport();
	for (int i = 0; i < 10; i++)
	{
		Buffer* rec2 = new Buffer();
		rec2->Append(receiverpubkey->Ptr(), receiverpubkey->Len());
		if (sender.Encapsulate(rec2) == ERROR_NONE)
		{
			memcpy(cipherText[i], sender.CipherData, sender.CipherSize);
			memcpy(secret[i], sender.SecretData, sender.SecretSize);
		}
	}


	for (int i = 0; i < 10; i++)
		if (receiver.Decapsulate(cipherText[i]) != ERROR_NONE || memcmp(receiver.SecretData, secret[i], receiver.SecretSize))
			printf("NE VALJA!");
}

#endif

#if 0
int main(void)
{
	Rand::Set();

	QKey_FrodoKem640Aes alice;
	alice.Generate();

	QKey_FrodoKem640Aes bob;
	bob.Generate();

	char cipherText1[16384] = { 0 };
	char cipherText2[16384] = { 0 };
	char cipherText3[16384] = { 0 };
	char cipherText4[16384] = { 0 };
	char secret1[16384] = { 0 };
	char secret2[16384] = { 0 };
	char secret3[16384] = { 0 };
	char secret4[16384] = { 0 };

	alice.Encapsulate(bob.PublicExport());
	memcpy(secret1, alice.SecretData, alice.SecretSize);
	memcpy(cipherText1, alice.CipherData, alice.CipherSize);

	alice.Decapsulate(alice.CipherData);
	memcpy(secret2, alice.SecretData, alice.SecretSize);
	memcpy(cipherText2, alice.CipherData, alice.CipherSize);

	bob.Decapsulate(cipherText1);
	memcpy(secret3, bob.SecretData, bob.SecretSize);
	//memcpy(cipherText3, bob.CipherData, bob.CipherSize);

	bob.Encapsulate(alice.PublicExport());
	memcpy(secret4, bob.SecretData, bob.SecretSize);
	memcpy(cipherText4, bob.CipherData, bob.CipherSize);


	/*

	NTRU_hps2048509 receiver;
	receiver.Generate();
	//receiver.Save("testq");
	//receiver.Load("testq");

	char cipherText[10][16384] = { 0 };
	char secret[10][16384] = { 0 };

	NTRU_hps2048509 sender; // does not generate private key
	Buffer* receiverpubkey = receiver.PublicExport();
	for (int i = 0; i < 10; i++)
	{
		Buffer* rec2 = new Buffer();
		rec2->Append(receiverpubkey->Ptr(), receiverpubkey->Len());
		if (sender.Encapsulate(rec2) == ERROR_NONE)
		{
			memcpy(cipherText[i], sender.CipherData, sender.CipherSize);
			memcpy(secret[i], sender.SecretData, sender.SecretSize);
		}
	}


	for (int i = 0; i < 10; i++)
		if (receiver.Decapsulate(cipherText[i]) != ERROR_NONE || memcmp(receiver.SecretData, secret[i], receiver.SecretSize))
			printf("NE VALJA!");

*/
}
#endif