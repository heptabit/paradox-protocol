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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h> // portable: uint64_t   MSVC: __int64 

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

int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif

uint64_t getTime(void)
{
    struct timeval tv = { 0 };
    gettimeofday(&tv, NULL);

    return (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
}


double measure_MakeSignature(LibOQSSignQKey* key, int milliSeconds, const char *data, size_t datalen, char *sig, size_t *siglen)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    size_t slen = *siglen;
    while ((end = getTime()) - start < milliSeconds)
    {
        slen = *siglen;
        if (key->Sign(data, datalen, sig, &slen) != ERROR_NONE)
            exit(0);
        counter++;
    }
    *siglen = slen;
    double t = (double)(end - start);
    return (counter * 1000)/t;
}

double measure_VerifySignature(LibOQSSignQKey* key, int milliSeconds, const char* data, size_t datalen, char* sig, size_t siglen)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        if (key->Verify(data, datalen, sig, siglen) != ERROR_NONE)
            exit(0);
        counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

double measure_Encapsulation(LibOQSEncapsQKey* key, int milliSeconds)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        if (key->Encapsulate() != ERROR_NONE)
            exit(0);
            counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

double measure_Decapsulation(LibOQSEncapsQKey* key, int milliSeconds, const char* data)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        if (key->Decapsulate((char *)data) != ERROR_NONE)
            exit(0);
        counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

double measure_Encrypt(SymmetricEncrypt* alg, int milliSeconds, const char* indata, char *outdata)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        if (alg->Encrypt(indata, 64, outdata, 64) != 64)
            exit(0);
        counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

double measure_Decrypt(SymmetricDecrypt* alg, int milliSeconds, const char* indata, char* outdata)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        if (alg->Decrypt(indata, 64, outdata, 64) != 64)
            exit(0);
        counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

double measure_Paradox(SenderUser *sender, ReceiverUserWithKey *receiver, int milliSeconds)
{
    uint64_t start = getTime(), end;

    unsigned int counter = 0;
    while ((end = getTime()) - start < milliSeconds)
    {
        Buffer* transport = sender->SendText("this is a text");
        if (!transport)
            exit(0);
        receiver->Receive(transport, NULL);
        delete transport;
        counter++;
    }
    double t = (double)(end - start);
    return (counter * 1000) / t;
}

int main(void)
{
    // declarations
    const int milliSeconds = 5000;
    char signature_buff[30000], data_buff[2048];

    // random buffer
    size_t datalen = sizeof(data_buff);
    size_t siglen = sizeof(signature_buff);
    for (int i = 0; i < datalen; i++)
        data_buff[i] = i;

    // measure sign and verify
    LibOQSSignQKey* sign_key = new QKey_Dilithium3(); User::LoadOrGenerateKey(sign_key, "");
    printf("Measure Dilithium3 make signature for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_MakeSignature(sign_key, milliSeconds, data_buff, datalen, signature_buff, &siglen));
    printf("Measure Dilithium3 verify signature for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_VerifySignature(sign_key, milliSeconds, data_buff, datalen, signature_buff, siglen));
    delete sign_key;


    // measure encaps and decaps
    LibOQSEncapsQKey* encaps_key = new QKey_Kyber1024(); User::LoadOrGenerateKey(encaps_key, "");
    LibOQSEncapsQKey* decaps_key = new QKey_Kyber1024(); User::LoadOrGenerateKey(decaps_key, "");
    encaps_key->PublicImport(decaps_key->PublicExport());
    decaps_key->PublicImport(encaps_key->PublicExport());
    printf("Measure Kyber1024 encapsulation for %d seconds: ", milliSeconds/1000);
    printf("%5.2f iterations per second\n", measure_Encapsulation(encaps_key, milliSeconds));
    memcpy(data_buff, encaps_key->CipherData, encaps_key->CipherSize);
    printf("Measure Kyber1024 decapsulation for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_Decapsulation(decaps_key, milliSeconds, data_buff));
    delete decaps_key;
    delete encaps_key;


    // measure AES256GCM
    Aes256GcmEnc *aesenc = new Aes256GcmEnc("1234567890123456789012345678901234567890123456789012345678901234567890", "1234567890123456789012345678901234567890123456789012345678901234567890");
    Aes256GcmDec* aesdec = new Aes256GcmDec("1234567890123456789012345678901234567890123456789012345678901234567890", "1234567890123456789012345678901234567890123456789012345678901234567890");
    printf("Measure Aes 256 GCM encrypt for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_Encrypt(aesenc, milliSeconds, data_buff, signature_buff));
    printf("Measure Aes 256 GCM decrypt for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_Decrypt(aesdec, milliSeconds, data_buff, signature_buff));
    delete aesdec;
    delete aesenc;

    // measure protocol speed
    QKey_Dilithium3 alice_identity; User::LoadOrGenerateKey(&alice_identity, "alice_identity");
    QKey_Kyber1024 bob_authentication; User::LoadOrGenerateKey(&bob_authentication, "bob_authentication");
    QKey_Kyber1024 bob_onetime; User::LoadOrGenerateKey(&bob_onetime, "bob_onetime");
    Key_ECDH25519 bob_prekey; User::LoadOrGenerateKey(&bob_prekey, "bob_prekey");
    SenderUser alice("alice", &alice_identity);
    alice.authentication_public = alice.LoadPublicKey<QKey_Kyber1024>(new QKey_Kyber1024(), "bob_authentication");
    alice.onetime_public = alice.LoadPublicKey<QKey_Kyber1024>(new QKey_Kyber1024(), "bob_onetime");
    alice.prekey_public = alice.LoadPublicKey<Key_ECDH25519>(new Key_ECDH25519(), "bob_prekey");
    ReceiverUserWithKey bob("bob", &bob_authentication, &bob_prekey, &bob_onetime);
    bob.identity_public = bob.LoadPublicKey<QKey_Dilithium3>(new QKey_Dilithium3, "alice_identity");

    printf("Measure Paradox transport protocol for %d seconds: ", milliSeconds / 1000);
    printf("%5.2f iterations per second\n", measure_Paradox(&alice, &bob, milliSeconds));

    return 0;
}
