#ifndef RAND_H
#define RAND_H

#include "Platform.h"
#include <openssl/rand.h>
#include "Errors.h"
#include "Buffer.h"
#include "Hash.h"

class Rand
{

public:
	static void Set(const char* sentence, size_t length)
	{
		static RAND_METHOD rand;

		sha.Update(sentence, length);

		rand.bytes = Bytes;
		rand.pseudorand = PseudoBytes;
		RAND_set_rand_method(&rand);
	}
	
	static void Set(const char *sentence)
	{
		Set(sentence, strlen(sentence));
	}

	static void Set(void)
	{
		srand((unsigned int)time(NULL));
		char b[64];
		for (int i = 0; i < 64; i++)
			b[i] = rand();
		sha.Update(b, 64);
	}

	static int Bytes(unsigned char* buf, int num)
	{
		static Buffer buffer;

		unsigned int n = (unsigned int)num;
		while (buffer.Len() < n)
		{
			buffer.Append(sha.Final(), SHA512_DIGEST_LENGTH);
			sha.Update(buffer.Ptr(), buffer.Len());
		}
		for (int i = 0; i < num; i++)
			buf[i] = buffer.GetChar();
		return 1;
	}

	static int PseudoBytes(unsigned char* buf, int num)
	{
		return Bytes(buf, num);
	}

	static Hash_SHA512 sha;
};


#endif
