#include "Platform.h"
#include <string.h>
#include "Hash.h"
#include "Base64.h"
#include "Key.h"

Buffer* PublicKey::PublicHash(void)
{
	if (!PublicHashBuffer)
	{
		Buffer* exp = PublicExport();
		if (exp && exp->Len())
		{
			Hash_SHA256 hash;
			PublicHashBuffer = new Buffer();
			PublicHashBuffer->Append(hash.Final(exp->Ptr(), exp->Len()), hash.HashLen);
		}
	}
	return PublicHashBuffer;

}

Buffer* PublicKey::PublicHashBase64(void)
{
	if (!PublicHashBase64Buffer)
	{
		Buffer* exp = PublicHash();
		if (exp && exp->Len())
		{
			Base64 base64;
			PublicHashBase64Buffer = new Buffer();
			base64.Encode(exp, PublicHashBase64Buffer);
		}
	}

	return PublicHashBase64Buffer;
}
