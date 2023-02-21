#include "Platform.h"
#include <string.h>
#include "User.h"

int SenderUser::X3DHCalculateShared(Buffer* sharedPrivateSecret, Buffer* sharedPublicEncapsText)
{
	Hash_SHA512 h;

	if (authentication_public->Encapsulate() == ERROR_NONE)
	{
		sharedPublicEncapsText->PutChar(MessageType::MessageTypeExchangeEncapsAuthentication);
		sharedPublicEncapsText->PutString(authentication_public->CipherData, authentication_public->CipherSize);
		h.Update(authentication_public->SecretData, authentication_public->SecretSize);
	}

	if (onetime_public->Encapsulate() == ERROR_NONE)
	{
		Buffer* onetime_public_id = onetime_public->PublicHash();
		if (onetime_public_id)
		{
			sharedPublicEncapsText->PutChar(MessageType::MessageTypeExchangeEncapsOneTimeWithId);
			sharedPublicEncapsText->PutString(onetime_public_id->Ptr(), onetime_public_id->Len());
				sharedPublicEncapsText->PutString(onetime_public->CipherData, onetime_public->CipherSize);
			h.Update(onetime_public->SecretData, onetime_public->SecretSize);
		}
	}

	Key_ECDH25519 ephemeral;
	ephemeral.Generate();
	Buffer* prekeyPublicKey = prekey_public->PublicExport();
	Buffer secret;
	if (ephemeral.Compute(prekeyPublicKey, &secret) == ERROR_NONE)
	{
		Buffer* prekey_id = prekey_public->PublicHash();
		if (prekey_id)
		{
			prekeyPublicKey = ephemeral.PublicExport();
			sharedPublicEncapsText->PutChar(MessageType::MessageTypeExchangeEphemeralPublicKeyWithId);
			sharedPublicEncapsText->PutString(prekey_id->Ptr(), prekey_id->Len());
			sharedPublicEncapsText->PutString(prekeyPublicKey->Ptr(), prekeyPublicKey->Len());
		}
	}

	const char* key = h.Final(secret.Ptr(), secret.Len());
	sharedPrivateSecret->Append(key, h.HashLen);
	return ERROR_NONE;
}


int ReceiverUser::X3DHCalculateShared(Buffer* sharedPrivateSecret, Buffer* sharedPublicEncapsText)
{
	Hash_SHA512 h;
	Buffer authenticationBuffer, onetimeBuffer, secret;

	while (sharedPublicEncapsText->Len())
	{
		switch (sharedPublicEncapsText->GetChar())
		{
		case MessageType::MessageTypeExchangeEncapsAuthentication:
		{
			int clen = 0;
			char* c1 = sharedPublicEncapsText->GetString(&clen);
			if (clen == authentication_private->CipherSize)
				if (authentication_private->Decapsulate(c1) == ERROR_NONE)
					authenticationBuffer.Append(authentication_private->SecretData, authentication_private->SecretSize);
		}
		break;

		case MessageType::MessageTypeExchangeEncapsOneTimeWithId:
		{
			bool found = false;
			int clen = 0, idlen = 0;
			char* id = sharedPublicEncapsText->GetString(&idlen);
			char* c1 = sharedPublicEncapsText->GetString(&clen);

			LibOQSEncapsQKey* onetime = NULL;
			if (OnOnetimeRequire(id, idlen, &onetime) && onetime)
			{
				if (clen == onetime->CipherSize)
				{
					if (onetime->Decapsulate(c1) == ERROR_NONE)
					{
						onetimeBuffer.Append(onetime->SecretData, onetime->SecretSize);
					}
					else
						return KEY_FAILED_TO_CALCULATE_X3DH;
				}
				else
					return KEY_FAILED_TO_CALCULATE_X3DH;
			}
			else
				return KEY_FAILED_TO_CALCULATE_X3DH;

		}
		break;

		case MessageType::MessageTypeExchangeEphemeralPublicKeyWithId:
		{
			bool found = false;
			int idlen = 0;
			char *id = sharedPublicEncapsText->GetString(&idlen);
			int clen = sharedPublicEncapsText->GetInt();
			Buffer senderEphemeral;
			senderEphemeral.Append(sharedPublicEncapsText->Ptr(), clen);
			sharedPublicEncapsText->Consume(clen);

			Key_ECDH25519 DH;
			Key_ED25519* prekey = NULL;
			if (OnPrekeyRequire(id, idlen, &prekey) && prekey)
			{
				DH.Import(prekey->Export());
				DH.Compute(&senderEphemeral, &secret);
			}
			else
				return KEY_FAILED_TO_CALCULATE_X3DH;

		}
		break;

		default:
			return KEY_FAILED_TO_CALCULATE_X3DH;
		}
	}
	h.Update(authenticationBuffer.Ptr(), authenticationBuffer.Len());
	h.Update(onetimeBuffer.Ptr(), onetimeBuffer.Len());
	const char* key = h.Final(secret.Ptr(), secret.Len());
	sharedPrivateSecret->Append(key, h.HashLen);

	return ERROR_NONE;
}

Buffer* SenderUser::Send(Buffer* payload)
{
	Buffer* messageData = new Buffer();

	if (!shared_secret || !init_vector)
	{
		// calculate secret, add
		Buffer bufferSecret;
		Buffer prepend;
		int ret = X3DHCalculateShared(&bufferSecret, &prepend);
		if (ret != ERROR_NONE)
			return NULL;

		if (prepend.Len())
		{
			messageData->PutChar(MessageType::MessageTypeKeyExchange);
			messageData->PutString(prepend.Ptr(), prepend.Len());
		}

		if (bufferSecret.Len() >= SHARED_SECRET_SIZE)
		{
			shared_index = 0;

			if (shared_secret)
				free(shared_secret);
			shared_secret = (char*)malloc(SHARED_SECRET_SIZE);
			if (shared_secret)
			{
				memcpy(shared_secret, bufferSecret.Ptr(), SHARED_SECRET_SIZE);
				bufferSecret.Consume(SHARED_SECRET_SIZE);
			}

			if (bufferSecret.Len() >= INIT_VECTOR_SIZE)
			{
				if (init_vector)
					free(init_vector);
				init_vector = (char*)malloc(INIT_VECTOR_SIZE);
				if (init_vector)
				{
					memcpy(init_vector, bufferSecret.Ptr(), INIT_VECTOR_SIZE);
					bufferSecret.Consume(INIT_VECTOR_SIZE);
				}
			}
		}
	}

	if (shared_secret && init_vector)
	{
		char tmp_init_vector[INIT_VECTOR_SIZE];
		memcpy(tmp_init_vector, init_vector, INIT_VECTOR_SIZE);
		ADD_32BIT(tmp_init_vector, shared_index);

		Aes256GcmEnc aes(shared_secret, tmp_init_vector);
		//Aes128EcbEnc aes("1234567890123456789012345678901234567890", "1234567890123456789012345678901234567890");
		
		// generate secret payload buffer, timestamped
		Buffer secretDataBuffer;
		secretDataBuffer.PutInt(shared_index++); 
		secretDataBuffer.PutString(payload->Ptr(), payload->Len());

		// encrypt payload
		Buffer cipherDataBuffer;
		char* cipherData;
		int cipherDataLen = ((int)(secretDataBuffer.Len() + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize;
		cipherDataBuffer.AppendSpace(&cipherData, cipherDataLen);
		aes.Encrypt(secretDataBuffer.Ptr(), cipherDataLen, cipherData, cipherDataLen);

		// add payload to message data
		messageData->PutChar(MessageType::MessageTypeEncryptedMessageWithLen);
		messageData->PutInt((unsigned int)secretDataBuffer.Len());
		messageData->PutString(cipherData, cipherDataLen);

		// add shared_secret to plaintext message secret buffer to make plaintext signautre somehow unique
		secretDataBuffer.Append(shared_secret, SHARED_SECRET_SIZE);

		// generate signature of plaintext payload and our keys
		Buffer signatureBuffer;
		char* signature;
		signatureBuffer.AppendSpace(&signature, identity_private->SignatureSize);
		size_t signatureLen = signatureBuffer.Len();

		Hash_SHA512 h;
		const char* hash = h.Final(secretDataBuffer.Ptr(), secretDataBuffer.Len());
		identity_private->Sign(hash, h.HashLen, signature, &signatureLen);

		// add signature to message data
		messageData->PutChar(MessageType::MessageTypeSignature);
		messageData->PutString(signature, signatureLen);

		// adjust shared secret for next iteration
		memcpy(shared_secret, hash, SHARED_SECRET_SIZE);

		return messageData;
	}

	delete messageData;
	return NULL;
}


int ReceiverUser::Receive(Buffer* transferData, Buffer *outdata)
{
	Buffer messageData, signatureData;
	unsigned int messageDataLen = 0;

	while (transferData->Len())
	{
		MessageType type = (MessageType)transferData->GetChar();
		switch (type)
		{
			case MessageType::MessageTypeKeyExchange:
			{
				int len;
				char* data = transferData->GetString(&len);
				Buffer bundle;
				bundle.Append(data, len);
				Buffer secret;
				if (X3DHCalculateShared(&secret, &bundle) == ERROR_NONE)
				{
					if (secret.Len() >= SHARED_SECRET_SIZE)
					{
						shared_index = 0;

						if (shared_secret)
							free(shared_secret);
						shared_secret = (char*)malloc(SHARED_SECRET_SIZE);
						if (shared_secret)
						{
							memcpy(shared_secret, secret.Ptr(), SHARED_SECRET_SIZE);
							secret.Consume(SHARED_SECRET_SIZE);
						}

						if (secret.Len() >= INIT_VECTOR_SIZE)
						{
							if (init_vector)
								free(init_vector);
							init_vector = (char*)malloc(INIT_VECTOR_SIZE);
							if (init_vector)
							{
								memcpy(init_vector, secret.Ptr(), INIT_VECTOR_SIZE);
								secret.Consume(INIT_VECTOR_SIZE);
							}
						}
					}
				}
			}
			break;

			case MessageType::MessageTypeEncryptedMessageWithLen:
			{
				messageDataLen = transferData->GetInt();
				int len;
				char* data = transferData->GetString(&len);
				messageData.Append(data, len);
				data = NULL;
			}
			break;

			case MessageType::MessageTypeSignature:
			{
				int len;
				char* data = transferData->GetString(&len);
				signatureData.Append(data, len);
				data = NULL;
			}
			break;

			default:
				return TRANSFER_INVALID_MESSAGE_CONTENTS;
		}
	}

	if (messageData.Len() && signatureData.Len() && shared_secret && init_vector)
	{
		char tmp_init_vector[INIT_VECTOR_SIZE];
		memcpy(tmp_init_vector, init_vector, INIT_VECTOR_SIZE);
		ADD_32BIT(tmp_init_vector, shared_index);

		Aes256GcmDec aes(shared_secret, tmp_init_vector);
		//Aes128EcbDec aes("1234567890123456789012345678901234567890", "1234567890123456789012345678901234567890");

		// generate secret payload buffer, timestamped
		Buffer secretDataBuffer;
		char* data;
		secretDataBuffer.AppendSpace(&data, messageData.Len());
		aes.Decrypt(messageData.Ptr(), (int)messageData.Len(), data, (int)messageData.Len());
		if (secretDataBuffer.Len() > messageDataLen)
			secretDataBuffer.ConsumeEnd((unsigned int)(secretDataBuffer.Len() - messageDataLen));
		secretDataBuffer.Append(shared_secret, SHARED_SECRET_SIZE);

		Hash_SHA512 h;
		const char* hash = h.Final(secretDataBuffer.Ptr(), secretDataBuffer.Len());
		if (identity_public->Verify(hash, h.HashLen, signatureData.Ptr(), signatureData.Len()) == ERROR_NONE)
		{
			if (shared_index == secretDataBuffer.GetInt()) // this is index
			{
				shared_index++;

				// adjust shared secret for next iteration
				memcpy(shared_secret, hash, SHARED_SECRET_SIZE);

				// ovaj kod ce se mijenjati, ali je za test nebitan jer u sstr dobijem strin
				// sta cu i kako s njim, ovisi o daljnjoj implementaciji
				int slen = 0;
				char* str = secretDataBuffer.GetString(&slen);

				if (outdata)
					outdata->Append(str, slen);
			}
		}
		else
			return SIGNERR_VERIFY_FAILURE;

	}
	else
		return TRANSFER_MESSAGE_EMPTY;


	return ERROR_NONE;
}