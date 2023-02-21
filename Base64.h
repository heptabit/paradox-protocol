#ifndef BASE64_H
#define BASE64_H

#include "Platform.h"

class Buffer;

static const char __Base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char __Pad64 = '=';
class Base64
{
public:
	Base64()
	{
	}

public:
	virtual ~Base64()
	{
	}



	static void Encode(Buffer* from, Buffer* to, int rows = 0)
	{
		Buffer temp;
		char* data;
		temp.AppendSpace(&data, from->Len()*2);
		memset(data, 0, from->Len()*2);
		int len = dumpbase64(data, (unsigned char*)from->Ptr(), (unsigned int)from->Len(), rows);
		to->Append(data, len);
	}
	static void Decode(Buffer* from, Buffer* to)
	{
		Buffer temp;
		char* data;
		temp.AppendSpace(&data, from->Len() * 2);
		int len = uudecode(from->Ptr(), (unsigned int)from->Len(), (unsigned char *)data, (unsigned int)from->Len() * 2);
		to->Append(data, len);
	}

protected:

	static int uudecode(const char* src, int srclen, unsigned char* target, size_t targsize)
	{
		int len;
		char* encoded, * p;

		/* copy the 'readonly' source */
		encoded = (char*)malloc(srclen + 1);
		memset(encoded, 0, srclen + 1);
		memcpy(encoded, src, srclen);
		/* skip whitespace and data */
		for (p = encoded; *p == ' ' || *p == '\t'; p++)
			;
		for (; *p != '\0' && *p != ' ' && *p != '\t'; p++)
			;
		/* and remove trailing whitespace because __b64_pton needs this */
		*p = '\0';
		len = b64_pton(encoded, target, targsize);
		free(encoded);
		return len;
	}

	static int dumpbase64(char* out, unsigned char* data, u_int len, int rows = 0)
	{
		int i, n;

		char* buf = (char*)malloc(2 * len);
		n = uuencode(data, len, buf, 2 * len);
		int outlen = 0;
		for (i = 0; i < n; i++)
		{
			*out++ = buf[i];
			outlen++;
			if (rows && (i % rows == (rows-1)))
			{
				*out++ = '\r';
				*out++ = '\n';
				outlen++;
				outlen++;
			}
		}
		if (rows && (i % rows != (rows-1)))
		{
			*out++ = '\r';
			*out++ = '\n';
			outlen++;
			outlen++;
		}

		free(buf);
		return outlen;
	}

	static int uuencode(unsigned char* src, unsigned int srclength, char* target, size_t targsize)
	{
		return b64_ntop(src, srclength, target, targsize);
	}

	static int b64_pton(char const* src, u_char* target, size_t targsize)
	{
		unsigned int tarindex;
		int state, ch;
		char* pos;

		state = 0;
		tarindex = 0;

		while ((ch = *src++) != '\0') {
			if (isspace(ch))	/* Skip whitespace anywhere. */
				continue;

			if (ch == __Pad64)
				break;

			pos = (char*)strchr(__Base64, ch);
			if (pos == 0) 		/* A non-base64 character. */
				return (-1);

			switch (state) {
			case 0:
				if (target) {
					if (tarindex >= targsize)
						return (-1);
					target[tarindex] = (char)((pos - __Base64) << 2);
				}
				state = 1;
				break;
			case 1:
				if (target) {
					if (tarindex + 1 >= targsize)
						return (-1);
					target[tarindex] |= (pos - __Base64) >> 4;
					target[tarindex + 1] = ((pos - __Base64) & 0x0f)
						<< 4;
				}
				tarindex++;
				state = 2;
				break;
			case 2:
				if (target) {
					if (tarindex + 1 >= targsize)
						return (-1);
					target[tarindex] |= (pos - __Base64) >> 2;
					target[tarindex + 1] = ((pos - __Base64) & 0x03)
						<< 6;
				}
				tarindex++;
				state = 3;
				break;
			case 3:
				if (target) {
					if (tarindex >= targsize)
						return (-1);
					target[tarindex] |= (pos - __Base64);
				}
				tarindex++;
				state = 0;
				break;
			}
		}

		/*
		 * We are done decoding Base-64 chars.  Let's see if we ended
		 * on a byte boundary, and/or with erroneous trailing characters.
		 */

		if (ch == __Pad64) {		/* We got a pad char. */
			ch = *src++;		/* Skip it, get next. */
			switch (state) {
			case 0:		/* Invalid = in first position */
			case 1:		/* Invalid = in second position */
				return (-1);

			case 2:		/* Valid, means one byte of info */
				/* Skip any number of spaces. */
				for (; ch != '\0'; ch = *src++)
					if (!isspace(ch))
						break;
				/* Make sure there is another trailing = sign. */
				if (ch != __Pad64)
					return (-1);
				ch = *src++;		/* Skip the = */
				/* Fall through to "single trailing =" case. */
				/* FALLTHROUGH */

			case 3:		/* Valid, means two bytes of info */
				/*
				 * We know this char is an =.  Is there anything but
				 * whitespace after it?
				 */
				for (; ch != '\0'; ch = *src++)
					if (!isspace(ch))
						return (-1);

				/*
				 * Now make sure for cases 2 and 3 that the "extra"
				 * bits that slopped past the last full byte were
				 * zeros.  If we don't check them, they become a
				 * subliminal channel.
				 */
				if (target && target[tarindex] != 0)
					return (-1);
			}
		}
		else {
			/*
			 * We ended by seeing the end of the string.  Make sure we
			 * have no partial bytes lying around.
			 */
			if (state != 0)
				return (-1);
		}

		return (tarindex);
	}

	static int b64_ntop(u_char const* src, size_t srclength, char* target, size_t targsize) 
	{
		/* [<][>][^][v][top][bottom][index][help] */
		size_t datalength = 0;
		u_char input[3];
		u_char output[4];
		size_t i;

		while (2 < srclength) {
			input[0] = *src++;
			input[1] = *src++;
			input[2] = *src++;
			srclength -= 3;

			output[0] = input[0] >> 2;
			output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
			output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
			output[3] = input[2] & 0x3f;

			if (datalength + 4 > targsize)
				return (-1);
			target[datalength++] = __Base64[output[0]];
			target[datalength++] = __Base64[output[1]];
			target[datalength++] = __Base64[output[2]];
			target[datalength++] = __Base64[output[3]];
		}

		/* Now we worry about padding. */
		if (0 != srclength) {
			/* Get what's left. */
			input[0] = input[1] = input[2] = '\0';
			for (i = 0; i < srclength; i++)
				input[i] = *src++;

			output[0] = input[0] >> 2;
			output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
			output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);

			if (datalength + 4 > targsize)
				return (-1);
			target[datalength++] = __Base64[output[0]];
			target[datalength++] = __Base64[output[1]];
			if (srclength == 1)
				target[datalength++] = __Pad64;
			else
				target[datalength++] = __Base64[output[2]];
			target[datalength++] = __Pad64;
		}
		if (datalength >= targsize)
			return (-1);
		target[datalength] = '\0';      /* Returned value doesn't count \0. */
		return (int)(datalength);
	}

};
#endif
