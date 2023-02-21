#include <stdlib.h>
#include <string.h>
#include "Platform.h"
#include "Buffer.h"



/* Initializes the buffer structure. */

Buffer::Buffer() : Buffer(1024)
{
}

// Function name	: Buffer::Buffer
// Description	    :
// Return type		:
Buffer::Buffer(size_t alloc)
{
	m_alloc = alloc;
	m_buf = (char *)malloc(m_alloc);
	if (m_buf)
		m_buf[0] = 0;
	m_offset = 0;
	m_end = 0;
}

/* Frees any memory used for the buffer. */
#include <stdio.h>

// Function name	: Buffer::~Buffer
// Description	    :
// Return type		:
Buffer::~Buffer()
{
//    Append("\0",1);
//	memset(m_buf, 0, m_alloc);
	free(m_buf);
}

/*
 * Clears any data from the buffer, making it empty.  This does not actually
 * zero the memory.
 */


// Function name	: Buffer::Clear
// Description	    :
// Return type		: void
void Buffer::Clear()
{
	m_offset = 0;
	m_end = 0;
	m_buf[0] = 0;
}

/* Appends data to the buffer, expanding it if necessary. */


// Function name	: Buffer::Append
// Description	    :
// Return type		: void
// Argument         : const char *data
// Argument         : unsigned int len
void Buffer::Append(const char *data, size_t len)
{
	if (len > 0)
	{
		// always enough data for encryption
		char *cp;
		AppendSpace(&cp, len+16);
		if (cp && len <= m_end - m_offset)
		{
			memcpy(cp, data, len);
			cp[len] = 0;

			if (m_end - m_offset > 16)
				m_end -= 16;
		}
	}
}

void Buffer::Append(const char *data)
{
	if (data)
		Append(data, (int)strlen(data));
}
/*
 * Appends space to the buffer, expanding the buffer if necessary. This does
 * not actually copy the data into the buffer, but instead returns a pointer
 * to the allocated region.
 */


// Function name	: Buffer::AppendSpace
// Description	    :
// Return type		: void
// Argument         : char **datap
// Argument         : unsigned int len
void Buffer::AppendSpace(char **datap, size_t len)
{
	/* If the buffer is empty, start using it from the beginning. */
	if (m_offset == m_end) {
		m_offset = 0;
		m_end = 0;
	}
restart:
	/* If there is enough space to store all data, store it now. */
	if (m_end + len < m_alloc) {
		if (datap)
			*datap = m_buf + m_end;
		m_end += len;
		return;
	}
	/*
	 * If the buffer is quite empty, but all data is at the m_end, move the
	 * data to the beginning and retry.
	 */
	if (m_offset > m_alloc / 2) {
		memmove(m_buf, m_buf + m_offset,
			m_end - m_offset);
		m_end -= m_offset;
		m_offset = 0;
		goto restart;
	}
	/* Increase the size of the buffer and retry. */
	m_alloc += len + m_alloc;
	char* tmpbuff = (char*)realloc(m_buf, m_alloc);
	if (tmpbuff)
		m_buf = tmpbuff;
	else
		return; // and probably crash
	goto restart;
}

/* Returns the number of bytes of data in the buffer. */


// Function name	: Buffer::Len
// Description	    :
// Return type		: unsigned int
size_t Buffer::Len()
{
	return m_end - m_offset;
}

/* Gets data from the beginning of the buffer. */


// Function name	: Buffer::Get
// Description	    :
// Return type		: void
// Argument         : char *buf
// Argument         : unsigned int len
void Buffer::Get(char *buf, unsigned int len)
{
	if (len > m_end - m_offset)
		return;
//		fatal("buffer_get: trying to get more bytes %d than in buffer %d",len, m_end - m_offset);
	memcpy(buf, m_buf + m_offset, len);
	m_offset += len;
}

/* Consumes the given number of bytes from the beginning of the buffer. */


// Function name	: Buffer::Consume
// Description	    :
// Return type		: void
// Argument         : unsigned int bytes
void Buffer::Consume(unsigned int bytes)
{
	if (bytes > m_end - m_offset)
		return;
//		fatal("buffer_consume: trying to get more bytes than in buffer");
	m_offset += bytes;

	if (m_offset == m_end)
		m_offset = m_end = 0;
}

/* Consumes the given number of bytes from the m_end of the buffer. */


// Function name	: Buffer::ConsumeEnd
// Description	    :
// Return type		: void
// Argument         : unsigned int bytes
void Buffer::ConsumeEnd(unsigned int bytes)
{
	if (bytes > m_end - m_offset)
		return;
//		fatal("buffer_consume_end: trying to get more bytes than in buffer");
	m_end -= bytes;
}

/* Returns a pointer to the first used byte in the buffer. */


// Function name	: *Buffer::Ptr
// Description	    :
// Return type		: char
char *Buffer::Ptr()
{
	return m_buf + m_offset;
}

/*
 * Returns an arbitrary binary string from the buffer.  The string cannot
 * be longer than 256k.  The returned value points to memory allocated
 * with xmalloc; it is the responsibility of the calling function to free
 * the data.  If length_ptr is non-NULL, the length of the returned data
 * will be stored there.  A null character will be automatically appended
 * to the returned string, and is not counted in length.
 */


/*
 * Returns a character from the buffer (0 - 255).
 */

// Function name	: Buffer::GetChar
// Description	    :
// Return type		: int
int Buffer::GetChar()
{
	char ch;
	Get(&ch, 1);
	return (unsigned char) ch;
}

/*
 * Stores a character in the buffer.
 */

// Function name	: Buffer::PutChar
// Description	    :
// Return type		: void
// Argument         : int value
void Buffer::PutChar(int value)
{
	char ch = value;
	Append(&ch, 1);
}


char *Buffer::GetNextLine()
{
	int i;
	size_t len;

	len = Len();
	char *mark = Ptr();

	if (len)
	{
		i=0;
		char *b = Ptr();
		while (b[i]!='\n' && i<len) i++;
		if (b[i]=='\n' && i<len)
		{
			// consume i+1
			Consume(i+1);

			if (i>0 && b[i-1]=='\r')
				i--;

			b[i]=0;
			return mark;
		}
		else
			return NULL;
	}
	else
		return NULL;
}

char *Buffer::GetNextDelimiter(char delimit)
{
	int i;
	
	size_t len;

	len = Len();
	char *mark = Ptr();

	if (len)
	{
		i=0;
		char *b = Ptr();
		while (i<len && b[i]!=delimit) i++;
		if (i<len && b[i]==delimit)
		{
			// consume i+1
			Consume(i+1);

			b[i]=0;
			return mark;
		}
		else
			return NULL;
	}
	else
		return NULL;
}

bool Buffer::HasLine()
{
	int i;
	size_t len;

	len = Len();
//	char *mark = Ptr();

	if (len)
	{
		i=0;
		char *b = Ptr();
		while (b[i]!='\n' && i<len) i++;
		if (b[i]=='\n' && i<len)
			return true;

	}
	return false;
}

void Buffer::PutInt(unsigned int value)
{
	char buf[4];
	PUT_32BIT(buf, value);
	Append(buf, 4);
}

void Buffer::PutInt64(unsigned __int64 value)
{
	char buf[8];
	PUT_64BIT(buf, value);
	Append(buf, 8);
}

unsigned int Buffer::GetInt()
{
	unsigned char buf[4];
	Get((char *) buf, 4);
	return (unsigned int)GET_32BIT(buf);
}

unsigned __int64 Buffer::GetInt64()
{
	unsigned char buf[8];
	Get((char*)buf, 8);
	return (unsigned __int64)GET_64BIT(buf);
}

unsigned int Buffer::PeekInt()
{
	if (Len()>=4)
	{
		unsigned char *a= (unsigned char *)Ptr();
		return (int)GET_32BIT(a);
	}
	return 0;
}

void Buffer::PutShort(unsigned short value)
{
	char buf[2];
	PUT_16BIT(buf, value);
	Append(buf, 2);
}

unsigned short Buffer::GetShort()
{
	unsigned char buf[2];
	Get((char *) buf, 2);
	return GET_16BIT(buf);
}

void Buffer::PutString(const char *str)
{
	int len = (int)strlen(str);
	PutInt(len);
	Append(str, len);
}
void Buffer::PutString(const char *str, size_t len)
{
	PutInt((unsigned int)len);
	Append(str, len);
}

char *Buffer::GetString(void)
{
	int len = GetInt();
	if (len)
	{
		char *out = Ptr();
		Consume(len);
		return out;
	}
	else
		return (char *)"";
}
char *Buffer::GetString(int *l)
{
	int len = GetInt();
	if (l)
		*l = len;
	if (len)
	{
		char *out = Ptr();
		Consume(len);
		return out;
	}
	else
		return (char *)"";
}

bool Buffer::Load(const char* filename)
{
	Clear();
	FILE* stream = fopen(filename, "rb");
	if (stream)
	{
		char buff[65535];
		while (!feof(stream))
		{
			size_t i = fread(buff, 1, sizeof(buff), stream);
			if (i > 0)
				Append(buff, (unsigned int)i);
			else
				break;
		}
		fclose(stream);
		return true;
	}
	return false;
}

bool Buffer::Save(const char* filename)
{
	FILE* stream = fopen(filename, "wb");
	if (stream)
	{
		if (fwrite(Ptr(), 1, Len(), stream))
		{
		}
		fclose(stream);
		return true;
	}
	return false;
}

bool Buffer::Exists(const char* filename)
{
	FILE* stream = fopen(filename, "rb");
	if (stream)
	{
		fclose(stream);
		return true;
	}
	return false;
}

Buffer* Buffer::ToHex(void)
{
	Buffer* out = new Buffer();
	out->Append(Ptr(), Len());
	::ToHex(out);
	return out;
}

void Buffer::FromHex(Buffer* hex)
{
	Append(hex->Ptr(), hex->Len());
	::FromHex(this);
}

void Buffer::ClearSafe(void)
{
	memset(m_buf, 0xfe, m_alloc);
}