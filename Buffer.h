#ifndef BUFFER_H
#define BUFFER_H

#define PUT_64BIT(cp, value) do { \
	(cp)[0] = (char)((value) >> 56); \
	(cp)[1] = (char)((value) >> 48); \
	(cp)[2] = (char)((value) >> 40); \
	(cp)[3] = (char)((value) >> 32); \
	(cp)[4] = (char)((value) >> 24); \
	(cp)[5] = (char)((value) >> 16); \
	(cp)[6] = (char)((value) >> 8); \
	(cp)[7] = (char)((value)); } while (0)

#define PUT_32BIT(cp, value) do { \
	(cp)[0] = (char)((value) >> 24); \
	(cp)[1] = (char)((value) >> 16); \
	(cp)[2] = (char)((value) >> 8); \
	(cp)[3] = (char)((value)); } while (0)

#define ADD_32BIT(cp, value) do { \
	(cp)[0] += (char)((value) >> 24); \
	(cp)[1] += (char)((value) >> 16); \
	(cp)[2] += (char)((value) >> 8); \
	(cp)[3] += (char)((value)); } while (0)

#define PUT_16BIT(cp, value) do { \
	(cp)[0] = (char)((value) >> 8); \
	(cp)[1] = (char)(value); } while (0)

#define GET_64BIT(cp) (((unsigned __int64)(unsigned char)(cp)[0] << 56) | \
	((unsigned __int64)(unsigned char)(cp)[1] << 48) | \
	((unsigned __int64)(unsigned char)(cp)[2] << 40) | \
	((unsigned __int64)(unsigned char)(cp)[3] << 32) | \
	((unsigned __int64)(unsigned char)(cp)[4] << 23) | \
	((unsigned __int64)(unsigned char)(cp)[5] << 16) | \
	((unsigned __int64)(unsigned char)(cp)[6] << 8) | \
	((unsigned __int64)(unsigned char)(cp)[7]))

#define GET_32BIT(cp) (((unsigned )(unsigned char)(cp)[0] << 24) | \
	((unsigned long)(unsigned char)(cp)[1] << 16) | \
	((unsigned long)(unsigned char)(cp)[2] << 8) | \
	((unsigned long)(unsigned char)(cp)[3]))

#define GET_16BIT(cp) (((unsigned long)(unsigned char)(cp)[0] << 8) | \
	((unsigned long)(unsigned char)(cp)[1]))

class Buffer
{

public:
		char	*m_buf;		/* Buffer for data. */
		size_t	 m_offset;	/* Offset of first byte containing data. */
		size_t	 m_end;		/* Offset of last byte containing data. */
		size_t	 m_alloc;		/* Number of bytes allocated for data. */

public:
	Buffer();
	Buffer(size_t alloc);
	~Buffer();
	void	 Clear();

	size_t	 Len();
	char	*Ptr();

	void	 Append(const char *);
	void	 Append(const char *, size_t);
	void	 AppendSpace(char **, size_t);

	void	 Get(char *, unsigned int);

	void	 Consume(unsigned int);
	void	 ConsumeEnd(unsigned int);

	void PutInt(unsigned int);
	void PutInt64(unsigned __int64);
	unsigned int GetInt();
	unsigned __int64 GetInt64();
	unsigned int PeekInt();
	void PutShort(unsigned short);
	unsigned short GetShort();

	int GetChar();
	void PutChar(int);

	void PutString(const char *str);
	void PutString(const char *str, size_t len);
	char *GetString();
	char *GetString(int *len);

	char *GetNextLine();
	char *GetNextDelimiter(char delimit);
	bool HasLine();

	bool Load(const char* filename);
	bool Save(const char* filename);
	static bool Exists(const char* filename);

	Buffer* ToHex(void);
	void FromHex(Buffer* hex);

	void ClearSafe(void);

};
#endif
