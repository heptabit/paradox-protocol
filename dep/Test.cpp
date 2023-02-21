#include <stdio.h>
#include <assert.h>

extern "C"
{
#include "c25519/c25519.h"
#include "c25519/ed25519.h"
#include "c25519/edsign.h"
#include "c25519/morph25519.h"
#include "c25519/sha512.h"

	void expand_key(uint8_t* expanded, const uint8_t* secret);

}
const char* msg = "1234512345";


int main(void)
{
/*
	unsigned char priv1[32], pub1[32], priv2[32], pub2[32], sig[8192];
	for (int i = 0; i < 32; i++)
	{
		priv1[i] = i;
		priv2[i] = i + 100;
	}

	ed25519_prepare(priv1);
	ed25519_prepare(priv2);

	edsign_sec_to_pub(pub1, priv1);
	edsign_sec_to_pub(pub2, priv2);

	edsign_sign(sig, pub1, priv1, (const unsigned char*)msg, strlen(msg));


	int ret = edsign_verify(sig, pub1, (const unsigned char*)msg, strlen(msg));
	ret++;
*/

/*
	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	uint8_t q1[F25519_SIZE];
	uint8_t q2[F25519_SIZE];
	uint8_t r1[F25519_SIZE];
	uint8_t r2[F25519_SIZE];

	uint8_t xe1[F25519_SIZE];
	uint8_t xe2[F25519_SIZE];
	uint8_t xq1[F25519_SIZE];
	uint8_t xq2[F25519_SIZE];

	unsigned int i;

	for (i = 0; i < sizeof(e1); i++)
		e1[i] = i;
	for (i = 0; i < sizeof(e2); i++)
		e2[i] = 100 + i;

	// Create private keys 
	ed25519_prepare(e1);
	ed25519_prepare(e2);

	edsign_sec_to_pub(q1, e1);
	edsign_sec_to_pub(q2, e2);


//	c25519_smult(q1, c25519_base_x, e1);
//	c25519_smult(q2, c25519_base_x, e2);

	morph25519_e2m(xq1, q1);
	morph25519_e2m(xq2, q2);

	morph25519_e2m(xe1, e1);
	morph25519_e2m(xe2, e2);

	//Diffie-Hellman exchange
	c25519_smult(r1, q2, e1);
	c25519_smult(r2, q1, e2);

	assert(f25519_eq(r1, r2));

	printf("  ");
	for (i = 0; i < F25519_SIZE; i++)
		printf("%02x", q1[i]);
	printf("\n");
*/

uint8_t e1[ED25519_EXPONENT_SIZE];
uint8_t c1[ED25519_EXPONENT_SIZE];
uint8_t e2[ED25519_EXPONENT_SIZE];
uint8_t c2[ED25519_EXPONENT_SIZE];
uint8_t q1[F25519_SIZE];
uint8_t q2[F25519_SIZE];
uint8_t p1x[F25519_SIZE];
uint8_t p1y[F25519_SIZE];
uint8_t p2x[F25519_SIZE];
uint8_t p2y[F25519_SIZE];
uint8_t s1x[F25519_SIZE];
uint8_t s1y[F25519_SIZE];
uint8_t s2x[F25519_SIZE];
uint8_t s2y[F25519_SIZE];
uint8_t r1[F25519_SIZE];
uint8_t r2[F25519_SIZE];
uint8_t x1[F25519_SIZE];
uint8_t x2[F25519_SIZE];
uint8_t ex1[F25519_SIZE];
uint8_t ey1[F25519_SIZE];
uint8_t ex2[F25519_SIZE];
uint8_t ey2[F25519_SIZE];
uint8_t sec1[F25519_SIZE];
uint8_t sec2[F25519_SIZE];
uint8_t y1[F25519_SIZE];
uint8_t y2[F25519_SIZE];
struct ed25519_pt p1;
struct ed25519_pt p2; 
unsigned char sig[8192];

struct ed25519_pt p;
int i;

for (i = 0; i < ED25519_EXPONENT_SIZE; i++) {
	c1[i] = e1[i] = i;
	c2[i] = e2[i] = 100 + i;
}

	//ed25519_prepare(e1);
	//ed25519_prepare(e2);

#define EXPANDED_SIZE 64

	struct sha512_state s1;

	unsigned char expanded1[EXPANDED_SIZE];
	sha512_init(&s1);
	sha512_final(&s1, e1, EDSIGN_SECRET_KEY_SIZE);
	sha512_get(&s1, expanded1, 0, EXPANDED_SIZE);
	ed25519_prepare(expanded1);

	ed25519_smult(&p1, &ed25519_base, expanded1);

	ed25519_unproject(x1, y1, &p1);
	ed25519_pack(q1, x1, y1);



	struct sha512_state s2;
	unsigned char expanded2[EXPANDED_SIZE];
	sha512_init(&s2);
	sha512_final(&s2, e2, EDSIGN_SECRET_KEY_SIZE);
	sha512_get(&s2, expanded2, 0, EXPANDED_SIZE);
	ed25519_prepare(expanded2);

	ed25519_smult(&p2, &ed25519_base, expanded2);

	ed25519_unproject(x2, y2, &p2);
	ed25519_pack(q2, x2, y2);
	//	edsign_sec_to_pub(q2, e2);


	edsign_sign(sig, q1, e1, (const unsigned char*)msg, strlen(msg));
	int ret = edsign_verify(sig, q1, (const unsigned char*)msg, strlen(msg));
	ret++;

//	ed25519_smult(&p1, &ed25519_base, e1);
//	ed25519_unproject(ex1, ey1, &p1);

//	ed25519_smult(&p2, &ed25519_base, e2);
//	ed25519_unproject(ex2, ey2, &p2);

	ed25519_try_unpack(ex1, ey1, q1);
	ed25519_try_unpack(ex2, ey2, q2);
	morph25519_e2m(r1, ey1);
	morph25519_e2m(r2, ey2);

	morph25519_secret_e2m(c1, e1);
	morph25519_secret_e2m(c2, e2);

	//Diffie-Hellman exchange
	c25519_smult(sec1, r2, c1);
	c25519_smult(sec2, r1, c2);

	assert(f25519_eq(sec1, sec2));

/*
	ed25519_prepare(e1);
	ed25519_smult(&p1, &ed25519_base, e1);
	ed25519_unproject(ex1, ey1, &p1);

	edsign_sec_to_pub(q1, e1);
	edsign_sign(sig, q1, e1, (const unsigned char*)msg, strlen(msg));

	c25519_prepare(c1);
	c25519_smult(r1, c25519_base_x, c1);

	morph25519_e2m(x1, ey1);



	c25519_prepare(c2);
	c25519_smult(r2, c25519_base_x, c2);

	//Diffie-Hellman exchange
	c25519_smult(sec1, r2, c1);
	c25519_smult(sec2, r1, c2);

	morph25519_m2e(ex1, ey1, q1, 1);
	ed25519_pack(x1, ex1, ey1);

	int ret = edsign_verify(sig, x1, (const unsigned char*)msg, strlen(msg));
	ret++;

*/

//print_point(s1x, s1y);
}