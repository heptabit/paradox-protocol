/* Montgomery <-> Edwards isomorphism
 * Daniel Beer <dlbeer@gmail.com>, 18 Jan 2014
 *
 * This file is in the public domain.
 */

#include "morph25519.h"
#include "f25519.h"
#include "sha512.h"

void morph25519_secret_e2m(uint8_t* montgomery, const uint8_t* y)
{
	struct sha512_state s;
	unsigned char h[64];

	sha512_init(&s);
	sha512_final(&s, y, F25519_SIZE);
	sha512_get(&s, h, 0, 64);

	h[0] &= 248;
	h[31] &= 127;
	h[31] |= 64;
	memcpy(montgomery, h, F25519_SIZE);
}

void morph25519_e2m(uint8_t *montgomery, const uint8_t *y)
{
	uint8_t yplus[F25519_SIZE];
	uint8_t yminus[F25519_SIZE];

	f25519_sub(yplus, f25519_one, y);
	f25519_inv__distinct(yminus, yplus);
	f25519_add(yplus, f25519_one, y);
	f25519_mul__distinct(montgomery, yplus, yminus);
	f25519_normalize(montgomery);
}

static void mx2ey(uint8_t *ey, const uint8_t *mx)
{
	uint8_t n[F25519_SIZE];
	uint8_t d[F25519_SIZE];

	f25519_add(n, mx, f25519_one);
	f25519_inv__distinct(d, n);
	f25519_sub(n, mx, f25519_one);
	f25519_mul__distinct(ey, n, d);
}

static uint8_t ey2ex(uint8_t *x, const uint8_t *y, int parity)
{
	static const uint8_t d[F25519_SIZE] = {
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
	};

	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];
	uint8_t c[F25519_SIZE];

	/* Compute c = y^2 */
	f25519_mul__distinct(c, y, y);

	/* Compute b = (1+dy^2)^-1 */
	f25519_mul__distinct(b, c, d);
	f25519_add(a, b, f25519_one);
	f25519_inv__distinct(b, a);

	/* Compute a = y^2-1 */
	f25519_sub(a, c, f25519_one);

	/* Compute c = a*b = (y^2+1)/(1-dy^2) */
	f25519_mul__distinct(c, a, b);

	/* Compute a, b = +/-sqrt(c), if c is square */
	f25519_sqrt(a, c);
	f25519_neg(b, a);

	/* Select one of them, based on the parity bit */
	f25519_select(x, a, b, (a[0] ^ parity) & 1);

	/* Verify that x^2 = c */
	f25519_mul__distinct(a, x, x);
	f25519_normalize(a);
	f25519_normalize(c);

	return f25519_eq(a, c);
}

uint8_t morph25519_m2e(uint8_t *ex, uint8_t *ey,
		       const uint8_t *mx, int parity)
{
	uint8_t ok;

	mx2ey(ey, mx);
	ok = ey2ex(ex, ey, parity);

	f25519_normalize(ex);
	f25519_normalize(ey);

	return ok;
}
