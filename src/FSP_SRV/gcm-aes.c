/**
 * Copyright (c) 2013 Jason Gao <jagao@outlook.com>
 * Inspired by original work of Mike Belopuhov <mike@vantronix.net>
 * This code implements Galois/Counter Mode using the AES cipher as to description of FIPS SP 800-38D
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define _CRT_RAND_S
#include <stdlib.h>
#include <string.h>
#include "gcm-aes.h"
#include "../endian.h"

#ifndef bcopy
#define bcopy(src, tgt, size) memcpy((tgt), (src), (size))
#endif

#define gfadd(X, Y, S)	(\
	((uint64_t *)(S))[0] = ((uint64_t *)(X))[0] ^ ((uint64_t *)(Y))[0], \
	((uint64_t *)(S))[1] = ((uint64_t *)(X))[1] ^ ((uint64_t *)(Y))[1]	\
	)

// UNRESOLVED!a more efficient platform-dependent inc() function!
#define gfinc(J) ( *(uint32_t *)((uint8_t *)(J) + GCM_IV_LEN_FIXED)	\
	= htobe32(be32toh(*(uint32_t *)((uint8_t *)(J) + GCM_IV_LEN_FIXED)) + 1) )

#define gf_addlen(bytesA, bytesC, X) (\
	((uint64_t *)(X))[0] ^= htobe64((uint64_t)(bytesA) << 3),	\
	((uint64_t *)(X))[1] ^= htobe64((uint64_t)(bytesC) << 3)	\
	)


const uint8_t J0[4] = { 0, 0, 0, 1};

/* Computes a block multiplication in the GF(2^128) */
/* didnot bother to enhance performance of ghash_gfmul */
/* should take use of hardware acceleration for large messages */
static void ghash_gfmul(void *X, void *Y, void *Z)
{
	uint8_t	*x = (uint8_t *)X;
	uint64_t	y[2];
	uint64_t	z[2] = { 0, 0 };
	int64_t		mul;
	register int i;

	y[0] = be64toh(((uint64_t *)Y)[0]);
	y[1] = be64toh(((uint64_t *)Y)[1]);

	for (i = 0; i < GCM_BLOCK_LEN * 8; i++) 
	{
		if (x[i >> 3] & (1 << (~i & 7)))
		{
			z[0] ^= y[0];
			z[1] ^= y[1];
		}

		mul = y[1] & 1;
		y[1] = (y[0] << 63) | (y[1] >> 1);
		y[0] = (y[0] >> 1) ^ (0xE100000000000000LL & (-mul));
		// works only for complementary coding of negative number
	}

	((uint64_t *)Z)[0] = htobe64(z[0]);
	((uint64_t *)Z)[1] = htobe64(z[1]);
}



// external IV part of ctx->J definitely cross 64-bit alignment border
// so we should not exploit 64-bit integer assignment
static __inline
void GCM_AES_SetIV(GCM_AES_CTX *ctx, const uint8_t *IV)
{
	// Reset hash state
	bzero(ctx->X, GCM_BLOCK_LEN);

	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = *(uint32_t *)J0;
	bcopy(IV, ctx->J + GMAC_SALT_LEN, GCM_IV_LEN_FIXED - GMAC_SALT_LEN);
}



// Given
//	GCM_AES_CTX *	pointer to the security context to set
//	const octet *	pointer to the key input buffer
//	int				number of octets the key occupied in the input buffer
// Do
//	Initialize the security context with the given key
// Remark
//	Salt is OPTIONAL. It is exploited as described in RFC4543
//	bytesK must be 16, 24 or 32 without salt, or 20, 28, 40 with salt
//	If the salt is not set here, it MUST have been set by the caller before Decrypt/Encrypt
void GCM_AES_SetKey(GCM_AES_CTX *ctx, const octet *K, int bytesK)
{
	// AES key schedule
	ctx->rounds = rijndaelKeySetupEnc(ctx->K, K, (bytesK & 0xF8) * 8);

	// The HASH sub-key
	bzero(ctx->H, GCM_BLOCK_LEN);
	bzero(ctx->X, GCM_BLOCK_LEN);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->X, ctx->H);

	*(uint32_t *)ctx->J = (bytesK & 7) == 0 ? 0 : *(uint32_t *)(K + (bytesK & 0xF8));
}



uint32_t GCM_AES_XorSalt(GCM_AES_CTX *ctx, uint32_t salt)
{
	register uint32_t u = *(uint32_t *)ctx->J;
	*(uint32_t *)ctx->J = u ^ salt;
	return u;
}



int	GCM_AES_AuthenticatedEncrypt(GCM_AES_CTX *ctx, uint64_t IV
								, const octet *P, uint32_t bytesP
								, const uint64_t *aad, uint32_t bytesA
								, uint64_t *bufCipherText	// capacity of ciphertext buffer MUST be no less than bytesP
								, octet *T, int bytesT)
{
	uint8_t		keystream[GCM_BLOCK_LEN];
	uint64_t	blk[2] = { 0, 0 };
	int	plen;
	int nMinus1;
	uint64_t *x;
	register int i;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	GCM_AES_SetIV(ctx, (const uint8_t *) & IV);

	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (uint64_t *)aad;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			x += GCM_BLOCK_LEN / sizeof(uint64_t);
		}
		if (plen != 0)
		{
			bcopy((uint8_t *)aad + (bytesA - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			blk[0] = blk[1] = 0;		// for security reason
		}
	}

	// Do cipher
	if(bytesP > 0)
	{
		nMinus1 = bytesP >> GCM_BLOCK_LEN_POWER;
		plen = bytesP & (GCM_BLOCK_LEN - 1);
		x = bufCipherText;
		// ICB
		gfinc(ctx->J);
		for(i = 0; i < nMinus1; i++)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			bcopy(P, (uint8_t *)blk, GCM_BLOCK_LEN);
			P += GCM_BLOCK_LEN;
			gfadd(blk, keystream, x);
			gfinc(ctx->J);
			//
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			x += GCM_BLOCK_LEN / sizeof(uint64_t);
		}

		blk[0] = blk[1] = 0;	// there maybe some plaintext in the temporary buffer
		if (plen != 0)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			for(i = 0; i < plen; i++)
				((uint8_t *)x)[i] = P[i] ^ keystream[i];
			bcopy(x, (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			blk[0] = blk[1] = 0;		// for security reason
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesP, ctx->X);
	ghash_gfmul(ctx->X, ctx->H, ctx->X);

	// The final round, compute the secured digest
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = *(const uint32_t *)J0;
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
	for (i = 0; i < bytesT; i++)
		T[i] = ctx->X[i] ^ keystream[i];
	bzero(ctx->X, GCM_BLOCK_LEN);
	bzero(keystream, sizeof(keystream));	// for security reason

	return 0;
}




int	GCM_AES_AuthenticateAndDecrypt(GCM_AES_CTX *ctx, uint64_t IV
									, const octet *C, uint32_t bytesC
									, const uint64_t *aad, uint32_t bytesA
									, const octet *T, int bytesT
									, uint64_t *bufPlainText	// capacity of plaintext buffer MUST be no less than bytesC
									)
{
	uint8_t		keystream[GCM_BLOCK_LEN];
	uint64_t	blk[2] = { 0, 0 };
	int	plen;
	int nMinus1;
	uint64_t *x;
	register int i;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	GCM_AES_SetIV(ctx, (const uint8_t *) & IV);

	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (uint64_t *)aad;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			x += GCM_BLOCK_LEN / sizeof(uint64_t);
		}
		if (plen != 0)
		{
			bcopy((uint8_t *)aad + (bytesA - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			blk[0] = blk[1] = 0;		// for security reason
		}
	}

	// Continue GHASH on C
	if(bytesC > 0)
	{
		const uint8_t *x = C;
		nMinus1 = bytesC >> GCM_BLOCK_LEN_POWER;
		plen = bytesC & (GCM_BLOCK_LEN - 1);
		for (i = 0; i < nMinus1; i++)
		{
			bcopy(x, (uint8_t *)blk, GCM_BLOCK_LEN); 
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			x += GCM_BLOCK_LEN;
		}

		blk[0] = blk[1] = 0;	// there maybe some ciphertext in the temporary buffer
		if (plen != 0)
		{
			bcopy(x, (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul(ctx->X, ctx->H, ctx->X);
			blk[0] = blk[1] = 0;		// for security reason
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesC, ctx->X);
	ghash_gfmul(ctx->X, ctx->H, ctx->X);

	// The final round, authenticate the digest
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = *(uint32_t *)J0;
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
	for (i = 0; i < bytesT; i++)
	{
		if(T[i] != (ctx->X[i] ^ keystream[i]))
			return -2;
	}

	// Do de-cipher, assume H is kept, while S, Z have been zeroed and J have been reset to J0
	if(bytesC > 0)
	{
		nMinus1 = bytesC >> GCM_BLOCK_LEN_POWER;
		plen = bytesC & (GCM_BLOCK_LEN - 1);
		x = bufPlainText;
		// ICB
		gfinc(ctx->J);
		for(i = 0; i < nMinus1; i++)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			bcopy(C, (uint8_t *)blk, GCM_BLOCK_LEN);
			C += GCM_BLOCK_LEN;
			gfadd(blk, keystream, x);
			gfinc(ctx->J);
			x += GCM_BLOCK_LEN / sizeof(uint64_t);
		}
		if (plen)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			for(i = 0; i < plen; i++)
				 ((uint8_t *)x)[i] = C[i] ^ keystream[i];
		}
		blk[0] = blk[1] = 0;	// for security reason
	}

	bzero(ctx->X, GCM_BLOCK_LEN);
	bzero(keystream, sizeof(keystream));	// for security reason

	return 0;	// no error
}
