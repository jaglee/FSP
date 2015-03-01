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

#include <stdlib.h>
#include <string.h>
#include "gcm-aes.h"


#ifndef bcopy
#define bcopy(src, tgt, size) memcpy((tgt), (src), (size))
#endif

#ifndef bzero
#define bzero(p, size) memset((p), 0, (size))
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


void GCM_AES_Init(GCM_AES_CTX *ctx, const uint8_t *K, int bytesK, const uint8_t *IV)
{
	// AES key schedule
	ctx->rounds = rijndaelKeySetupEnc(ctx->K, K, bytesK * 8);

	// Hash state
	bzero(ctx->H, GCM_BLOCK_LEN);
	bzero(ctx->X, GCM_BLOCK_LEN);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->X, ctx->H);

	// J0/pre-Initial Counter Block (as the length of IV is fixed to 96 bits)
	bcopy(IV, ctx->J, GCM_IV_LEN_FIXED);
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
}


void GMAC_InitWithKey(GCM_AES_CTX *ctx, const uint8_t *K, int bytesK)
{
	// AES key schedule
	ctx->rounds = rijndaelKeySetupEnc(ctx->K, K, (bytesK - GMAC_SALT_LEN) * 8);

	// Hash state
	bzero(ctx->H, GCM_BLOCK_LEN);
	bzero(ctx->X, GCM_BLOCK_LEN);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->X, ctx->H);

	// Salt of J0/pre-Initial Counter Block, as to RFC4543
	// assert(GMAC_SALT_LEN == sizeof(uint32_t));
	*(uint32_t *)ctx->J = *(uint32_t *) & K[bytesK - GMAC_SALT_LEN];
}


void GMAC_SetIV(GCM_AES_CTX *ctx, const uint8_t *IV)
{
	// well, it may cross 64-bit alignment border so we should not exploit 64-bit integer assignment
	bcopy(IV, ctx->J + GMAC_SALT_LEN, GCM_IV_LEN_FIXED - GMAC_SALT_LEN);
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
}


int	GCM_AES_EncryptAndAuthenticate(GCM_AES_CTX *ctx
								, const uint8_t *P, uint32_t bytesP
								, const uint8_t *A, uint32_t bytesA
								, uint8_t *C	// capacity of ciphertext buffer MUST be no less than bytesP
								, uint8_t *T, int bytesT
								)
{
	uint32_t	blk[4] = { 0, 0, 0, 0 };
	uint8_t	keystream[GCM_BLOCK_LEN];
	int	plen;
	int nMinus1;
	uint32_t *x;
	register int i, j;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (uint32_t *)A;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(A + (bytesA - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// Do cipher
	if(bytesP > 0)
	{
		nMinus1 = bytesP >> GCM_BLOCK_LEN_POWER;
		plen = bytesP & (GCM_BLOCK_LEN - 1);
		x = (uint32_t *)C;
		// ICB
		gfinc(ctx->J);
		for(i = 0; i < nMinus1; i++)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			gfadd(P + (i << GCM_BLOCK_LEN_POWER), keystream, C + (i << GCM_BLOCK_LEN_POWER));
			gfinc(ctx->J);
			//
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			x += 4;
		}

		if (plen != 0)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			for(i = 0, j = bytesP - plen; i < plen; i++, j++)
			{
				 C[j] = P[j] ^ keystream[i];
			}
			//
			bcopy(C + (bytesP - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesP, ctx->X);
	ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);

	// The final round, compute the secured digest
	// UNRESOLVED!could make a platform-depended representation of '1'
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
	for (i = 0; i < bytesT; i++)
		T[i] = ctx->X[i] ^ keystream[i];
	bzero(ctx->X, GCM_BLOCK_LEN);
	bzero(keystream, sizeof(keystream));	// for security reason

	return 0;
}



int	GCM_AES_AuthenticatedDecrypt(GCM_AES_CTX *ctx
								, const uint8_t *C, uint32_t bytesC
								, const uint8_t *A, uint32_t bytesA
								, const uint8_t *T, int bytesT
								, uint8_t *P	// capacity of plaintext buffer MUST be no less than bytesC
								)
{
	uint32_t	blk[4] = { 0, 0, 0, 0 };
	uint8_t	keystream[GCM_BLOCK_LEN];
	int	plen;
	int nMinus1;
	uint32_t *x;
	register int i, j;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	// A at first
	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (uint32_t *)A;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(A + (bytesA - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}


	// Continue GHASH on C
	if(bytesC > 0)
	{
		nMinus1 = bytesC >> GCM_BLOCK_LEN_POWER;
		plen = bytesC & (GCM_BLOCK_LEN - 1);
		x = (uint32_t *)C;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(C + (bytesC - plen), (uint8_t *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesC , ctx->X);
	ghash_gfmul((uint32_t *)ctx->X, (uint32_t *)ctx->H, (uint32_t *)ctx->X);

	// The final round, authenticate the digest
	// UNRESOLVED!could make a platform-depended representation of '1'
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(uint32_t *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
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
		// ICB
		gfinc(ctx->J);
		for(i = 0; i < nMinus1; i++)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			gfadd(C + (i << GCM_BLOCK_LEN_POWER), keystream, P + (i << GCM_BLOCK_LEN_POWER));
			gfinc(ctx->J);
		}
		if (plen)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			for(i = 0, j = bytesC - plen; i < plen; i++, j++)
			{
				 P[j] = C[j] ^ keystream[i];
			}
		}
	}
	bzero(ctx->X, GCM_BLOCK_LEN);
	bzero(keystream, sizeof(keystream));	// for security reason

	return 0;	// no error
}



int GCM_SecureHash(GCM_AES_CTX *ctx, const uint8_t *A, uint32_t bytesA, uint8_t *T, int bytesT)
{
	return GCM_AES_EncryptAndAuthenticate(ctx, NULL, 0, A, bytesA, NULL, T, bytesT);
}
