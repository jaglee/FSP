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
	((u64 *)(S))[0] = ((u64 *)(X))[0] ^ ((u64 *)(Y))[0], \
	((u64 *)(S))[1] = ((u64 *)(X))[1] ^ ((u64 *)(Y))[1]	\
	)

// UNRESOLVED! a more efficient platform-dependent inc() function!
#define gfinc(J) ( *(u32 *)((u8 *)(J) + GCM_IV_LEN_FIXED)	\
	= htobe32(be32toh(*(u32 *)((u8 *)(J) + GCM_IV_LEN_FIXED)) + 1) )

#define gf_addlen(bytesA, bytesC, X) (\
	((u64 *)(X))[0] ^= htobe64((u64)(bytesA) << 3),	\
	((u64 *)(X))[1] ^= htobe64((u64)(bytesC) << 3)	\
	)

/* Computes a block multiplication in the GF(2^128) */
/* didnot bother to enhance performance of ghash_gfmul */
/* should take use of hardware acceleration for large messages */
static void ghash_gfmul(void *X, void *Y, void *Z)
{
	u8	*x = (u8 *)X;
	u64	y[2];
	u64	z[2] = { 0, 0 };
	i64	mul;
	register int i;

	y[0] = be64toh(((u64 *)Y)[0]);
	y[1] = be64toh(((u64 *)Y)[1]);

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

	((u64 *)Z)[0] = htobe64(z[0]);
	((u64 *)Z)[1] = htobe64(z[1]);
}


void GCM_AES_Init(GCM_AES_CTX *ctx, const u8 *K, int bytesK, const u8 *IV)
{
	// AES key schedule
	ctx->rounds = rijndaelKeySetupEnc(ctx->K, K, bytesK * 8);

	// Hash state
	bzero(ctx->H, GCM_BLOCK_LEN);
	bzero(ctx->X, GCM_BLOCK_LEN);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->X, ctx->H);

	// J0/pre-Initial Counter Block (as the length of IV is fixed to 96 bits)
	bcopy(IV, ctx->J, GCM_IV_LEN_FIXED);
	*(u32 *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
}


void GMAC_InitWithKey(GCM_AES_CTX *ctx, const u8 *K, int bytesK)
{
	// AES key schedule
	ctx->rounds = rijndaelKeySetupEnc(ctx->K, K, (bytesK - GMAC_SALT_LEN) * 8);

	// Hash state
	bzero(ctx->H, GCM_BLOCK_LEN);
	bzero(ctx->X, GCM_BLOCK_LEN);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->X, ctx->H);

	// Salt of J0/pre-Initial Counter Block, as to RFC4543
	// assert(GMAC_SALT_LEN == sizeof(u32));
	*(u32 *)ctx->J = *(u32 *) & K[bytesK - GMAC_SALT_LEN];
}


void GMAC_SetIV(GCM_AES_CTX *ctx, const u8 *IV)
{
	// well, it may cross 64-bit alignment border so we should not exploit 64-bit integer assignment
	bcopy(IV, ctx->J + GMAC_SALT_LEN, GCM_IV_LEN_FIXED - GMAC_SALT_LEN);
	*(u32 *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
}


int	GCM_AES_EncryptAndAuthenticate(GCM_AES_CTX *ctx
								, const u8 *P, u32 bytesP
								, const u8 *A, u32 bytesA
								, u8 *C	// capacity of ciphertext buffer MUST be no less than bytesP
								, u8 *T, int bytesT
								)
{
	u32	blk[4] = { 0, 0, 0, 0 };
	u8	keystream[GCM_BLOCK_LEN];
	int	plen;
	int nMinus1;
	u32 *x;
	register int i, j;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (u32 *)A;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(A + (bytesA - plen), (u8 *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// Do cipher
	if(bytesP > 0)
	{
		nMinus1 = bytesP >> GCM_BLOCK_LEN_POWER;
		plen = bytesP & (GCM_BLOCK_LEN - 1);
		x = (u32 *)C;
		// ICB
		gfinc(ctx->J);
		for(i = 0; i < nMinus1; i++)
		{
			rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
			gfadd(P + (i << GCM_BLOCK_LEN_POWER), keystream, C + (i << GCM_BLOCK_LEN_POWER));
			gfinc(ctx->J);
			//
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
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
			bcopy(C + (bytesP - plen), (u8 *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesP, ctx->X);
	ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);

	// The final round, compute the secured digest
	// UNRESOLVED! could make a platform-depended representation of '1'
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(u32 *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
	rijndaelEncrypt(ctx->K, ctx->rounds, ctx->J, keystream);
	for (i = 0; i < bytesT; i++)
		T[i] = ctx->X[i] ^ keystream[i];
	bzero(ctx->X, GCM_BLOCK_LEN);
	bzero(keystream, sizeof(keystream));	// for security reason

	return 0;
}



int	GCM_AES_AuthenticatedDecrypt(GCM_AES_CTX *ctx
								, const u8 *C, u32 bytesC
								, const u8 *A, u32 bytesA
								, const u8 *T, int bytesT
								, u8 *P	// capacity of plaintext buffer MUST be no less than bytesC
								)
{
	u32	blk[4] = { 0, 0, 0, 0 };
	u8	keystream[GCM_BLOCK_LEN];
	int	plen;
	int nMinus1;
	u32 *x;
	register int i, j;

	if(bytesT > GCM_BLOCK_LEN)
		return -2;

	// A at first
	// AAD at first
	if (bytesA > 0)
	{
		nMinus1 = bytesA >> GCM_BLOCK_LEN_POWER;
		plen = bytesA & (GCM_BLOCK_LEN - 1);
		x = (u32 *)A;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(A + (bytesA - plen), (u8 *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}


	// Continue GHASH on C
	if(bytesC > 0)
	{
		nMinus1 = bytesC >> GCM_BLOCK_LEN_POWER;
		plen = bytesC & (GCM_BLOCK_LEN - 1);
		x = (u32 *)C;
		for (i = 0; i < nMinus1; i++)
		{
			gfadd(ctx->X, x, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			x += 4;
		}
		if (plen != 0)
		{
			bcopy(C + (bytesC - plen), (u8 *)blk, plen);
			gfadd(ctx->X, blk, ctx->X);
			ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);
			blk[0] = blk[1] = blk[2] = blk[3] = 0;
		}
	}

	// The length round: somewhat roll-out of ghash_update (but conform to the original GCM specification)
	gf_addlen(bytesA, bytesC , ctx->X);
	ghash_gfmul((u32 *)ctx->X, (u32 *)ctx->H, (u32 *)ctx->X);

	// The final round, authenticate the digest
	// UNRESOLVED! could make a platform-depended representation of '1'
	/* GCTR(J0); assume IV is 96 bits; recover J0 first */
	*(u32 *) & ctx->J[GCM_IV_LEN_FIXED] = htobe32(1);
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



int GCM_SecureHash(GCM_AES_CTX *ctx, const u8 *A, u32 bytesA, u8 *T, int bytesT)
{
	return GCM_AES_EncryptAndAuthenticate(ctx, NULL, 0, A, bytesA, NULL, T, bytesT);
}
