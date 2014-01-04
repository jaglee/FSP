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

#ifndef _GCM_AES_H_
#define _GCM_AES_H_

#include "rijndael-alg-fst.h"

// assume the compiler support 64-bit integer. and it is assumed that the operand is properly alligned
#ifndef htobe64

#if !defined(_MSC_VER) || !defined(_M_IA64) && !defined(_M_X64) && (!defined(_M_IX86) || _MSC_VER < 1400)
#define _DWORD_SWAP(l)                \
        ( ( ((l) >> 24) & 0x000000FFL ) |       \
            ( ((l) >>  8) & 0x0000FF00L ) |       \
            ( ((l) <<  8) & 0x00FF0000L ) |       \
            ( ((l) << 24) & 0xFF000000L ) )

#define _QWORD_SWAP(l)            \
        ( ( ((l) >> 56) & 0x00000000000000FFLL ) |       \
            ( ((l) >> 40) & 0x000000000000FF00LL ) |       \
            ( ((l) >> 24) & 0x0000000000FF0000LL ) |       \
            ( ((l) >>  8) & 0x00000000FF000000LL ) |       \
            ( ((l) <<  8) & 0x000000FF00000000LL ) |       \
            ( ((l) << 24) & 0x0000FF0000000000LL ) |       \
            ( ((l) << 40) & 0x00FF000000000000LL ) |       \
            ( ((l) << 56) & 0xFF00000000000000LL ) )

__inline u32 be32toh(u32 v) 
{ 
	return _DWORD_SWAP(v);
}

__inline u32 htobe32(u32 v)
{ 
	return _DWORD_SWAP(v);
}


__inline u64 be64toh(u64 v) 
{ 
	return _QWORD_SWAP(v);
}

__inline u64 htobe64(u64 v) 
{ 
	return _QWORD_SWAP(v);
}
#else

#pragma intrinsic(_byteswap_ushort, _byteswap_ulong, _byteswap_uint64)
#define be16toh(v) _byteswap_ushort(v)
#define htobe16(v) _byteswap_ushort(v)
#define be32toh(v) _byteswap_ulong(v)
#define htobe32(v) _byteswap_ulong(v)
#define be64toh(v) _byteswap_uint64(v)
#define htobe64(v) _byteswap_uint64(v)

#endif

#endif

#define GCM_BLOCK_LEN		16
#define GCM_IV_LEN_FIXED	12
#define GCM_BLOCK_LEN_POWER 4	// 2^^4 == 16
#define GMAC_SALT_LEN		4	// As of RFC4543

typedef long long i64;
typedef unsigned long long u64;

typedef struct _GCM_AES_CTX {
	u32	K[4*(RIJNDAEL_MAXNR + 1)];
	u8	H[GCM_BLOCK_LEN];	/* hash subkey */
	u8	X[GCM_BLOCK_LEN];	/* to X<m+n+1> */
	u8	J[GCM_BLOCK_LEN];	/* counter block */
	int	rounds;
} GCM_AES_CTX;

#ifdef __cplusplus
extern "C" {
#endif

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const u8 *		byte array representation of AES key
//	int				length in bytes of the key, must be 16, 24 or 32
//	const u8 *		byte array representation of initial vector, must of 96-bit
// Do
//	Initialize the Galois/Counter Mode AES context, including deriving the hash sub-key
//	so that successive AE operation is feasible
void	GCM_AES_Init(GCM_AES_CTX *, const u8 *, int, const u8 *);

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const u8 *		byte array representation of AES key AND the salt, as of RFC4543
//	int				length in bytes of the key, must be 20, 28 or 36
// Do
//	Initialize the Galois/Counter Mode AES-GMAC context, including deriving the hash sub-key
//	so that successive AE/GMAC operation is feasible
void	GMAC_InitWithKey(GCM_AES_CTX *, const u8 *, int);


// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const u8 *		byte array representation of initial vector, must be of 64-bit, as of RFC4543
// Do
//	Set IV of the Galois/Counter Mode AES-GMAC context
void	GMAC_SetIV(GCM_AES_CTX *, const u8 *);


// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const u8 * P	byte array representation of the plaintext
//	u32 bytesP		length in bytes of the plaintext
//	const u8 * A	byte array representation of the additional authentication data
//	u32 bytesA		length in bytes of the additional authentication data
//	u8 * C			placeholder of the ciphertext. the buffer size maynot be less than bytesP
//	u8 * T			placeholder of the tag(secure digest). the buffe size MAYNOT be less than bytesT
//	int bytesT		capacity in byte of the tag buffer
// Do
//	Encrypt the plaintext into ciphertext, store the ciphertext into the buffer specified by C
//	and calculte the authenticate tag, store the tag into the buffer specified by T 
// Return
//	-2 if parameter error
//  0 if success
int		GCM_AES_EncryptAndAuthenticate(GCM_AES_CTX *ctx
									, const u8 *P, u32 bytesP
									, const u8 *A, u32 bytesA
									, u8 *C	// capacity of ciphertext buffer MUST be no less than bytesP
									, u8 *T, int bytesT
									);

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const u8 * C	byte array representation of the ciphertext
//	u32 bytesC		length in bytes of the ciphertext
//	const u8 * A	byte array representation of the additional authentication data
//	u32 bytesA		length in bytes of the additional authentication data
//	const u8 * T	byte array representation of the tag(secure digest)
//	int bytesT		length in bytes of the tag
//	u8 * P			placeholder of the plaintext . the buffer size MAYNOT be less than bytesC
// Do
//	Authenticate the ciphertext, the additional data and the tag, if success
//	decrypt and store the ciphertext into the buffer specified by C
// Return
//	-2 if parameter error
//	-1 if authentication failed
//  0 if success
int		GCM_AES_AuthenticatedDecrypt(GCM_AES_CTX *ctx
									, const u8 *C, u32 bytesC
									, const u8 *A, u32 bytesA
									, const u8 *T, int bytesT
									, u8 *P	// capacity of plaintext buffer MUST be no less than bytesC
									);

int		GCM_SecureHash(GCM_AES_CTX *ctx, const u8 *A, u32 bytesA, u8 *T, int bytesT);

#ifdef __cplusplus
}
#endif

#endif /* _GMAC_H_ */