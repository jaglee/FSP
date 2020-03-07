/**
 * Copyright (c) 2013 Jason Gao <jagao@outlook.com>
 * Inspired by original work of Mike Belopuhov <mike@vantronix.net>
 * This code implements Galois/Counter Mode using the AES cipher as to description of FIPS SP 800-38D
 * with certain limitations
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

#include "../Intrins.h"
#include "rijndael-alg-fst.h"

#define GCM_BLOCK_LEN		16
#define GCM_IV_LEN_FIXED	12
#define GCM_BLOCK_LEN_POWER 4	// 2^^4 == 16
#define GMAC_SALT_LEN		4	// As of RFC4543

typedef struct _GCM_AES_CTX {
	uint32_t	K[4*(RIJNDAEL_MAXNR + 1)];
	uint8_t		H[GCM_BLOCK_LEN];	/* hash subkey */
	uint8_t		X[GCM_BLOCK_LEN];	/* to X<m+n+1> */
	uint8_t		J[GCM_BLOCK_LEN];	/* counter block */
	int32_t		rounds;
} GCM_AES_CTX;

#ifdef __cplusplus
extern "C" {
#endif

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	const octet *	octet array representation of AES key
//	int				length in bytes of the key, must be 16, 24, 32 (without salt) or 20, 28, 40 (with salt)
void	GCM_AES_SetKey(GCM_AES_CTX *, const octet *, int);

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	uint32_t	*	the non-default salt
// Do
//	Set the internal salt to the given value XOR with the origin value
// Return
//	The original salt
// Remark
//	The salt is the leftmost 32-bit of the 96-bit IV. The value is just a bit string of length 32
uint32_t GCM_AES_XorSalt(GCM_AES_CTX *, uint32_t);


// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	uint64_t		the rightmost 64-bit of the 96-bit initial vector
//	const octet *	P, byte array representation of the plaintext
//	uint32_t		length in bytes of the plaintext
//	const uint64_t* byte array representation of the additional authentication data
//	uint32_t		length in bytes of the additional authentication data
//	uint64_t*		placeholder of the ciphertext. the buffer size maynot be less than bytesP
//	octet *			placeholder of the tag(secure digest). the buffe size MAYNOT be less than bytesT
//	int				capacity in byte of the tag buffer
// Do
//	Encrypt the plaintext into ciphertext, store the ciphertext into the buffer specified by C
//	and calculte the authenticate tag, store the tag into the buffer specified by T 
// Return
//	-2 if parameter error
//  0 if success
// Remark
//	The additional authenticated data and the output buffer must be aligned on 64-bit border
//	a 32-bit per-session pseudo-random salt is automatically prefixed to IV internally
int	GCM_AES_AuthenticatedEncrypt(GCM_AES_CTX *ctx, uint64_t IV
								, const octet *P, uint32_t bytesP
								, const uint64_t *aad, uint32_t bytesA
								, uint64_t *bufCipherText	// capacity of ciphertext buffer MUST be no less than bytesP
								, octet *T, int bytesT
								);

// Given
//	GCM_AES_CTX *	pointer to the GCM context
//	uint64_t		the rightmost 64-bit of the 96-bit initial vector
//	const octet *C, byte array representation of the ciphertext
//	uint32_t		length in bytes of the ciphertext
//	const uint64_t* byte array representation of the additional authentication data
//	uint32_t		length in bytes of the additional authentication data
//	const octet *	byte array representation of the tag(secure digest)
//	int				length in bytes of the tag
//	uint64_t*		placeholder of the plaintext. the buffer size MAY NOT be less than bytesC
// Do
//	Authenticate the ciphertext, the additional data and the tag, if success
//	decrypt and store the ciphertext into the buffer specified by C
// Return
//	-2 if parameter error
//	-1 if authentication failed
//  0 if success
// Remark
//	The additional authenticated data and the output buffer must be aligned on 64-bit border
//	a 32-bit per-session pseudo-random salt is automatically prefixed to IV internally
int	GCM_AES_AuthenticateAndDecrypt(GCM_AES_CTX *ctx, uint64_t IV
									, const octet *C, uint32_t bytesC
									, const uint64_t *aad, uint32_t bytesA
									, const octet *T, int bytesT
									, uint64_t *bufPlainText	// capacity of plaintext buffer MUST be no less than bytesC
									);

#ifdef __cplusplus
}
#endif


/* ----------------------------------------------------------------------- *
 * The following routines are used in this implementation. They are
 * written via macros to simulate zero-overhead call-by-reference.
 * All have default implemantations for when they are not defined in an
 * architecture-specific manner.
 *
 * MUL64: 64x64->128-bit multiplication
 * PMUL64: assumes top bits cleared on inputs
 * ADD128: 128x128->128-bit addition
 * GET_REVERSED_64: load and byte-reverse 64-bit word  
 * GET_REVERSED_32: load and byte-reverse 32-bit word (added by Jason Gao)
 * ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
#if (__GNUC__ && (__x86_64__ || __amd64__))
/* ----------------------------------------------------------------------- */

#define ADD128(rh,rl,ih,il)                                               \
    asm ("addq %3, %1 \n\t"                                               \
         "adcq %2, %0"                                                    \
    : "+r"(rh),"+r"(rl)                                                   \
    : "r"(ih),"r"(il) : "cc");

#define MUL64(rh,rl,i1,i2)                                                \
    asm ("mulq %3" : "=a"(rl), "=d"(rh) : "a"(i1), "r"(i2) : "cc")

#define PMUL64 MUL64

#define GET_REVERSED_64(p)                                                \
    ({uint64_t x;                                                         \
     asm ("bswapq %0" : "=r" (x) : "0"(*(uint64_t *)(p))); x;})

#define GET_REVERSED_32(p)                                                \
    ({uint32_t x;                                                         \
     asm ("bswap %0" : "=r" (x) : "0"(*(uint32_t *)(p))); x;})

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && __i386__)
/* ----------------------------------------------------------------------- */

#define GET_REVERSED_64(p)                                                \
    ({ uint64_t x;                                                        \
    uint32_t *tp = (uint32_t *)(p);                                       \
    asm  ("bswap %%edx\n\t"                                               \
          "bswap %%eax"                                                   \
    : "=A"(x)                                                             \
    : "a"(tp[1]), "d"(tp[0]));                                            \
    x; })

#define GET_REVERSED_32(p)                                                \
    ({uint32_t x;                                                         \
     asm ("bswap %0" : "=r" (x) : "0"(*(uint32_t *)(p))); x;})

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && __ppc64__)
/* ----------------------------------------------------------------------- */

#define ADD128(rh,rl,ih,il)                                               \
    asm volatile (  "addc %1, %1, %3 \n\t"                                \
                    "adde %0, %0, %2"                                     \
    : "+r"(rh),"+r"(rl)                                                   \
    : "r"(ih),"r"(il));

#define MUL64(rh,rl,i1,i2)                                                \
{ uint64_t _i1 = (i1), _i2 = (i2);                                        \
    rl = _i1 * _i2;                                                       \
    asm volatile ("mulhdu %0, %1, %2" : "=r" (rh) : "r" (_i1), "r" (_i2));\
}

#define PMUL64 MUL64

#define GET_REVERSED_64(p)                                                \
    ({ uint32_t hi, lo, *_p = (uint32_t *)(p);                            \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(hi) : "b%"(4), "r"(_p) );  \
       ((uint64_t)hi << 32) | (uint64_t)lo; } )

#define GET_REVERSED_32(p)                                                \
    ({ uint32_t lo, *_p = (uint32_t *)(p);								  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       lo; } )

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && (__ppc__ || __PPC__))
/* ----------------------------------------------------------------------- */

#define GET_REVERSED_64(p)                                                \
    ({ uint32_t hi, lo, *_p = (uint32_t *)(p);                            \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(hi) : "b%"(4), "r"(_p) );  \
       ((uint64_t)hi << 32) | (uint64_t)lo; } )

#define GET_REVERSED_32(p)                                                \
    ({ uint32_t lo, *_p = (uint32_t *)(p);								  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       lo; } )

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && (__ARMEL__ || __ARM__))
/* ----------------------------------------------------------------------- */

#define bswap32(v)                                                        \
({ uint32_t tmp,out;                                                      \
    asm volatile(                                                         \
        "eor    %1, %2, %2, ror #16\n"                                    \
        "bic    %1, %1, #0x00ff0000\n"                                    \
        "mov    %0, %2, ror #8\n"                                         \
        "eor    %0, %0, %1, lsr #8"                                       \
    : "=r" (out), "=&r" (tmp)                                             \
    : "r" (v));                                                           \
    out;})

/* ----------------------------------------------------------------------- */
#elif _MSC_VER
/* ----------------------------------------------------------------------- */

#include <intrin.h>

#if (_M_IA64 || _M_X64) && \
    (!defined(__INTEL_COMPILER) || __INTEL_COMPILER >= 1000)
#define MUL64(rh,rl,i1,i2)   (rl) = _umul128(i1,i2,&(rh));
#pragma intrinsic(_umul128)
#define PMUL64 MUL64
#endif

/* MSVC uses add, adc in this version */
#define ADD128(rh,rl,ih,il)                                          \
    {   uint64_t _il = (il);                                         \
        (rl) += (_il);                                               \
        (rh) += (ih) + ((rl) < (_il));                               \
    }

#if _MSC_VER >= 1300
#define GET_REVERSED_64(p) _byteswap_uint64(*(uint64_t *)(p))
#define GET_REVERSED_32(p) _byteswap_ulong(*(uint32_t *)(p))
#pragma intrinsic(_byteswap_uint64, _byteswap_ulong)
#endif

#if _MSC_VER >= 1400 && \
    (!defined(__INTEL_COMPILER) || __INTEL_COMPILER >= 1000)
#define MUL32(i1,i2)    (__emulu((uint32_t)(i1),(uint32_t)(i2)))
#pragma intrinsic(__emulu)
#endif

/* ----------------------------------------------------------------------- */
#endif
/* ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* Default implementations, if not defined above                           */
/* ----------------------------------------------------------------------- */

#ifndef ADD128
#define ADD128(rh,rl,ih,il)                                              \
    {   uint64_t _il = (il);                                             \
        (rl) += (_il);                                                   \
        if ((rl) < (_il)) (rh)++;                                        \
        (rh) += (ih);                                                    \
    }
#endif

#ifndef MUL32
#define MUL32(i1,i2)    ((uint64_t)(uint32_t)(i1)*(uint32_t)(i2))
#endif

#ifndef PMUL64              /* rh may not be same as i1 or i2 */
#define PMUL64(rh,rl,i1,i2) /* Assumes m doesn't overflow     */         \
    {   uint64_t _i1 = (i1), _i2 = (i2);                                 \
        uint64_t m = MUL32(_i1,_i2>>32) + MUL32(_i1>>32,_i2);            \
        rh         = MUL32(_i1>>32,_i2>>32);                             \
        rl         = MUL32(_i1,_i2);                                     \
        ADD128(rh,rl,(m >> 32),(m << 32));                               \
    }
#endif

#ifndef MUL64
#define MUL64(rh,rl,i1,i2)                                               \
    {   uint64_t _i1 = (i1), _i2 = (i2);                                 \
        uint64_t m1= MUL32(_i1,_i2>>32);                                 \
        uint64_t m2= MUL32(_i1>>32,_i2);                                 \
        rh         = MUL32(_i1>>32,_i2>>32);                             \
        rl         = MUL32(_i1,_i2);                                     \
        ADD128(rh,rl,(m1 >> 32),(m1 << 32));                             \
        ADD128(rh,rl,(m2 >> 32),(m2 << 32));                             \
    }
#endif

#ifndef GET_REVERSED_64
#ifndef bswap64
#ifndef bswap32
#define bswap32(x)                                                        \
  ({ uint32_t bsx = (x);                                                  \
      ((((bsx) & 0xff000000u) >> 24) | (((bsx) & 0x00ff0000u) >>  8) |    \
       (((bsx) & 0x0000ff00u) <<  8) | (((bsx) & 0x000000ffu) << 24)); })
#endif
#define bswap64(x)                                                        \
     ({ union { uint64_t ll; uint32_t l[2]; } w, r;                       \
         w.ll = (x);                                                      \
         r.l[0] = bswap32 (w.l[1]);                                       \
         r.l[1] = bswap32 (w.l[0]);                                       \
         r.ll; })
#endif
#define GET_REVERSED_64(p) bswap64(*(uint64_t *)(p)) 
#define GET_REVERSED_32(p) bswap32(*(uint32_t *)(p))
#endif


#endif /* _GMAC_H_ */