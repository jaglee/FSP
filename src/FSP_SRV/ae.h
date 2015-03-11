/* ---------------------------------------------------------------------------
 *
 * AEAD API 0.12 - 23-MAY-2012
 *
 * This file gives an interface appropriate for many authenticated
 * encryption with associated data (AEAD) implementations. It does not try
 * to accommodate all possible options or limitations that an implementation
 * might have -- you should consult the documentation of your chosen
 * implementation to find things like RFC 5116 constants, alignment
 * requirements, whether the incremental interface is supported, etc.
 *
 * This file is in the public domain. It is provided "as is", without
 * warranty of any kind. Use at your own risk.
 *
 * Comments are welcome: Ted Krovetz <ted@krovetz>.
 *
 * ------------------------------------------------------------------------ */

#ifndef _AE_H_
#define _AE_H_


/* ----------------------------------------------------------------------- */
/* User configuration options                                              */
/* ----------------------------------------------------------------------- */

/* Set the AES key length to use and length of authentication tag to produce.
/  Setting either to 0 requires the value be set at runtime via ae_init().
/  Some optimizations occur for each when set to a fixed value.            */
#define OCB_KEY_LEN         16  /* 0, 16, 24 or 32. 0 means set in ae_init */
#define OCB_TAG_LEN         8	/* 0 to 16. 0 means set in ae_init         */

/* This implementation has built-in support for multiple AES APIs. Set any
/  one of the following to non-zero to specify which to use.               */
#define USE_OPENSSL_AES      0  /* http://openssl.org                      */
#define USE_REFERENCE_AES    1  /* Internet search: rijndael-alg-fst.c     */
#define USE_AES_NI           0  /* Uses compiler's intrinsics              */

/* During encryption and decryption, various "L values" are required.
/  The L values can be precomputed during initialization (requiring extra
/  space in ae_ctx), generated as needed (slightly slowing encryption and
/  decryption), or some combination of the two. L_TABLE_SZ specifies how many
/  L values to precompute. L_TABLE_SZ must be at least 3. L_TABLE_SZ*16 bytes
/  are used for L values in ae_ctx. Plaintext and ciphertexts shorter than
/  2^L_TABLE_SZ blocks need no L values calculated dynamically.            */
#define L_TABLE_SZ          16

/* Set L_TABLE_SZ_IS_ENOUGH non-zero iff you know that all plaintexts
/  will be shorter than 2^(L_TABLE_SZ+4) bytes in length. This results
/  in better performance.                                                  */
#define L_TABLE_SZ_IS_ENOUGH 1


/* Define standard sized integers                                          */
#if defined(_MSC_VER) && (_MSC_VER < 1600)
	typedef unsigned __int8  uint8_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef          __int64 int64_t;
#else
	#include <stdint.h>
#endif

/* Compiler-specific intrinsics and fixes: bswap64, ntz                    */
#if _MSC_VER
	#define inline __inline        /* MSVC doesn't recognize "inline" in C */
	#define restrict __restrict  /* MSVC doesn't recognize "restrict" in C */
    #define __SSE2__   (_M_IX86 || _M_AMD64 || _M_X64)    /* Assume SSE2  */
    #define __SSSE3__  (_M_IX86 || _M_AMD64 || _M_X64)    /* Assume SSSE3 */
	#include <intrin.h>
	#pragma intrinsic(_byteswap_uint64, _BitScanForward, memcpy)
	#define bswap64(x) _byteswap_uint64(x)
	static inline unsigned long ntz(unsigned long x) { _BitScanForward(&x, x); return x; }
#elif __GNUC__
	#define inline __inline__            /* No "inline" in GCC ansi C mode */
	#define restrict __restrict__      /* No "restrict" in GCC ansi C mode */
	#define bswap64(x) __builtin_bswap64(x)           /* Assuming GCC 4.3+ */
	#define ntz(x)     __builtin_ctz((unsigned)(x))   /* Assuming GCC 3.4+ */
#else              /* Assume some C99 features: stdint.h, inline, restrict */
	#define bswap32(x)                                              \
	   ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
		(((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))

	 static inline uint64_t bswap64(uint64_t x) {
		union { uint64_t u64; uint32_t u32[2]; } in, out;
		in.u64 = x;
		out.u32[0] = bswap32(in.u32[1]);
		out.u32[1] = bswap32(in.u32[0]);
		return out.u64;
	}

	#if (L_TABLE_SZ <= 9) && (L_TABLE_SZ_IS_ENOUGH)   /* < 2^13 byte texts */
	static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[] = {0,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,7,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,8,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,7,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2};
		return tz_table[x/4];
	}
	#else       /* From http://supertech.csail.mit.edu/papers/debruijn.pdf */
	static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[32] =
		{ 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
		 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
		return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
	}
	#endif
#endif

/* ----------------------------------------------------------------------- */
/* Define blocks and operations -- Patch if incorrect on your compiler.    */
/* ----------------------------------------------------------------------- */

#if __SSE2__
    #include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
    #include <emmintrin.h>              /* SSE2 instructions               */
    typedef __m128i block;
    #define xor_block(x,y)        _mm_xor_si128(x,y)
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__ || USE_AES_NI
    #include <tmmintrin.h>              /* SSSE3 instructions              */
    #define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))
	#else
    static inline block swap_if_le(block b) {
		block a = _mm_shuffle_epi32  (b, _MM_SHUFFLE(0,1,2,3));
		a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2,3,0,1));
		a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2,3,0,1));
		return _mm_xor_si128(_mm_srli_epi16(a,8), _mm_slli_epi16(a,8));
    }
	#endif
	static inline block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		block hi = _mm_load_si128((__m128i *)(KtopStr+0));   /* hi = B A */
		block lo = _mm_loadu_si128((__m128i *)(KtopStr+1));  /* lo = C B */
		__m128i lshift = _mm_cvtsi32_si128(bot);
		__m128i rshift = _mm_cvtsi32_si128(64-bot);
		lo = _mm_xor_si128(_mm_sll_epi64(hi,lshift),_mm_srl_epi64(lo,rshift));
		#if __SSSE3__ || USE_AES_NI
		return _mm_shuffle_epi8(lo,_mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7));
		#else
		return swap_if_le(_mm_shuffle_epi32(lo, _MM_SHUFFLE(1,0,3,2)));
		#endif
	}
	static inline block double_block(block bl) {
		const __m128i mask = _mm_set_epi32(135,1,1,1);
		__m128i tmp = _mm_srai_epi32(bl, 31);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
		bl = _mm_slli_epi32(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}
#elif __ALTIVEC__
    #include <altivec.h>
    typedef vector unsigned block;
    #define xor_block(x,y)         vec_xor(x,y)
    #define zero_block()           vec_splat_u32(0)
    #define unequal_blocks(x,y)    vec_any_ne(x,y)
    #define swap_if_le(b)          (b)
	#if __PPC64__
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		union {uint64_t u64[2]; block bl;} rval;
		rval.u64[0] = (KtopStr[0] << bot) | (KtopStr[1] >> (64-bot));
		rval.u64[1] = (KtopStr[1] << bot) | (KtopStr[2] >> (64-bot));
        return rval.bl;
	}
	#else
	/* Special handling: Shifts are mod 32, and no 64-bit types */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		const vector unsigned k32 = {32,32,32,32};
		vector unsigned hi = *(vector unsigned *)(KtopStr+0);
		vector unsigned lo = *(vector unsigned *)(KtopStr+2);
		vector unsigned bot_vec;
		if (bot < 32) {
			lo = vec_sld(hi,lo,4);
		} else {
			vector unsigned t = vec_sld(hi,lo,4);
			lo = vec_sld(hi,lo,8);
			hi = t;
			bot = bot - 32;
		}
		if (bot == 0) return hi;
		*(unsigned *)&bot_vec = bot;
		vector unsigned lshift = vec_splat(bot_vec,0);
		vector unsigned rshift = vec_sub(k32,lshift);
		hi = vec_sl(hi,lshift);
		lo = vec_sr(lo,rshift);
		return vec_xor(hi,lo);
	}
	#endif
	static inline block double_block(block b) {
		const vector unsigned char mask = {135,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		const vector unsigned char perm = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0};
		const vector unsigned char shift7  = vec_splat_u8(7);
		const vector unsigned char shift1  = vec_splat_u8(1);
		vector unsigned char c = (vector unsigned char)b;
		vector unsigned char t = vec_sra(c,shift7);
		t = vec_and(t,mask);
		t = vec_perm(t,t,perm);
		c = vec_sl(c,shift1);
		return (block)vec_xor(c,t);
	}
#elif __ARM_NEON__
    #include <arm_neon.h>
    typedef int8x16_t block;      /* Yay! Endian-neutral reads! */
    #define xor_block(x,y)             veorq_s8(x,y)
    #define zero_block()               vdupq_n_s8(0)
    static inline int unequal_blocks(block a, block b) {
		int64x2_t t=veorq_s64((int64x2_t)a,(int64x2_t)b);
		return (vgetq_lane_s64(t,0)|vgetq_lane_s64(t,1))!=0;
    }
    #define swap_if_le(b)          (b)  /* Using endian-neutral int8x16_t */
	/* KtopStr is reg correct by 64 bits, return mem correct */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		const union { unsigned x; unsigned char endian; } little = { 1 };
		const int64x2_t k64 = {-64,-64};
		uint64x2_t hi = *(uint64x2_t *)(KtopStr+0);   /* hi = A B */
		uint64x2_t lo = *(uint64x2_t *)(KtopStr+1);   /* hi = B C */
		int64x2_t ls = vdupq_n_s64(bot);
		int64x2_t rs = vqaddq_s64(k64,ls);
		block rval = (block)veorq_u64(vshlq_u64(hi,ls),vshlq_u64(lo,rs));
		if (little.endian)
			rval = vrev64q_s8(rval);
		return rval;
	}
	static inline block double_block(block b)
	{
		const block mask = {135,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		block tmp = vshrq_n_s8(b,7);
		tmp = vandq_s8(tmp, mask);
		tmp = vextq_s8(tmp, tmp, 1);  /* Rotate high byte to end */
		b = vshlq_n_s8(b,1);
		return veorq_s8(tmp,b);
	}
#else
    typedef struct { uint64_t l,r; } block;
    static inline block xor_block(block x, block y) {
    	x.l^=y.l; x.r^=y.r; return x;
    }
    static inline block zero_block(void) { const block t = {0,0}; return t; }
    #define unequal_blocks(x, y)         ((((x).l^(y).l)|((x).r^(y).r)) != 0)
    static inline block swap_if_le(block b) {
		const union { unsigned x; unsigned char endian; } little = { 1 };
    	if (little.endian) {
    		block r;
    		r.l = bswap64(b.l);
    		r.r = bswap64(b.r);
    		return r;
    	} else
    		return b;
    }

	/* KtopStr is reg correct by 64 bits, return mem correct */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
        block rval;
        if (bot != 0) {
			rval.l = (KtopStr[0] << bot) | (KtopStr[1] >> (64-bot));
			rval.r = (KtopStr[1] << bot) | (KtopStr[2] >> (64-bot));
		} else {
			rval.l = KtopStr[0];
			rval.r = KtopStr[1];
		}
        return swap_if_le(rval);
	}

	#if __GNUC__ && __arm__
	static inline block double_block(block b) {
		__asm__ ("adds %1,%1,%1\n\t"
				 "adcs %H1,%H1,%H1\n\t"
				 "adcs %0,%0,%0\n\t"
				 "adcs %H0,%H0,%H0\n\t"
				 "it cs\n\t"
				 "eorcs %1,%1,#135"
		: "+r"(b.l), "+r"(b.r) : : "cc");
		return b;
	}
	#else
	static inline block double_block(block b) {
		uint64_t t = (uint64_t)((int64_t)b.l >> 63);
		b.l = (b.l + b.l) ^ (b.r >> 63);
		b.r = (b.r + b.r) ^ (t & 135);
		return b;
	}
	#endif

#endif

/*---------------*/
#if USE_OPENSSL_AES
/*---------------*/

#include <openssl/aes.h>                            /* http://openssl.org/ */

#define BPI 4  /* Number of blocks in buffer per ECB call */

/*-------------------*/
#elif USE_REFERENCE_AES
/*-------------------*/

#include "../rijndael-alg-fst.h"              /* Barreto's Public-Domain Code */
#if (OCB_KEY_LEN == 0)
	typedef struct { uint32_t rd_key[60]; int rounds; } AES_KEY;
	#define ROUNDS(ctx) ((ctx)->rounds)
	#define AES_set_encrypt_key(x, y, z) \
	 do {rijndaelKeySetupEnc((z)->rd_key, x, y); (z)->rounds = y/32+6;} while (0)
	#define AES_set_decrypt_key(x, y, z) \
	 do {rijndaelKeySetupDec((z)->rd_key, x, y); (z)->rounds = y/32+6;} while (0)
#else
	typedef struct { uint32_t rd_key[OCB_KEY_LEN+28]; } AES_KEY;
	#define ROUNDS(ctx) (6+OCB_KEY_LEN/4)
	#define AES_set_encrypt_key(x, y, z) rijndaelKeySetupEnc((z)->rd_key, x, y)
	#define AES_set_decrypt_key(x, y, z) rijndaelKeySetupDec((z)->rd_key, x, y)
#endif
#define AES_encrypt(x,y,z) rijndaelEncrypt((z)->rd_key, ROUNDS(z), x, y)
#define AES_decrypt(x,y,z) rijndaelDecrypt((z)->rd_key, ROUNDS(z), x, y)

#define BPI 4  /* Number of blocks in buffer per ECB call */


/*----------*/
#elif USE_AES_NI
/*----------*/

#include <wmmintrin.h>

#if (OCB_KEY_LEN == 0)
	typedef struct { __m128i rd_key[15]; int rounds; } AES_KEY;
	#define ROUNDS(ctx) ((ctx)->rounds)
#else
	typedef struct { __m128i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY;
	#define ROUNDS(ctx) (6+OCB_KEY_LEN/4)
#endif


#define BPI 8  /* Number of blocks in buffer per ECB call   */
               /* Set to 4 for Westmere, 8 for Sandy Bridge */

#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------- */
/* Define OCB context structure.                                           */
/* ----------------------------------------------------------------------- */

/*------------------------------------------------------------------------
/ Each item in the OCB context is stored either "memory correct" or
/ "register correct". On big-endian machines, this is identical. On
/ little-endian machines, one must choose whether the byte-string
/ is in the correct order when it resides in memory or in registers.
/ It must be register correct whenever it is to be manipulated
/ arithmetically, but must be memory correct whenever it interacts
/ with the plaintext or ciphertext.
/------------------------------------------------------------------------- */

struct _ae_ctx {
    block offset;                          /* Memory correct               */
    block checksum;                        /* Memory correct               */
    block Lstar;                           /* Memory correct               */
    block Ldollar;                         /* Memory correct               */
    block L[L_TABLE_SZ];                   /* Memory correct               */
    block ad_checksum;                     /* Memory correct               */
    block ad_offset;                       /* Memory correct               */
    block cached_Top;                      /* Memory correct               */
	uint64_t KtopStr[3];                   /* Register correct, each item  */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    AES_KEY decrypt_key;
    AES_KEY encrypt_key;
    #if (OCB_TAG_LEN == 0)
    unsigned tag_len;
    #endif
};

/* --------------------------------------------------------------------------
 *
 * Constants
 *
 * ----------------------------------------------------------------------- */

/* Return status codes: Negative return values indicate an error occurred.
 * For full explanations of error values, consult the implementation's
 * documentation.                                                          */
#define AE_SUCCESS       ( 0)  /* Indicates successful completion of call  */
#define AE_INVALID       (-1)  /* Indicates bad tag during decryption      */
#define AE_NOT_SUPPORTED (-2)  /* Indicates unsupported option requested   */

/* Flags: When data can be processed "incrementally", these flags are used
 * to indicate whether the submitted data is the last or not.               */
#define AE_FINALIZE      (1)   /* This is the last of data                  */
#define AE_PENDING       (0)   /* More data of is coming                    */

/* --------------------------------------------------------------------------
 *
 * AEAD opaque structure definition
 *
 * ----------------------------------------------------------------------- */

typedef struct _ae_ctx ae_ctx;

/* --------------------------------------------------------------------------
 *
 * Data Structure Routines
 *
 * ----------------------------------------------------------------------- */

ae_ctx* ae_allocate  (void *misc);  /* Allocate ae_ctx, set optional ptr   */
void    ae_free      (ae_ctx *ctx); /* Deallocate ae_ctx struct            */
int     ae_clear     (ae_ctx *ctx); /* Undo initialization                 */
int     ae_ctx_sizeof(void);        /* Return sizeof(ae_ctx)               */
/* ae_allocate() allocates an ae_ctx structure, but does not initialize it.
 * ae_free() deallocates an ae_ctx structure, but does not zero it.
 * ae_clear() zeroes sensitive values associated with an ae_ctx structure
 * and deallocates any auxiliary structures allocated during ae_init().
 * ae_ctx_sizeof() returns sizeof(ae_ctx), to aid in any static allocations.
 */

/* --------------------------------------------------------------------------
 *
 * AEAD Routines
 *
 * ----------------------------------------------------------------------- */

int ae_init(ae_ctx     *ctx,
            const void *key,
            int         key_len,
            int         nonce_len,
            int         tag_len);
/* --------------------------------------------------------------------------
 *
 * Initialize an ae_ctx context structure.
 *
 * Parameters:
 *  ctx       - Pointer to an ae_ctx structure to be initialized
 *  key       - Pointer to user-supplied key
 *  key_len   - Length of key supplied, in bytes
 *  nonce_len - Length of nonces to be used for this key, in bytes
 *  tag_len   - Length of tags to be produced for this key, in bytes
 *
 * Returns:
 *  AE_SUCCESS       - Success. Ctx ready for use.
 *  AE_NOT_SUPPORTED - An unsupported length was supplied. Ctx is untouched.
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * ----------------------------------------------------------------------- */

int ae_encrypt(ae_ctx     *ctx,
               const void *nonce,
               const void *pt,
               int         pt_len,
               const void *ad,
               int         ad_len,
               void       *ct,
               void       *tag,
               int         final);
/* --------------------------------------------------------------------------
 *
 * Encrypt plaintext; provide for authentication of ciphertext/associated data.
 *
 * Parameters:
 *  ctx    - Pointer to an ae_ctx structure initialized by ae_init.
 *  nonce  - Pointer to a nonce_len (defined in ae_init) byte nonce.
 *  pt     - Pointer to plaintext bytes to be encrypted.
 *  pt_len - number of bytes pointed to by pt.
 *  ad     - Pointer to associated data.
 *  ad_len - number of bytes pointed to by ad.
 *  ct     - Pointer to buffer to receive ciphertext encryption.
 *  tag    - Pointer to receive authentication tag; or NULL
 *           if tag is to be bundled into the ciphertext.
 *  final  - Non-zero if this call completes the plaintext being encrypted.
 *
 * If nonce!=NULL then a message is being initiated. If final!=0
 * then a message is being finalized. If final==0 or nonce==NULL
 * then the incremental interface is being used. If nonce!=NULL and
 * ad_len<0, then use same ad as last message.
 *
 * Returns:
 *  non-negative     - Number of bytes written to ct.
 *  AE_NOT_SUPPORTED - Usage mode unsupported (eg, incremental and/or sticky).
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * ----------------------------------------------------------------------- */

int ae_decrypt(ae_ctx     *ctx,
               const void *nonce,
               const void *ct,
               int         ct_len,
               const void *ad,
               int         ad_len,
               void       *pt,
               const void *tag,
               int         final);
/* --------------------------------------------------------------------------
 *
 * Decrypt ciphertext; provide authenticity of plaintext and associated data.
 *
 * Parameters:
 *  ctx    - Pointer to an ae_ctx structure initialized by ae_init.
 *  nonce  - Pointer to a nonce_len (defined in ae_init) byte nonce.
 *  ct     - Pointer to ciphertext bytes to be decrypted.
 *  ct_len - number of bytes pointed to by ct.
 *  ad     - Pointer to associated data.
 *  ad_len - number of bytes pointed to by ad.
 *  pt     - Pointer to buffer to receive plaintext decryption.
 *  tag    - Pointer to tag_len (defined in ae_init) bytes; or NULL
 *           if tag is bundled into the ciphertext. Non-NULL tag is only
 *           read when final is non-zero.
 *  final  - Non-zero if this call completes the ciphertext being decrypted.
 *
 * If nonce!=NULL then "ct" points to the start of a ciphertext. If final!=0
 * then "in" points to the final piece of ciphertext. If final==0 or nonce==
 * NULL then the incremental interface is being used. If nonce!=NULL and
 * ad_len<0, then use same ad as last message.
 *
 * Returns:
 *  non-negative     - Number of bytes written to pt.
 *  AE_INVALID       - Authentication failure.
 *  AE_NOT_SUPPORTED - Usage mode unsupported (eg, incremental and/or sticky).
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * NOTE !!! NOTE !!! -- The ciphertext should be assumed possibly inauthentic
 *                      until it has been completely written and it is
 *                      verified that this routine did not return AE_INVALID.
 *
 * ----------------------------------------------------------------------- */

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* _AE_H_ */
