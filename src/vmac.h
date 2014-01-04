#ifndef HEADER_VMAC_H
#define HEADER_VMAC_H

/* --------------------------------------------------------------------------
 * VMAC and VHASH Implementation by Ted Krovetz (tdk@acm.org) and Wei Dai.
 * This implementation is herby placed in the public domain.
 * The authors offers no warranty. Use at your own risk.
 * Please send bug reports to the authors.
 * Last modified: 17 APR 08, 1700 PDT
 * ----------------------------------------------------------------------- */

/**
 * Updated by Jason Gao <jagao@outlook.com>, March 2013
 * The update is herby placed in the public domain without any warranty
 * 
 * 1. We'd like to use either Paulo Barreto's or hardware implementaions but not OpenSSL
 * 2. Adopt stdint.h if compiled under VS2010 or later
 * 3. Implementation of PMUL64, ADD128, get64BE, get64LE, get64PE and their dependents
 *    as well as macro ALIGN, FASTCALL were moved here from vmac.c for sake of code-reuse
 * 4. Add definition of uint16_t on 'stdint.h' is not applicable
 */

/* --------------------------------------------------------------------------
 * User definable settings.
 * ----------------------------------------------------------------------- */
#define VMAC_TAG_LEN   64 /* Must be 64 or 128 - 64 sufficient for most    */
#define VMAC_KEY_LEN  128 /* Must be 128, 192 or 256                       */
#define VMAC_NHBYTES  128 /* Must 2^i for any 3 < i < 13. Standard = 128   */
#define VMAC_PREFER_BIG_ENDIAN  0  /* Prefer non-x86 */

#define VMAC_CACHE_NONCES 0 /* Set to non-zero to cause caching            */
                            /* of consecutive nonces on 64-bit tags        */

/* --------------------------------------------------------------------------
 * This implementation uses uint32_t and uint64_t as names for unsigned 32-
 * and 64-bit integer types. These are defined in C99 stdint.h. The
 * following may need adaptation if you are not running a C99 or
 * Microsoft C environment.
 * ----------------------------------------------------------------------- */
#define VMAC_USE_STDINT 1  /* Set to zero if system has no stdint.h        */
 
#if VMAC_USE_STDINT && (!_MSC_VER || _MSC_VER >= 1600) /* Try stdint.h if non-Microsoft */
#ifdef  __cplusplus
#define __STDC_CONSTANT_MACROS
#endif
#include <stdint.h>
#elif (_MSC_VER)                  /* Microsoft C ealier than VS2010 does not have stdint.h    */
typedef __int32 int32_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#define UINT64_C(v) v ## UI64
#else                             /* Guess sensibly - may need adaptation  */
typedef int int32_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define UINT64_C(v) v ## ULL
#endif

/* --------------------------------------------------------------------------
 * This implementation had been modified slightly by Jason Gao
 * supports only one free AES implementations: Paulo Barreto's
 * the source file (rijndael-alg-fst.c, .h) is inlucded in this distribution
 * ----------------------------------------------------------------------- */

#include "rijndael-alg-fst.h"
typedef u32 aes_int_key[4*(VMAC_KEY_LEN/32+7)];

#define aes_encryption(in,out,int_key)                  \
	    	rijndaelEncrypt((u32 *)(int_key),           \
	                        ((VMAC_KEY_LEN/32)+6),      \
	    				    (u8 *)(in), (u8 *)(out))
#define aes_key_setup(user_key,int_key)                 \
	    	rijndaelKeySetupEnc((u32 *)(int_key),       \
	    	                    (u8 *)(user_key), \
	    	                    VMAC_KEY_LEN)

/* --------------------------------------------------------------------- */

typedef struct {
	uint64_t nhkey  [(VMAC_NHBYTES/8)+2*(VMAC_TAG_LEN/64-1)];
	uint64_t polykey[2*VMAC_TAG_LEN/64];
	uint64_t l3key  [2*VMAC_TAG_LEN/64];
	uint64_t polytmp[2*VMAC_TAG_LEN/64];
	aes_int_key cipher_key;
	#if (VMAC_TAG_LEN == 64) && (VMAC_CACHE_NONCES)
	uint64_t cached_nonce[2];
	uint64_t cached_aes[2];
	#endif
	int first_block_processed;
} vmac_ctx_t;

/* --------------------------------------------------------------------- */
#ifdef  __cplusplus
extern "C" {
#endif
/* --------------------------------------------------------------------------
 *                        <<<<< USAGE NOTES >>>>>
 *
 * Given msg m (mbytes in length) and nonce buffer n
 * this function returns a tag as its output. The tag is returned as
 * a number. When VMAC_TAG_LEN == 64, the 'return'ed integer is the tag,
 * and *tagl is meaningless. When VMAC_TAG_LEN == 128 the tag is the
 * number y * 2^64 + *tagl where y is the function's return value.
 * If you want to consider tags to be strings, then you must do so with
 * an agreed upon endian orientation for interoperability, and convert
 * the results appropriately. VHASH hashes m without creating any tag.
 * Consecutive substrings forming a prefix of a message may be passed
 * to vhash_update, with vhash or vmac being called with the remainder
 * to produce the output.
 *
 * Requirements:
 * - On 32-bit architectures with SSE2 instructions, ctx and m MUST be
 *   begin on 16-byte memory boundaries.
 * - m MUST be your message followed by zeroes to the nearest 16-byte
 *   boundary. If m is a length multiple of 16 bytes, then it is already
 *   at a 16-byte boundary and needs no padding. mbytes should be your
 *   message length without any padding. 
 * - The first bit of the nonce buffer n must be 0. An i byte nonce, is made
 *   as the first 16-i bytes of n being zero, and the final i the nonce.
 * - vhash_update MUST have mbytes be a positive multiple of VMAC_NHBYTES
 * ----------------------------------------------------------------------- */

#define vmac_update vhash_update

void vhash_update(unsigned char m[],
          unsigned int mbytes,
          vmac_ctx_t *ctx);

uint64_t vmac(unsigned char m[],
         unsigned int mbytes,
         unsigned char n[16],
         uint64_t *tagl,
         vmac_ctx_t *ctx);

uint64_t vhash(unsigned char m[],
          unsigned int mbytes,
          uint64_t *tagl,
          vmac_ctx_t *ctx);

/* --------------------------------------------------------------------------
 * When passed a VMAC_KEY_LEN bit user_key, this function initialazies ctx.
 * ----------------------------------------------------------------------- */

void vmac_set_key(unsigned char user_key[], vmac_ctx_t *ctx);

/* --------------------------------------------------------------------------
 * This function aborts current hash and resets ctx, ready for a new message.
 * ----------------------------------------------------------------------- */

void vhash_reset(vmac_ctx_t *ctx);

/* --------------------------------------------------------------------- */

#ifdef  __cplusplus
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

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#define NOINLINE      __attribute__ ((noinline))
#define FASTCALL
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#define NOINLINE      __declspec(noinline)
#define FASTCALL      __fastcall
#else
#define ALIGN(n)
#define NOINLINE
#define FASTCALL
#endif

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

/* ----------------------------------------------------------------------- */

#if (VMAC_PREFER_BIG_ENDIAN)
#  define get64PE get64BE
#else
#  define get64PE get64LE
#endif

#if (VMAC_ARCH_BIG_ENDIAN)
#  define get64BE(ptr) (*(uint64_t *)(ptr))
#  define get64LE(ptr) GET_REVERSED_64(ptr)
#  define get32BE(ptr) (*(uint32_t *)(ptr))
#  define get32LE(ptr) GET_REVERSED_32(ptr)
#  define net64tohost(v) (v)
#  define net32tohost(v) (v)
#  define net16tohost(v) (v)
#  define host64tonet(v) (v)
#  define host32tonet(v) (v)
#  define host16tonet(v) (v)
#else /* assume little-endian */
#  define get64BE(ptr) GET_REVERSED_64(ptr)
#  define get64LE(ptr) (*(uint64_t *)(ptr))
#  define get32BE(ptr) GET_REVERSED_32(ptr)
#  define get32LE(ptr) (*(uint32_t *)(ptr))
#  define net64tohost(v) f_Net64ToHost((uint64_t)v)
#  define net32tohost(v) f_Net32ToHost((uint32_t)v)
#  define net16tohost(v) f_Net16ToHost((uint16_t)v)
#  define host64tonet(v) net64tohost(v)	// purely reverse
#  define host32tonet(v) net32tohost(v)	// purely reverse
#  define host16tonet(v) net16tohost(v)	// purely reverse
#endif


#ifdef __cplusplus // or else implementation should provided its own
static inline uint64_t f_Net64ToHost(uint64_t tmp) { GET_REVERSED_64(& tmp); return tmp; }
static inline uint32_t f_Net32ToHost(uint32_t tmp) { GET_REVERSED_32(& tmp); return tmp; }
static inline uint16_t f_Net16ToHost(uint16_t tmp) { return (tmp << 8) | (tmp >> 8); }
#endif

#endif /* HEADER_AES_H */
