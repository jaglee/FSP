/* --------------------------------------------------------------------------
 * VHASH-AE Implementation by Ted Krovetz (tdk@acm.org).
 * Version: 0.01 (14 July 2006)
 * This implementation is herby placed in the public domain.
 * The author offers no warranty. Use at your own risk.
 * Please send bug reports to the author.
 * ----------------------------------------------------------------------- */

/*
 * Update 2015.2.25 By Jason Gao
 * Calling a more recent vmac()
 * vhash_abort -> vmac_reset
 */
/* VMAC and VMAC-AE require that the high bit of the nonce be 0. There is
 * an assertion during encryption that the nonce has this property. You
 * must define the symbol NDEBUG befoer assert.h is included to disable
 * the assertion.
 */
#include <assert.h>
#include <string.h>
#include "vmac_ae.h"

/* --------------------------------------------------------------------------
 * This implementation only supports nonces upto 96 bits and encrypting
 * plaintexts of upto 2^36 - 16 bytes (about 4GB) per nonce.
 * ----------------------------------------------------------------------- */

/* These may need adjusting for particular targets */
#define VMAC_ARCH_64 (__x86_64__ || __amd64__ || __ppc64__ || _M_X64)
#define VMAC_BIG_ENDIAN (__BIG_ENDIAN__ || \
        !(__x86_64__ || __i386__ || _M_IX86 || _M_X64))

/* ----------------------------------------------------------------------- */
#if (__GNUC__ && (__x86_64__ || __amd64__))
/* ----------------------------------------------------------------------- */

#define PUT_REVERSED_64(p,x) 				                                  \
	asm volatile ("bswapq %0" :  "=r"(*(uint64_t *)(p)): "0"(x))
#define PUT_REVERSED_32(p,x) 				                                  \
	asm volatile ("bswap %0" :  "=r"(*(uint32_t *)(p)): "0"(x))


/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && __i386__)
/* ----------------------------------------------------------------------- */

#define PUT_REVERSED_64(p,x) 					                             \
	{ uint64_t y; asm volatile ("bswap %%edx\n\t" 		                     \
	    		  "bswap %%eax\n\t" 			                             \
	    		  "movl (%2), %%edx\n\t"	                                 \
	    		  "movl 4(%2), %%eax" 								         \
	: "=A"(y)								             					 \
	: "0"(x), "r"(p)                                                         \
	: "memory"); }
#define PUT_REVERSED_64x(p,x) 					                             \
	asm volatile ("bswap %%edx\n\t" 		                                 \
	    		  "bswap %%eax\n\t" 			                             \
	    		  "xchgl %%eax, %%edx"	                                     \
	: "=A"(*(uint32_t *)(p))								             	 \
	: "0"(x))
#define PUT_REVERSED_32(p,x) 				                                  \
	asm volatile ("bswap %0" :  "=r"(*(uint32_t *)(p)): "0"(x))


/* ----------------------------------------------------------------------- */
#elif _MSC_VER
/* ----------------------------------------------------------------------- */

#include <intrin.h>

#define PUT_REVERSED_64(p,x)   *(uint64_t *)(p) = _byteswap_uint64(x)
#define PUT_REVERSED_32(p,x)   *(uint32_t *)(p) = _byteswap_ulong(x)
#pragma intrinsic(_byteswap_uint64)
#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(memcpy)

/* ----------------------------------------------------------------------- */
#endif
/* ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* Default implementation, if not defined above                           */
/* ----------------------------------------------------------------------- */


#ifndef PUT_REVERSED_64
#define PUT_REVERSED_64(p,x)                                               \
	*(uint64_t *)(p) = ( (uint64_t)x                               << 56) |          \
	                   ((x & UINT64_C(0x0000000000ff00)) << 40) |          \
		               ((x & UINT64_C(0x00000000ff0000)) << 24) |          \
		               ((x & UINT64_C(0x000000ff000000)) <<  8) |          \
		               ((x & UINT64_C(0x0000ff00000000)) >>  8) |          \
		               ((x & UINT64_C(0x00ff0000000000)) >> 24) |          \
		               ((x & UINT64_C(0xff000000000000)) >> 40) |          \
		               ( (uint64_t)x                               >> 56)
#endif

#ifndef PUT_REVERSED_32
#define PUT_REVERSED_32(p,x)                                               \
	*(uint32_t *)(p) = (x >> 24) | ((x & 0x00FF0000) >> 8 )				   \
                     | ((x & 0x0000FF00) << 8 ) | (x << 24)
#endif

/* ----------------------------------------------------------------------- */

#if (VMAC_BIG_ENDIAN)

#define put32BE(ptr,x) (*(uint32_t *)(ptr) = (uint32_t)(x))
#define put64BE(ptr,x) (*(uint64_t *)(ptr) = (uint64_t)(x))

#else /* assume little-endian */

#define put64BE    PUT_REVERSED_64
#define put32BE    PUT_REVERSED_32

#endif

/* ----------------------------------------------------------------------- */

void vmac_ae_set_key(unsigned char user_key[], vmac_ae_ctx_t *ctx)
{
	vmac_set_key(user_key, &ctx->vmac_ctx);
	ctx->lengths[0] = 0;
	ctx->lengths[1] = 0;
}

/* ----------------------------------------------------------------------- */

static void vmac_ae_add(unsigned char *d,
         unsigned int dbytes,
         vmac_ae_ctx_t *ctx)
{
	unsigned initial, remaining, lbytes, zeros, space;
	unsigned char *leftover;
	
	zeros = (16 - (dbytes % 16)) % 16; /* zeroes needed after d */
	leftover = ctx->leftover;
	lbytes = ctx->lbytes;
	
	/* If some bytes have been buffered, deal with them first */
	if (lbytes) {
		space = VMAC_NHBYTES - lbytes; /* space left in buffer */
		if (dbytes <= space) {
			memcpy(leftover+lbytes, d, dbytes);
			memset(leftover+lbytes+dbytes, 0, zeros);
			lbytes += dbytes + zeros;
			if (lbytes == VMAC_NHBYTES) {
				vhash_update(leftover, VMAC_NHBYTES, &ctx->vmac_ctx);
				lbytes = 0;
			}
			ctx->lbytes = lbytes;
			return;
		} else {
			memcpy(leftover+lbytes, d, space);
			vhash_update(leftover, VMAC_NHBYTES, &ctx->vmac_ctx);
			ctx->lbytes = 0;
			d += space;
			dbytes -= space;
		}
	}
	
	/* Next deal with any multiple of VMAC_NHBYTES bytes */
	remaining = dbytes % VMAC_NHBYTES;
	initial   = dbytes & ~(VMAC_NHBYTES-1);
	if (initial)
		vhash_update(d, initial, &ctx->vmac_ctx);
	
	/* Finally, if any bytes remain, buffer them and pad to 16 bytes */
	if (remaining) {
		memcpy(leftover, d+initial, remaining);
		memset(leftover+remaining, 0, zeros);
		lbytes = remaining + zeros;
		if (lbytes == VMAC_NHBYTES) {
			vhash_update(leftover, VMAC_NHBYTES, &ctx->vmac_ctx);
			lbytes = 0;
		}
		ctx->lbytes = lbytes;
	}
}

/* ----------------------------------------------------------------------- */

void vmac_ae_header(unsigned char *h,
         unsigned int hbytes,
         vmac_ae_ctx_t *ctx)
{
	put64BE(ctx->lengths, (uint64_t)(hbytes * 8));
	vmac_ae_add(h, hbytes, ctx);
}

/* ----------------------------------------------------------------------- */

void vmac_ae_footer(unsigned char *f,
         unsigned int fbytes,
         vmac_ae_ctx_t *ctx)
{
	*(unsigned char *)(ctx->lengths) = (unsigned char)((fbytes & 15) * 8);
	vmac_ae_add(f, fbytes, ctx);
}

/* ----------------------------------------------------------------------- */

void vmac_ae_crypt(unsigned char *it, /* in text  */
		 unsigned char *ot,           /* out text */
		 unsigned char *at,           /* authentication text (it/ot) */
         unsigned int tbytes,         /* text bytes */
         unsigned char n[],
		 unsigned int nbytes,
		 vmac_ae_ctx_t *ctx)
{
	uint64_t      tmp [2];
	uint64_t      tmp2[2];
	uint32_t      ctr;
	unsigned int  iters, remaining;
	uint64_t      *itp        = (uint64_t *)it,
	              *otp        = (uint64_t *)ot;
	aes_int_key   *cipher_key = &(ctx->vmac_ctx.cipher_key);
	
	assert((n[0] & 0x80) == 0); /* First bit of nonce must be zero */

	iters     = tbytes / 16;
	remaining = tbytes % 16;
	
	/* Copy supplied nonce to ctx */
	((uint64_t *)(ctx->nonce))[0] = 0;
	((uint64_t *)(ctx->nonce))[1] = 0;
	memcpy(ctx->nonce, n, nbytes);
	ctx->nbytes = nbytes;
	
	/* Store length of encryption */
	put64BE(ctx->lengths+1, (uint64_t)(tbytes * 8));
	
	for (ctr = 1; ctr <= iters; ctr++) {
		put32BE(ctx->nonce+3, (uint32_t)(ctr));
		aes_encryption(ctx->nonce, tmp, cipher_key);
		otp[0] = itp[0] ^ tmp[0];
		otp[1] = itp[1] ^ tmp[1];
		itp += 2;
		otp += 2;
	}
	if (remaining) {
		put32BE(ctx->nonce+3, (uint32_t)(ctr));
		aes_encryption(ctx->nonce, tmp, cipher_key);
		memcpy(tmp2, itp, remaining);
		tmp[0] ^= tmp2[0];
		tmp[1] ^= tmp2[1];
		memcpy(otp, tmp, remaining);
	}
	vmac_ae_add(at,tbytes,ctx);
}

/* ----------------------------------------------------------------------- */

uint64_t vmac_ae_finalize(uint64_t *tagl, vmac_ae_ctx_t *ctx)
{
	uint64_t tagh;
	unsigned lbytes = ctx->lbytes;
	
	if (lbytes) {
		vhash_update(ctx->leftover, lbytes, &ctx->vmac_ctx);
	}
	ctx->nonce[3] = 0;
	//tagh = vmac(ctx->lengths, 16, (unsigned char *)ctx->nonce,
	//            ctx->nbytes, tagl, &ctx->vmac_ctx);	// fix length of nonce to 16 bytes
	tagh = vmac((unsigned char *)ctx->lengths, 16, (unsigned char *)ctx->nonce, tagl, &ctx->vmac_ctx);

	ctx->lengths[0] = 0;
	ctx->lengths[1] = 0;
	ctx->lbytes = 0;
	return tagh;
}

/* ----------------------------------------------------------------------- */

void vmac_ae_reset(vmac_ae_ctx_t *ctx)
{
	vhash_reset(&ctx->vmac_ctx);	
	ctx->lengths[0] = 0;
	ctx->lengths[1] = 0;
	ctx->lbytes = 0;
}
