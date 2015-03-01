/* --------------------------------------------------------------------------
 * VMAC-AE Implementation by Ted Krovetz (tdk@acm.org).
 * Version: 0.01 (14 July 2006)
 * This implementation is herby placed in the public domain.
 * The author offers no warranty. Use at your own risk.
 * Please send bug reports to the author.
 * ----------------------------------------------------------------------- */

/*
 * 2015.2.25 Updated by Jason Gao
 * vhash_abort -> vmac_ae_reset
 */

#ifndef HEADER_VMAC_AE_H
#define HEADER_VMAC_AE_H

#include "../vmac.h"

/* ----------------------------------------------------------------------- */

typedef struct {          /* Must be 16-byte aligned on 32-bit i386 */
    uint32_t nonce[4];
	uint64_t lengths[2];  /* hbytes, tbytes. Big-Endian */
	unsigned char leftover[VMAC_NHBYTES];
	vmac_ctx_t vmac_ctx;
	int nbytes;
	int lbytes;
} vmac_ae_ctx_t;

/* ----------------------------------------------------------------------- */
#ifdef  __cplusplus
extern "C" {
#endif
/* ----------------------------------------------------------------------- */

void vmac_ae_set_key(unsigned char user_key[], vmac_ae_ctx_t *ctx);
/* fills *ctx */

void vmac_ae_reset(vmac_ae_ctx_t *ctx);
/* Resets internal variables without finishing current work */


/* Given Header H, Plaintext P and Footer F, you must call in the
 * following sequence: vmac_ae_header(H) [if H non-empty], vmac_ae_encrypt(P),
 * vmac_ae_footer(F) [if F non-empty]. If H or F is empty, do not call the
 * corresponding function.
 */
void vmac_ae_header(unsigned char *h,
         unsigned int hbytes,
         vmac_ae_ctx_t *ctx);
void vmac_ae_footer(unsigned char *f,
         unsigned int fbytes,
         vmac_ae_ctx_t *ctx);
void vmac_ae_crypt(unsigned char *it, /* in text  */
		 unsigned char *ot,           /* out text */
		 unsigned char *at,           /* authentication text (it/ot) */
         unsigned int tbytes,         /* text length in bytes */
         unsigned char n[],
		 unsigned int nbytes,
		 vmac_ae_ctx_t *ctx);

uint64_t vmac_ae_finalize(uint64_t *tagl, vmac_ae_ctx_t *ctx);
/* Returns the authentication tag as a number. If VMAC_TAG_LEN == 64 then
 * the entire tag is returned and tagl should be ignored. If VMAC_TAG_LEN
 * == 128, then the high 64-bits are returned and *tagl has the low bits
 */


/* ----------------------------------------------------------------------- */
#ifdef  __cplusplus
}
#endif
/* ----------------------------------------------------------------------- */

/* These macros simplify calling vmac_ae_crypt */
#define vmac_ae_encrypt(pt,ct,tbytes,n,nbytes,ctx) \
           vmac_ae_crypt(pt,ct,ct,tbytes,n,nbytes,ctx) 

#define vmac_ae_decrypt(ct,pt,tbytes,n,nbytes,ctx) \
           vmac_ae_crypt(ct,pt,ct,tbytes,n,nbytes,ctx) 

/* ----------------------------------------------------------------------- */
#endif /* HEADER_VMAC_AE_H */
