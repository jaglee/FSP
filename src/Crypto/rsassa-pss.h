/*
 * The C interface declaration of the implementation of multi-factor RSA based on GMPlib,
 * for dual-factor signature scheme with appendix, EMSA-Probabilistic Signature Scheme
 * which is not provided in the C++ interface
 * 
    Copyright (c) 2013, Jason Gao <jagao@outlook.com>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT,INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RSA_SSA_H_INCLUDED
#define _RSA_SSA_H_INCLUDED

#ifndef BYTE
#define BYTE unsigned char
#endif

#define DEFAULT_PUBLIC_EXPONENT 65537
#define DEFAULT_HASH_BITS		224	// sizeof(salt) == hash length
#define DEFAULT_SIGNATURE_BYTES	64	// it's very easy to extend the function to support arbitrary length

typedef void * RSA_T;

#ifdef __cplusplus
extern "C" {
#endif

	RSA_T RSASSA_NewByImport(const BYTE *, size_t);
	RSA_T RSASSA_NewByCreate(int);
	void RSASSA_Free(RSA_T);

	int RSASSA_ExportModulus(RSA_T, BYTE *);
	int RSASSA_KeyBytes(RSA_T);

	/**
	 * Multi-factor encryption scheme - Optimal Asymetric Encryption Padding (OAEP) only
	 * public exponent === 65537
	 * DEPRECATED
	 */
	//int RSAES_OAEP_Encrypt(RSA_T, const BYTE *, int, const BYTE *, int, BYTE *);
	//int RSAES_OAEP_Decrypt(RSA_T, const BYTE *, int, const BYTE *, int, BYTE *);
	int RSASSA_PSS_Sign(RSA_T, const BYTE *, int, BYTE *);
	int RSASSA_PSS_Verify(RSA_T, const BYTE *, int, const BYTE *);

#ifdef __cplusplus
}
#endif


#endif