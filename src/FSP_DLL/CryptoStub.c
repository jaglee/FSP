/*
 * Provide stubs to some interesting crypto functions in tweetnacl
 *
    Copyright (c) 2012, Jason Gao
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

#include "tweetnacl.h"

// See "FSP_DLL.h" and "FSP_API.h". But FSP_DLL.h is NOT C-compatible
#ifdef _MSC_VER
#define FSPAPI __stdcall
#else
#define FSPAPI
#endif

#define DllSpec __declspec(dllexport)

// http://tweetnacl.cr.yp.to/

// OS-dependent crypto service
#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

void randombytes(BYTE * buf, size_t len)
{
	HCRYPTPROV   hCryptProv;
	CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
	CryptGenRandom(hCryptProv, (DWORD)len, buf);
	// Why PROV_RNG does not work? Elliptic Curve Nyberg-Rueppel Analog (ECNRA)?
}



// Given
//	pointer to the buffer of exported public key
//	pointer to the buffer of exported private key
// Do
//	Generate the public-private key pair
// Return
//	0 (always succeed in presumed constant time)
DllSpec
int FSPAPI CryptoNaClKeyPair(unsigned char *pk, unsigned char *sk)
{
	return crypto_box_keypair(pk, sk);
}


// Given
//	pointer to the buffer of the shared secret, crypto_core_hsalsa20_tweet_KEYBYTES = 32 bytes
//	the byte string of the peer's public key
//	the byte string of the near end's private key
// Do
//	Derive the shared secret
// Return
//	0 (always succeed in presumed constant time)
DllSpec
int FSPAPI CryptoNaClGetSharedSecret(unsigned char *s, const unsigned char *pk, const unsigned char *sk)
{
	return crypto_box_beforenm(s, pk, sk);
}



DllSpec
int FSPAPI CryptoNaClHash(unsigned char *buf, const unsigned char *input, unsigned long long len)
{
	return crypto_hash(buf, input, len);
}




DllSpec
int FSPAPI CryptoNaClScalarMult(unsigned char *buf, const unsigned char *exp, const unsigned char *base)
{
	return crypto_scalarmult(buf, exp, base);
}


DllSpec
int FSPAPI CryptoNaClScalarMultBase(unsigned char *buf, const unsigned char *exp)
{
	return crypto_scalarmult_base(buf, exp);
}
