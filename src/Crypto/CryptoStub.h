#ifndef _CRYPTO_STUB_H
#define _CRYPTO_STUB_H

/*
 * Provide stubs to some interesting crypto functions in tweetnacl
 *
    Copyright (c) 2017, Jason Gao
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
#define CRYPTO_NACL_KEYBYTES	32
#define CRYPTO_NACL_HASHBYTES	64

#include "../Intrins.h"
#include "sha256.h"

#if defined(__WINDOWS__)

# ifdef _MSC_VER
#  ifndef __cplusplus
#	define SINLINE static __forceinline
#  endif
#  define FSPAPI __stdcall
# else
#  ifndef __cplusplus
#	define SINLINE static __inline__
#  endif
#  define FSPAPI
# endif

// Only supported on Windows Vista and above
# if WINVER < 0x0600
#	undef	WINVER
#	define	WINVER 0x0600
# endif

# define WIN32_LEAN_AND_MEAN
# include <Windows.h>

#elif defined(__linux__) || defined(__CYGWIN__)

# ifndef __cplusplus
#  define SINLINE static __inline__
# endif
# define FSPAPI
# define printf_s	printf	// let the compiler check the safety of formatted printing

#endif

#ifdef __cplusplus
# define SINLINE static inline
#endif

#define crypto_box_curve25519xsalsa20poly1305_beforenm crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
#define crypto_box_curve25519xsalsa20poly1305_keypair crypto_box_curve25519xsalsa20poly1305_tweet_keypair
#define crypto_hash_sha512 crypto_hash_sha512_tweet

#define crypto_box_beforenm crypto_box_curve25519xsalsa20poly1305_beforenm
#define crypto_box_keypair crypto_box_curve25519xsalsa20poly1305_keypair

#ifdef __cplusplus
extern "C"
{
#endif

// Given
//	void *		the pointer of the buffer to hold the random octets
//	size_t		number of the random octets to generate
// Do
//	Generate a string of random octets of given size, save it in the given buffer
void randombytes(void *, size_t);

#if defined(__WINDOWS__)
// WideCharToMultiByte and MultiByteToWideChar have severe security issues handled in these functions:

// Given
//	octet[]		the pointer of the buffer to hold the output string in UTF-8 encoding
//	int			the capacity of the buffer, typically not exceed 32767, in octets
//	LPCWCH		the wide-character string which is NUL-terminated
// Do
//	translate the wide-character string to string encoded in the UTF-8 character set
// Return
//	Number of output octets, including the terminate NUL
int WideStringToUTF8(octet[], int, LPCWCH);

// Given
//	char[]		the pointer of the buffer to hold the output string encoded in UTF8
//	int			the capacity of the buffer, typically not exceed 32767, in octets
//	LPCSTR		the source string in multi-byte character set, which is not necessarily NUL-terminated
// Do
//	translate the locale string encoded in multi-byte character set to UTF-8 encoded string
// Return
//	Number of output single-byte characters
int LocalMBCSToUTF8(octet[], int, LPCSTR);

// Given
//	char[]		the pointer of the buffer to hold the output locale string encoded in multi-byte character set
//	int			the capacity of the buffer, typically not exceed 32767, in octets
//	LPCSTR		the source string in UTF-8 code set, which is not necessarily NUL-terminated
// Do
//	translate the UTF-8 encoded string to locale string encoded in multi-byte character set
// Return
//	Number of output single-byte characters
int UTF8ToLocalMBCS(char[], int, LPCSTR);

// Given
//	wchar_t[]	the pointer of the buffer to hold the output wide character string (in UTF16)
//	int			the capacity of the buffer, typically not exceed 32767, in wchar_ts
//	LPCSTR		the source string in UTF-8 code set, which is not necessarily NUL-terminated
//	int			number of octets to be translated in the source string
// Do
//	translate the UTF-8 encoded string to Unicode wide character string (UTF16)
// Return
//	Number of output wide characters
int UTF8ToWideChars(wchar_t[], int, LPCSTR, int);

#endif

// in tweetnacl.c:
int crypto_box_beforenm(unsigned char *,const unsigned char *,const unsigned char *);
int crypto_box_keypair(unsigned char *,unsigned char *);
int crypto_hash_sha512(unsigned char *,const unsigned char *,unsigned long long);

#ifdef __cplusplus
}
#endif


// Given
//	pointer to the buffer of exported public key
//	pointer to the buffer of exported private key
// Do
//	Generate the public-private key pair
// Return
//	0 (always succeed in presumed constant time)
SINLINE int FSPAPI CryptoNaClKeyPair(octet *pk, octet *sk)
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
SINLINE int FSPAPI CryptoNaClGetSharedSecret(octet *s, const octet *pk, const octet *sk)
{
	return crypto_box_beforenm(s, pk, sk);
}



// Given
//	pointer to the buffer of the output hash, 64 bytes
//	the input byte string to calculate the hash
//	the length of the byte string
// Do
//	get the SHA512 result
// Return
//	0 (always succeed in presumed constant time)
SINLINE int FSPAPI CryptoNaClHash(octet *buf, const octet *input, size_t len)
{
	return crypto_hash_sha512(buf, input, len);
}



// A very simple HMAC-SHA256 here
// ipad = the byte 0x36 repeated B times
// opad = the byte 0x5C repeated B times.
// H(K XOR opad, H(K XOR ipad, text))
SINLINE
void hmac_sha256_key512(octet *output, const octet *key, const octet *input, size_t len)
{
	sha256_t ctx;
	struct
	{
		octet padk[CRYPTO_NACL_HASHBYTES];
		octet ih[SHA256_DIGEST_SIZE];
	} km;
	for(register int i = 0; i < CRYPTO_NACL_HASHBYTES; i++)
		km.padk[i] = key[i] ^ 0x36;
	//
	sha256_init(& ctx);
	sha256_update(& ctx, km.padk, sizeof(km.padk));
	sha256_update(& ctx, input, len);
	sha256_final(& ctx, km.ih);
	//
	for(register int i = 0; i < CRYPTO_NACL_HASHBYTES; i++)
		km.padk[i] = key[i] ^ 0x5C;
	//
	sha256_init(& ctx);
	sha256_update(& ctx, (octet *) & km, sizeof(km));
	sha256_final(& ctx, output);
}

#endif