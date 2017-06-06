/*
 * An implementation of multi-factor RSA based on GMPlib
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

#ifndef _RSA_GMP_INCLUDED
#define _RSA_GMP_INCLUDED

#include <gmp.h>

/**
 * Tested under a GNU-MP library compiled to 32-bit ABI
 * export CFLAGS="-O3"
 * cd /path/to/gmp-5.1.1
 * ./configure --build=i686-pc-mingw32 --enable-static --disable-shared
 * make && make check && make install && make distclean
 * for C interface declaration
 */
#include "rsassa-pss.h"

#ifndef BYTE
#define BYTE unsigned char
#endif

#define RSA_PKCS1_PADDING_SIZE 11


bool GenerateProvablePrimes(mpz_t p, mpz_t q, int nlen, int N1, int N4, const mpz_t e);
bool GenerateProvablePrimes(mpz_t p, mpz_t q, int nlen, const mpz_t e);
bool Provable_Prime_Construction(mpz_t p, mpz_t p1, mpz_t p2, mpz_t pseed, int L, int N1, int N2, const mpz_t firstseed, const mpz_t e);
bool PseudoRandom(mpz_t x, int bits);
bool ST_Random_Prime(mpz_t prime, mpz_t prime_seed, int & prime_gen_counter, int length, const mpz_t input_seed);


//
// PS = k - mLen - 3; PS will be at least 8 octets
// EM = 0x00 || 0x02 || PS || 0x00 || M
// For public key encryption only (could be exploited for key transfer)
class RSA_GMP_Base
{
protected:
	size_t	_len;
	mpz_t	n;
	unsigned long e;
	bool	hasPublic;
	//
	void  _RSA_EP(mpz_t c, const BYTE * p1)
	{
		mpz_t m;
		mpz_init(m);
		mpz_import(m, _len, 1, 1, 0, 0, p1);
		mpz_powm_ui(c, m, e, n);
		mpz_clear(m);
	}
	//
	friend int RSASSA_PSS_Verify(RSA_T, const BYTE *, int, const BYTE *);
	//
public:
	RSA_GMP_Base(): hasPublic(false) { }
	virtual ~RSA_GMP_Base() { mpz_clear(n); }
	//
	int Encrypt(const BYTE *, int, BYTE *);
	int ExportPublicKey(BYTE * tgt, unsigned long *e0 = NULL) const
	{
		size_t size;
		mpz_export(tgt, & size, 1, 1, 1, 0, n);
		if(e0 != NULL)
			*e0 = this->e;
		return (int)size;
	}
	int RSA_size() const { return (int)_len; }
	bool ImportPublicKey(const BYTE *, size_t, unsigned long e = 17);
};



class RSA_GMP: public RSA_GMP_Base
{
	mpz_t	d;	// (n, d) is the first form of private key
	mpz_t	p, q, dP, dQ, qInv;	// the second form of private key
	bool	hasPrivate;
	int		_RSA_DP(mpz_t, const BYTE *);
	//
	friend int RSASSA_PSS_Sign(RSA_T, const BYTE *, int, BYTE *);
	//
public:
	RSA_GMP(): hasPrivate(false) { }
	~RSA_GMP();
	//
	int Decrypt(const BYTE *, int, BYTE *);
	bool GenerateKey(int, unsigned long e = 17);
};


// RSA Signer with multiple(> 3) primes, PKCS #1 v2.2
class RSA_mP_Public
{
protected:
	size_t	_len;
	mpz_t	n;		// RSA public modulus
	mpz_t	e;		// RSA public exponent
	RSA_mP_Public() { }
public:
	static const int MININUM_RSA_BYTES = 256;
	//
	RSA_mP_Public(const BYTE *, size_t, const BYTE * = NULL, unsigned long = 65537);
	int ExportPublicModulus(BYTE * tgt) const
	{
		size_t size;
		mpz_export(tgt, & size, 1, 1, 1, 0, n);
		return (int)size;
	}
	int ExportPublicExponent(BYTE * tgt) const
	{
		size_t size;
		mpz_export(tgt, & size, 1, 1, 1, 0, e);
		return (int)size;
	}
	~RSA_mP_Public() { mpz_clears(n, e, NULL); }
	//
	int RSA_size() const { return (int)_len; }
	bool Verify(const BYTE *, int, const BYTE *);
};



class RSA_mP_Signer: public RSA_mP_Public
{
	static const int MINIMUM_FACTOR_BITS = 224;	// suggested mininum length of SHA-3
	static const int FACTOR_ALIGNMENT_2N = 6;	// 5, 6 or 7 is acceptable choice, but not 8 or above
	static const int MAX_PRIMES_NUM = 5;		// shoudn't be too large or else it might be too easy to factor n
	// the first form of private key (n, d) is simply unacceptable for multiple primes
	// primes/factors
	mpz_t	r_[MAX_PRIMES_NUM];
	// CRT exponents
	mpz_t	d_[MAX_PRIMES_NUM];
	// CRT coefficients
	mpz_t	t_[MAX_PRIMES_NUM];
	int		u;	// number of primes
	//
	int		_RSA_SP1S(mpz_t, const BYTE *);
public:
	//
	RSA_mP_Signer(int, unsigned long e1 = 0);
	~RSA_mP_Signer();
	//
	int Sign(const BYTE *, int, BYTE *);
};
#endif
