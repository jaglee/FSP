/*
 * An implementation of multi-factor RSA based on GMPlib
 * TODO: parameter generation conform to FIPS PUB 186-3
 * integer factorization cryptography (IFC) Appendix B.3.4
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

#include <stdlib.h>
#include <malloc.h>
#include <assert.h>
#include <time.h>
#include "rsa-gmp.hpp"

// Import the public key. Do check whether the public exponent is a prime
bool RSA_GMP_Base::ImportPublicKey(const BYTE *strN, size_t len, unsigned long e1)
{
	mpz_t eL;
	mpz_init_set_ui(eL, e1);
	this->e = e1;
	e1 = mpz_probab_prime_p(eL, 16);
	mpz_clear(eL);
	if(! e1)
	{
		_len = 0;
		return false;
	}

	mpz_init(n);
	mpz_import(n, len, 1, 1, 0, 0, strN);
	_len = mpz_sizeinbase(n, 2) + 7;
	_len >>= 3;
	return (hasPublic = true);
}


int
RSA_GMP_Base::Encrypt(const BYTE *plaintext, int len, BYTE *ciphertext)
{
	if(_len - RSA_PKCS1_PADDING_SIZE < (size_t)len)
		return -1;

	// A stack overflow exception is generated if the space cannot be allocated
    BYTE *p1 = (BYTE *)_alloca(_len);
	BYTE *p = p1;
	*p++ = 0;
    *p++ = 2;
	for(int	padlen = int(_len - len - 3); padlen > 0; padlen--)
	{
		*p = rand() & 0xFF;
		if (*p == 0)
			*p = 0xA5;	// 0x10100101, conform to non-zero requirement, with balanced 0s and 1s
		p++;
    }
    *p++ = 0;
    memcpy(p, plaintext, len);
    assert((p + len - p1) == _len);

    mpz_t c;
    mpz_init(c);
	_RSA_EP(c, p1);
	//
    size_t size;
	mpz_export(ciphertext, & size, 1, 1, 0, 0, c);
	assert(_len >= size);
    mpz_clear(c);

    return (int)size;
}



int
RSA_GMP::_RSA_DP(mpz_t m, const BYTE *src)
{
	mpz_t c;
    mpz_init(c);
    mpz_import(c, _len, 1, 1, 0, 0, src);

    if(mpz_cmp_ui(c, 0) < 0 || mpz_cmp(c, n) >= 0)
	{
		mpz_clear(c);
		return -1;
    }

	// make sure mod p and mod q is legal. dP, dQ and qInv might be invalid, however, no exception would be thrown
	// the caller should make sure the private key is valid
    if (mpz_cmp_ui(p, 0) == 0 || mpz_cmp_ui(q, 0) == 0)
	{
		mpz_powm(m, c, d, n);
		mpz_clear(c);
		return 0;
	}

	mpz_t m1, h;
	mpz_inits(m1, h, NULL);

    // m1 = c ^ dP mod p
    mpz_fdiv_r(m1, c, p);
    mpz_powm(m1, m1, dP, p);
    // m2 = c ^ dQ mod q
    mpz_fdiv_r(m, c, q);
    mpz_powm(m, m, dQ, q);
	// h = (m1 - m2) * qInv mod p
    mpz_sub(h, m1, m);
    mpz_mul(h, h, qInv);
    mpz_fdiv_r(h, h, p);
	// m = m2 + q * h;
    mpz_addmul(m, q, h);

    mpz_clears(h, m1, c, NULL);
	return 0;
}


// RSA_PKCS1_PADDING
int
RSA_GMP::Decrypt(const BYTE *ciphertext, int len, BYTE *plaintext)
{
	if ((size_t)len > _len)
		return -1;

	size_t size;
    mpz_t m;
    mpz_init(m);
	if(_RSA_DP(m, ciphertext) < 0)
	{
		mpz_clear(m);
		return -1;
	}
	mpz_export(plaintext, & size, 1, 1, 0, 0, m);
    mpz_clear(m);
	if(size >= _len)	// the leading zero should have bee skipped
		return -2;

    BYTE *p = plaintext;
    if (*p != 2)
		return -3;
	for(size--, p++; size > 0 && *p != 0; size--, p++)
		;
    if (size == 0)
		return -4;
    size--, p++;
    memmove(plaintext, p, size);
    return (int)size;
}



// bits MAYNOT be less than RSA_PKCS1_PADDING_SIZE * 16 (176); the caller MUST guarantee that e1 is a prime
bool RSA_GMP::GenerateKey(int bits, unsigned long e1)
{
	if((bits & 0xFF) != 0)	// allowed bits are 256<would it ever be used?>, 512, 768, 1024, 2048, 3072
		return false;

	// firstly test the public exponent: must be a (provable?) prime
	mpz_t eL;
	this->e = e1;
	mpz_init_set_ui(eL, e1);
	if(mpz_probab_prime_p(eL, 25) == 0)
	{
		mpz_clear(eL);
		return false;
	}

	mpz_t y1, y2, lamda;
    mpz_inits(n, p, q, d, dP, dQ, qInv, y1, y2, lamda, NULL);

	// generate two large prime p and q
	if(bits > 1280)
	{
		hasPrivate = GenerateProvablePrimes(p, q, bits, eL);
		if(! hasPrivate)
			goto l_bailout;
	}
	else
	{
		// FIPS 186-3 Table B.1. Minimum and maximum lengths of p1, p2, q1 and q2 
		// N1, N2 > 100; N1 + N2 < 239, for bit length 1024.
		// We extra-polate the upper bound to 1280 and the lower bound to 512
		hasPrivate = GenerateProvablePrimes(p, q, bits,  (bits >> 8) * 25 + 1, (bits >> 8) * 35 - 3, eL);
		if(! hasPrivate)
			goto l_bailout;
	}

	if (mpz_cmp(p, q) < 0)
		mpz_swap(p, q);

	// for dual-prime RSA lamda(n) = LCM((p - 1) * (q - 1))
    mpz_sub_ui(y1, p, 1);
	mpz_sub_ui(y2, q, 1);
    mpz_lcm(lamda, y1, y2);
    // e * d = 1 mod lamda(n) -> d = 1/e mod (p - 1)(q - 1)
    mpz_invert(d, eL, lamda);

	// e * dP = 1 mod (p - 1) -> dP = 1/e mod (p-1) -> dP = d mod (q - 1)
    mpz_invert(dP, eL, y1);
	// e * dQ = 1 mod (q - 1) -> dQ = 1/e mod (q-1) -> dQ = d mod (p - 1)
    mpz_invert(dQ, eL, y2);
	// q * qInv = 1 mod p -> qInv = 1/q mod p
	mpz_invert(qInv, q, p);

    // n = p * q
    mpz_mul(n, p, q);
	_len = mpz_sizeinbase(n, 2) + 7;
	_len >>= 3;
	assert(_len == bits / 8);	// can we safely assert that?

l_bailout:
	mpz_clears(lamda, y2, y1, eL, NULL);
	return hasPrivate;
}


RSA_GMP::~RSA_GMP()
{
	if(! hasPrivate)
		return;
	// release in reverse order
	mpz_clears(qInv, dQ, dP, d, q, p, NULL);
	// n to be cleared by ~RSA_GMP_Base()
}



bool
RSA_mP_Public::Verify(const BYTE *fingerprint, int len, const BYTE *digest)
{
	if (len > (long)_len)
		return false;

    mpz_t s;
	mpz_init(s);
	mpz_import(s, len, 1, 1, 0, 0, fingerprint);
	if (mpz_cmp(s, n) >= 0)
	{
		mpz_clear(s);
		return false;
	}
	//
	mpz_t m;
	mpz_init(m);
	mpz_powm(m, s, e, n);
	//
	BYTE *pM = (BYTE *)_alloca(_len);
    size_t size;
	mpz_export(pM, & size, 1, 1, 0, 0, m);
	mpz_clear(m);
	mpz_clear(s);
	if(size >= _len)	// the leading zero should have bee skipped
		return false;
	//
    if (*pM != 1)
		return false;
	for(size--, pM++; size > 0 && *pM == 0xff; size--, pM++)
		;
    if (size == 0 || *pM != 0)
		return false;
	//
    size--, pM++;
    return memcmp(digest, pM, size) == 0;
}


// Construct the public key. Do check whether the public exponent is a definate prime
// The caller should get assurance of the public key
RSA_mP_Public::RSA_mP_Public(const BYTE *strN, size_t len, const BYTE *strE, unsigned long eLen)
{
	mpz_init(n);
	mpz_import(n, len, 1, 1, 0, 0, strN);
	mpz_init(e);
	if(strE == NULL)
		mpz_set_ui(e, eLen);
	else
		mpz_import(n, eLen, 1, 1, 0, 0, strE);
	//
	if(mpz_probab_prime_p(e, 32) != 2)
		_len = 0;
	else
		_len =  (mpz_sizeinbase(n, 2) + 7) >> 3;
}


int
RSA_mP_Signer::_RSA_SP1S(mpz_t s, const BYTE *src)
{
	// make sure mod r#i is legal for i = 1, 2, ... u
	for(int i = -2; i < u; i++)
	{
		if (mpz_cmp_ui(r_[i], 0) == 0)
			return -2;
	}

	mpz_t m;
    mpz_init(m);
    mpz_import(m, _len, 1, 1, 0, 0, src);
    if(mpz_cmp_ui(m, 0) < 0 || mpz_cmp(m, n) >= 0)
	{
		mpz_clear(m);
		return -1;
    }

	mpz_t s1, h, R;
	mpz_inits(s1, h, R, NULL);

	mpz_fdiv_r(s, m, r_[0]);
	mpz_powm(s, s, d_[0], r_[0]);
	mpz_set_ui(R, 1);
	for(int i = 1; i < u; i++)
	{
		// R = R * r#(i-1)
		mpz_mul(R, R, r_[i - 1]);
		// s#i = m ^ d#i mod r#i
	    mpz_fdiv_r(s1, m, r_[i]);
		mpz_powm(s1, s1, d_[i], r_[i]);
		// h = (s#i -s) * t#i mod r#i
		mpz_sub(h, s1, s);
		mpz_mul(h, h, t_[i]);
		mpz_fdiv_r(h, h, r_[i]);
		// s = s + R * h
		mpz_addmul(s, R, h);
	}
	mpz_clears(R, h, s1, m, NULL);
	return 0;
}


int
RSA_mP_Signer::Sign(const BYTE *digest, int len, BYTE *fingerprint)
{
	if(_len - RSA_PKCS1_PADDING_SIZE < (size_t)len)
		return -1;

    BYTE *p0 = (BYTE *)_alloca(_len);
    BYTE *p = p0;
    *p++ = 0;
    *p++ = 1;
    memset(p, 0xff, _len - len - 3);
    p += _len - len - 3;
    *p++ = 0;
    memcpy(p, digest, len);
    assert((p + len - p0) == _len);

    size_t size;
    mpz_t s;
    mpz_init(s);
	if(_RSA_SP1S(s, p0) < 0)
	{
		mpz_clear(s);
		return -1;
	}
	mpz_export(fingerprint, & size, 1, 1, 0, 0, s);
    mpz_clear(s);

    return (int)size;
}



RSA_mP_Signer::RSA_mP_Signer(int bits, unsigned long e1)
{
	int rBits = ((bits / 3) >> FACTOR_ALIGNMENT_2N) << FACTOR_ALIGNMENT_2N;
	register int i;
	mpz_t y;
	mpz_t & p = r_[MAX_PRIMES_NUM - 1];
	mpz_t & q = r_[MAX_PRIMES_NUM - 2];

	// in case destructor error
	mpz_inits(n, e, y, NULL);
	for(i = 0; i < MAX_PRIMES_NUM; i++)
	{
		mpz_inits(r_[i], d_[i], t_[i], NULL);
	}

	_len = 0;	// mark it unworkable

	if(bits < MININUM_RSA_BYTES * 8 || rBits <= MINIMUM_FACTOR_BITS * 2)
		goto l_bailout;

	if(e1 == 0)
	{
		// firstly, generate the public exponent. to make life easier just make sure it is less than any factor
		mpz_setbit(e, 0);
		mpz_setbit(e, (i = 1));
		mpz_setbit(e, __max(bits / 3 / (MAX_PRIMES_NUM - 2), MINIMUM_FACTOR_BITS) - 1);
		while(mpz_probab_prime_p(e, 25) == 0)
		{
			mpz_clrbit(e, i);
			mpz_setbit(e, ++i);
		}
		// probility that e is a composite number is extremely low
	}
	else
	{
		mpz_set_ui(e, e1);
		if(mpz_probab_prime_p(e, 25) != 2)
			goto l_bailout;
	}

	// generate two large primes p and q
	if(! PseudoRandom(p, rBits))
		goto l_bailout;		// p is guaranteed to be large enough
	srand((unsigned int)p->_mp_d[0]);
    do
	{
		mpz_nextprime(p, p);
		mpz_sub_ui(y, p, 1);
		mpz_gcd(y, y, e);
    } while(mpz_cmp_ui(y, 1) != 0);

	if(! PseudoRandom(q, rBits))
		goto l_bailout;		// q is guaranteed to be large enough
    do 
	{
		mpz_nextprime(q, q);
		mpz_sub_ui(y, q, 1);
		mpz_gcd(y, y, e);
    } while(mpz_cmp_ui(y, 1) != 0);

    if (mpz_cmp(p, q) < 0)
		mpz_swap(p, q);
	// note that roles of p and q are reversed actually
	// TODO: it should be make sure that that none of p − 1, p + 1, q − 1, or q + 1 is a smooth number

	// now the additional factors. note that p is placed at last
	const int MAXIMUM_FACTOR_BITS = rBits - MINIMUM_FACTOR_BITS - 1;
	const int E_MINIMUM_BITS = (int)mpz_sizeinbase(e, 2) + 1;
	int leftBits = bits - int(mpz_sizeinbase(p, 2) + mpz_sizeinbase(q, 2));
	u = 0;
	do
	{
		bool unique = true;
		mpz_t & z = r_[u];
		do
		{
			rBits = E_MINIMUM_BITS
				+ int((unsigned long long)rand() * (MAXIMUM_FACTOR_BITS - E_MINIMUM_BITS) / RAND_MAX);
			if(leftBits - rBits < MINIMUM_FACTOR_BITS)
				rBits = leftBits;
			// The bit length of the last factor might be less than the effective minimum
			// As MAXIMUM_FACTOR_BITS + MINIMUM_FACTOR_BITS == (primary factor size in bits) - 1
			// The bit length of any factor would not exceed the primary factor
			if(! PseudoRandom(z, rBits))
				goto l_bailout;
			do
			{
				mpz_nextprime(z, z);
				mpz_sub_ui(y, z, 1);
				mpz_gcd(y, y, e);
			} while(mpz_cmp_ui(y, 1) != 0);
			// bubble sort (smaller is move upward) and make sure the factor is unique
			int r;
			for(i = u - 1; i >= 0; i--)
			{
				r = mpz_cmp(r_[i], z);
				if(r <= 0)
					break;
			}
			//
			if(r == 0)
			{
				unique = false;
				continue;
			}
			for(register int j = u; j > i + 1; j--)
			{
				mpz_swap(r_[j], r_[j - 1]);
			}
		} while(! unique);
		//
		leftBits -= rBits;
		++u;
	} while(leftBits > 0 && u < MAX_PRIMES_NUM - 2);
	if(leftBits > 0)
	{
		_len = 0;
		goto l_bailout;
	}
	// Now move p and q upward to make the factor stored continueously when necessary
	if(u < MAX_PRIMES_NUM - 2)
	{
		mpz_swap(r_[u++], r_[MAX_PRIMES_NUM - 2]);
		mpz_swap(r_[u++], r_[MAX_PRIMES_NUM - 1]);
	}

	// The the CRT exponents and the co-efficents
    mpz_sub_ui(y, r_[0], 1);
    mpz_invert(d_[0], e, y);
    mpz_set(n, r_[0]);
	// t[0] is wasted. but it seems that life is easier
	for(int i = 1; i < u; i++)
	{
		// e * d#i = 1 mod (r#i - 1)
		mpz_sub_ui(y, r_[i], 1);
		mpz_invert(d_[i], e, y);
		// r1 * r2 * ... r#i-1 * t#i = 1 mod r#i
		mpz_mod(y, n, r_[i]);
		mpz_mul(n, n, r_[i]);
		mpz_invert(t_[i], y, r_[i]);
	}

	_len = mpz_sizeinbase(n, 2) + 7;
	_len >>= 3;
	assert(_len == bits / 8);	// can we safely assert that?

l_bailout:
	mpz_clear(y);
}


RSA_mP_Signer::~RSA_mP_Signer()
{
	// release in reverse order
	for(int i = MAX_PRIMES_NUM - 1; i >= 0; i--)
	{
		mpz_clears(t_[i], d_[i], r_[i], NULL);
	}
	// RSA_mP_Public::~RSA_mP_Public();
	// n and e to be cleared by ~RSA_mP_Public()
}
