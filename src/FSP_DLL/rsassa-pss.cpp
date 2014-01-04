/*
 * Implementation of the C interface of multi-factor RSA based on GMPlib
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
#include <time.h>
#include <malloc.h>
#include <intrin.h>
#include <assert.h>
#include "rsa-gmp.hpp"
#include "rsassa-pss.h"
#include "../KeccakReferenceAndOptimized/Sources/KeccakNISTInterface.h"

#define SSA_PSS_PREMASK_SUFFIX	'\x1'
#define SSA_PSS_SUFFIX_BYTE		((BYTE)'\xbc')	// signed char wourld refuse to be equal to unsigned char

static int GenerateMask(BYTE * mask, int len, const BYTE * mgfSeed);

extern "C" {

RSA_T RSASSA_NewByImport(const BYTE *strN, size_t len)
{
	RSA_GMP_Base *pRSA = new RSA_GMP_Base();
	//
	if(! pRSA->ImportPublicKey(strN, len, DEFAULT_PUBLIC_EXPONENT))
	{
		delete pRSA;
		return NULL;
	}
	//
	return (RSA_T)pRSA;
}


RSA_T RSASSA_NewByCreate(int keySize)
{
	RSA_GMP *pRSA = new RSA_GMP();
	//
	if(! pRSA->GenerateKey(keySize, DEFAULT_PUBLIC_EXPONENT))
	{
		delete pRSA;
		return NULL;
	}
	//
	return (RSA_T)pRSA;
}



void RSASSA_Free(RSA_T pRSA)
{
	delete (RSA_GMP_Base *)pRSA;
}


int RSASSA_ExportModulus(RSA_T pRSA, BYTE * buffer)
{
	return ((RSA_GMP_Base *)pRSA)->ExportPublicKey(buffer);
}


int RSASSA_KeyBytes(RSA_T pRSA)
{
	return ((RSA_GMP_Base *)pRSA)->RSA_size();
}


// Given
//	
// Return
//	positive integer which is the size of signed message with appendix if no error
//	-1 if message too long (or some other odd error that should not happen)
//	-2 if encoding error
static const BYTE padding1[8];
int RSASSA_PSS_Sign(RSA_T pRSA, const BYTE *message, int mlen, BYTE *signature)
{
	size_t size = ((RSA_GMP *)pRSA)->_len;
	if(int(size - DEFAULT_SIGNATURE_BYTES) <= 0)
		return -2;

	BYTE mHash[DEFAULT_HASH_BITS / 8];
	BYTE * H;
	BYTE salt[DEFAULT_HASH_BITS / 8];
	BYTE DB[DEFAULT_SIGNATURE_BYTES - sizeof(mHash)];	// {could} - 1

	BYTE * EM = (BYTE *)time(NULL);
	Hash(DEFAULT_HASH_BITS, (const BitSequence *) & EM, sizeof(EM) * 8, salt);
	EM = (BYTE *)_alloca(size);
	if(EM == NULL)
		return -2;
	H = & EM[size - sizeof(mHash) - 1];

	// EMSA-PSS-ENCODE
	// M ==> (Hash) ==> mHash
	if(Hash(DEFAULT_HASH_BITS, message, mlen << 3, mHash) != SUCCESS)
		return -2;

	// padding1 | mHash | salt ==> M'
	// M' ==> (Hash) ==> H
	hashState hashCtx;
	Init(& hashCtx, DEFAULT_HASH_BITS);
	Update(& hashCtx, padding1, sizeof(padding1) * 8);
	Update(& hashCtx, mHash, DEFAULT_HASH_BITS);
	Update(& hashCtx, salt, DEFAULT_HASH_BITS);
	Final(& hashCtx, H);

	// padding2 | salt ==> DB
	memset(DB, 0, DEFAULT_SIGNATURE_BYTES - sizeof(salt) - sizeof(mHash) - 2);
	DB[DEFAULT_SIGNATURE_BYTES - sizeof(salt) - sizeof(mHash) - 2] = SSA_PSS_PREMASK_SUFFIX;
	memcpy(DB + DEFAULT_SIGNATURE_BYTES - sizeof(salt) - sizeof(mHash) - 1, salt, sizeof(salt));

	// H ==> (MGF) ==> mask [stored in place of EM]
	// mask XOR DB ==> maskedDB
	// maskedDB | H | 0xbc ==> EM

	GenerateMask(EM + size - DEFAULT_SIGNATURE_BYTES, DEFAULT_SIGNATURE_BYTES - sizeof(mHash) - 1, H);
	for(register int i = DEFAULT_SIGNATURE_BYTES - sizeof(mHash) - 2; i >= 0; i--)
	{
		EM[size - DEFAULT_SIGNATURE_BYTES + i] ^= DB[i];
	}
	EM[size - 1] = SSA_PSS_SUFFIX_BYTE;
	// set leftmost bits to zero
	memset(EM, 0, size - DEFAULT_SIGNATURE_BYTES);

	// Sign the PSS-encoded message
	mpz_t s;
	mpz_init(s);
	if(((RSA_GMP *)pRSA)->_RSA_DP(s, EM) != 0)
	{
		mpz_clear(s);
		return -2;
	}

	mpz_export(signature, & size, 1, 1, 0, 0, s);
	mpz_clear(s);
	return 0;
}


// Given
//
// Return
//	1 if valid signature
//  0 if invalid signature
int RSASSA_PSS_Verify(RSA_T pRSA
					, const BYTE *message, int mlen
					, const BYTE *signature
					)
{
	const int sLen = DEFAULT_HASH_BITS / 8;	// length in bytes of the salt
	BYTE EM[DEFAULT_SIGNATURE_BYTES];
	BYTE mHash[DEFAULT_HASH_BITS / 8];
	BYTE dbMask[DEFAULT_SIGNATURE_BYTES - sizeof(mHash)];	// could ' - 1' further
	size_t size;

	mpz_t m;
	mpz_init(m);
	// UNRESOLVED! Check signature out of range error? No. verification would eventually fail
	((RSA_GMP_Base *)pRSA)->_RSA_EP(m, signature);
	// if the leftmost .. bits of the leftmost octet in maskedDB are not all equal to zero,
	// output 'inconsistent' and stop
	if(mpz_sizeinbase(m, 2) > DEFAULT_SIGNATURE_BYTES * 8)
	{
		mpz_clear(m);
		return 0;
	}
	mpz_export(EM, & size, 1, 1, 0, 0, m);
	mpz_clear(m);
	// fatal error that could cause memory corruption
	if(size > sizeof(EM))
		return 0;

	// EMSA-RSASSA_PSS_Verify(M, EM, modBits - 1);
	if(size < DEFAULT_HASH_BITS / 8 + sLen + 2)
		return 0;
	if(EM[size - 1] != SSA_PSS_SUFFIX_BYTE)
		return 0;
	size -= (sizeof(mHash) + 1);

	BYTE * H = & EM[size];
	GenerateMask(dbMask, (int)size, H);

	// Bytes from EM[size - sLen] to EM[size - 1] form the salt after de-masking
	register int i = (int)size - 1;
	while(i >= int(size - 1 - sLen))
	{
		EM[i] ^= dbMask[i];
		i--;
	}
	if(EM[size - 1 - sLen] != SSA_PSS_PREMASK_SUFFIX)
		return 0;
	//
	while(i >= 0)
	{
		EM[i] ^= dbMask[i];
		if(EM[i--] != 0)
			return 0;
	}

	// M ==> (Hash) ==> mHash
	Hash(DEFAULT_HASH_BITS, message, mlen << 3, mHash);

	// padding1 | mHash | salt ==> M'
	// M' ==> (Hash) ==> H'
	BYTE Hquot[sizeof(mHash)];
	hashState hashCtx;
	Init(& hashCtx, DEFAULT_HASH_BITS);
	Update(& hashCtx, padding1, sizeof(padding1) * 8);
	Update(& hashCtx, mHash, sizeof(mHash) * 8);
	Update(& hashCtx, & EM[size - sLen], sLen << 3);
	Final(& hashCtx, Hquot);

	for(register int i = 0; i < sizeof(mHash); i++)
	{
		if(H[i] != Hquot[i])
			return 0;
	}
	return 1;
}


};


// return 0 if no error, -2 if mask too long
static int GenerateMask(BYTE * mask, int maskLen, const BYTE * mgfSeed)
{
	if((maskLen + DEFAULT_HASH_BITS / 8 - 1) / (DEFAULT_HASH_BITS / 8) <= 0)
		return -2;

	hashState hashCtx;
	hashState savedCtx;
	BYTE h[DEFAULT_HASH_BITS / 8];

	Init(& hashCtx, DEFAULT_HASH_BITS);
	Update(& hashCtx, mgfSeed, DEFAULT_HASH_BITS);
	savedCtx = hashCtx;

	unsigned int counter = 0;	// uint32_t
	int n;
	do
	{
		Update(& hashCtx, (const BitSequence *) & counter, 32);
		Final(& hashCtx, h);
		n = maskLen < sizeof(h) ? maskLen : sizeof(h);
		memcpy(mask, h, n);
		maskLen -= n;
		if(maskLen <= 0)
			break;
		//
		hashCtx = savedCtx;
		counter++;
	} while(1);
	//
	return 0;
}




/**
 * FIPS_186-3 Digital Signature Standard (DSS) Appendix B-3 Integer Factor Cryptography Key Pair Generation 
 */

/**
 * B.3.2 Generation of Random Primes that are Provable Prime
 *
 An approved method that satisfies the constraints of Appendix B.3.1 shall be used for the generation of IFC random primes
 p and q that are provably prime (see case A.1). One such method is provided in Appendix B.3.2.1 and B.3.2.2.
 For this method, a random seed is initially required (see Appendix B.3.2.1);
 the length of the seed is equal to twice the security strength associated with the modulus n.
 After the seed is obtained, the primes can be generated (see Appendix B.3.2.2). 

 As of NIST SP800-51 part 1
 bits of security		RSA key length bit
  80					1024
 112					2048
 128					3072
 192					7680
 256					15360

 */
//Input:
//  nlen The intended bit length of the modulus n.  
//  e    The public verification exponent
//  (seed The seed obtained using the method in B.3.2.1)
//Output: 
// status	The status of the generation process, where status is either SUCCESS or FAILURE.
//			When FAILURE is returned, zero values shall be returned as the other parameters. 
// p and q	The private prime factors of n. 
bool GenerateProvablePrimes(mpz_t p, mpz_t q, int nlen, const mpz_t e)
{
/**
 * B.3.2.2 Construction of the Provable Primes p and q 
 */
	//1.	If nlen is neither 2048 nor 3072, then return (FAILURE, 0, 0).  [Test delayed]
	//2.	If ((e ≤ 2^^16) OR (e ≥ 2^^256) OR (e is not odd)), then return (FAILURE, 0, 0). 
	//3.	Set the value of security_strength in accordance with the value of nlen, as specified in SP 800-57, Part 1. 
	int n = (int)mpz_sizeinbase(e, 2);
	if(n < 16 || n > 256 || mpz_tstbit(e, 0) == 0)
	{
l_failure:
		mpz_set_ui(p, 0);
		mpz_set_ui(q, 0);
		return false;
	}
	int	security_strength = nlen == 2048 ? 112 : nlen == 3072 ? 128 : 0;
	if(security_strength <= 0)
		goto l_failure;

/**
  *	B.3.2.1 Get the Seed (nested)
  *
	The following process or its equivalent shall be used to generate the seed for this method.  
	Input:  nlen 	The intended bit length of the modulus n. 
	Output: 
		status 	The status to be returned, where status is either SUCCESS or FAILURE.
		seed 	The seed. If status = FAILURE, a value of zero is returned as the seed. 
 */
	// 1. If nlen is not valid, then Return (FAILURE, 0). 
	// 2. Let security_strength be the security strength associated with nlen, as specified in SP 800-57, Part 1. 
	// 3. Obtain a string seed of (2 * security_strength) bits from an RBG that supports the security_strength. 
	// 4. Return (SUCCESS, seed).

	mpz_t	seed, pseed, p1, p2;
	mpz_inits(seed, pseed, p1, p2, NULL);

	// just a trick for assertion to work
	bool	status = ! PseudoRandom(seed, 2 * security_strength);
	assert(status == false);

/**
 * End of nested B.3.2.1
 */
	//4.	If (len(seed) ≠ 2 * security_strength), then return (FAILURE, 0, 0). 

	//5.	working_seed = seed. 
	// but we reuse seed as 'working_seed'
	//6.	Generate p: 
	//6.1	Using 	L = nlen/2, N1 = 1, N2 = 1, first_seed = working_seed and e, use the provable prime construction method
	//		in Appendix C.10 to obtain p and pseed. If FAILURE  is returned, then return (FAILURE, 0, 0). 
	if(! Provable_Prime_Construction(p, p1, p2, pseed, nlen / 2, 1, 1, seed, e))
	{
		mpz_set_ui(q, 0);		// p should have been reset to 0 if it ever failed
		goto l_return;
	}
	// hereafter we reuse seed as 'qseed', pseed as 'working_seed'
	//6.2	working_seed = pseed. 
	do
	{
		//7.	Generate q: 
		//7.1	Using 	L = nlen/2, N1 = 1, N2 = 1, first_seed = working_seed and e, use the provable prime construction method
		//		in Appendix C.10 to obtain q and qseed. If FAILURE  is returned, then return (FAILURE, 0, 0). 
		if(! Provable_Prime_Construction(q, p1, p2, seed, nlen / 2, 1, 1, pseed, e))
		{
			mpz_set_ui(p, 0);	// q should have been reset to 0 if it ever failed
			goto l_return;
		}
		//7.2	working_seed = qseed. 
		mpz_set(pseed, seed);
		//8.	If ( |p – q| ≤ 2^^(nlen/2 – 100), then go to step 7. 
		mpz_sub(p1, p, q);
		mpz_abs(p2, p1);	// p2 = |p - q|
		mpz_set_ui(p1, 0);
		mpz_setbit(p1, nlen / 2 - 100);	// p1 = 2^^(nlen/2 - 100)
	} while(mpz_cmp(p1, p2) > 0);
	//
	//9.	Zeroize the internally generated seeds: 
	//9.1	pseed = 0; 
	//9.2	qseed = 0; 
	//9.3	working_seed = 0. 
	//10.	Return (SUCCESS, p, q). 
	status = true;
	//
l_return:
	mpz_clears(seed, pseed, p1, p2, NULL);
	return status;
}


/**
 * B.3.4 Generation of Provable Primes with Conditions Based on Auxiliary Provable Primes 
 *
 This section specifies an approved method for the generation of the IFC primes p and q with the additional conditions
 specified in Appendix B.3.1, case B.1, where p, p1, p2, q, q1 and q2 are all provable primes.
 For this method, a random seed is initially required (see Appendix B.3.2.1); the length of the seed is equal to
 twice the security strength associated with the modulus n. After the first seed is obtained, the primes can be generated. 
 Let bitlen1, bitlen2, bitlen3, and bitlen4 be the bit lengths for p1, p2, q1 and q2, respectively, in accordance with Table B.1.
 The following process or its equivalent shall be used to generate the provable primes:

 */
// Input: 
//	nlen 	The intended bit length of the modulus n. 
//	e		The public verification exponent.  
//  N1		length of (min) auxiliary prime number p1/q1
//	N2		length of (max) auxiliary prime number p2/q2
//	<seed>	The seed obtained using the method in Appendix B.3.2.1.}{embedded}
// Output: 
//	status	The status of the generation process, where status is either SUCCESS or FAILURE.
//			If FAILURE is returned then zeros shall be returned as the values for p and q. 
//	p and q The private prime factors of n. 
// Remark
//	Minum bit length of auxiliary primes is given in N1, while the maximum is given in N4, and N2, N3 were choosed randomly
//	The process is mandatory for key length less than 2048 bits
//	Checking of e was loosened { acceptable minimal e = 17, for bit length 512 and 768 <difiniately ephemeral key> }
bool GenerateProvablePrimes(mpz_t p, mpz_t q, int nlen, int N1, int N2, const mpz_t e)
{
	//1.	If nlen is neither 1024, 2048, nor 3072, then return (FAILURE, 0, 0). {Extended!}
	// As in FIPS-186-3  Table B-1 provable primes Max. length of len(p1) + len(p2) and len(q1) + len(q2) 
	// Less stringent than original
	if(nlen <= 1280)
	{
		// N1, N2 > 100; N1 + N2 < 239, when key bit length = 1024
		int minlen = (nlen >> 8) * 25;	// the real minimum - 1 [greatly loosened!]
		int maxsum = (nlen >> 8) * 60 - 1;
		if(N1 != 1 && N1 <= minlen || N2 != 1 && N2 <= minlen || (N1 + N2) >= maxsum)
			goto l_failure;
	}
	else if(nlen == 2048)
	{
		// N1, N2 > 140; N1 + N2 < 494
		if(N1 != 1 && N1 <= 140 || N2 != 1 && N2 <= 140 || (N1 + N2) >= 494)
			goto l_failure;
	}
	else if(nlen == 3072)
	{
		// N1, N2 > 170; N1 + N2 < 750
		if(N1 != 1 && N1 <= 170 || N2 != 1 && N2 <= 170 || (N1 + N2) >= 750)
			goto l_failure;
	}
	else // (nlen > 3072) || {nlen is an 'odd' number}
	{
		goto l_failure;
	}

	//2.	If ((e ≤ 2^^16) OR (e ≥ 2^^256) OR (e is not odd)), then return (FAILURE, 0, 0).
	//3.	Set the value of security_strength in accordance with the value of nlen, as specified in SP 800-57, Part 1. 
	//4.	If (len(seed) ≠ 2 * security_strength), then return (FAILURE, 0, 0).  {Extended!}
	int n = (int)mpz_sizeinbase(e, 2);
	if((n < 16 && nlen >= 1024 || n < 4) || n > 256 || mpz_tstbit(e, 0) == 0)
	{
l_failure:
		mpz_set_ui(p, 0);
		mpz_set_ui(q, 0);
		return false;
	}
	int	security_strength = nlen == 2048 ? 112 : nlen == 3072 ?  128 : nlen >= 1024 ? 80 : 64;	
	if(nlen < (security_strength << 3) || nlen > (security_strength << 4))
		goto l_failure;	// well, 512 is the minum, actually; and 768, 1280 are the other two extendedly acceptable length

	mpz_t	seed, pseed, p1, p2;
	mpz_inits(seed, pseed, p1, p2, NULL);

	// just a trick for assertion to work
	bool	status = ! PseudoRandom(seed, 2 * security_strength);
	assert(status == false);
	srand((unsigned int)seed->_mp_d[0]);

	//5.	working_seed = seed. 
	// but we reuse seed as 'working_seed'
	//6.	Generate p: 
	//6.1	Using L = nlen/2, N1 = bitlen1, N2 = bitlen2, firstseed = working_seed and e, use the provable prime construction
	//		method in Appendix C.10 to obtain p, p1, p2 and pseed. If FAILURE is returned, return (FAILURE, 0, 0). 
	N2 = N1 + (N2 - N1) * rand() / RAND_MAX;
	if(! Provable_Prime_Construction(p, p1, p2, pseed, nlen / 2, N1, N2, seed, e))
	{
		mpz_set_ui(q, 0);		// p should have been reset to 0 if it ever failed
		goto l_return;
	}
	// hereafter we reuse seed as 'qseed', pseed as 'working_seed'
	//6.2	working_seed = pseed. 
	do
	{
		//7.	Generate q: 
		//7.1	Using L = nlen/2, N1 = bitlen3, N2 = bitlen4 and firstseed = working_seed and e, use the provable prime construction
		//		method in Appendix C.10 to obtain q, q1, q2 and qseed. If FAILURE is returned, return (FAILURE, 0, 0).
		N2 = N1 + (N2 - N1) * rand() / RAND_MAX;	// gradually reduce N2 to make prime construction less difficult
		if(! Provable_Prime_Construction(q, p1, p2, seed, nlen / 2, N1, N2, pseed, e))
		{
			mpz_set_ui(p, 0);	// q should have been reset to 0 if it ever failed
			goto l_return;
		}
		//7.2	working_seed = qseed. 
		mpz_set(pseed, seed);
		//8.	If ( |p – q| ≤ 2^^(nlen/2 – 100), then go to step 7. 
		mpz_sub(p1, p, q);
		mpz_abs(p2, p1);	// p2 = |p - q|
		mpz_set_ui(p1, 0);
		mpz_setbit(p1, nlen / 2 - 100);	// p1 = 2^^(nlen/2 - 100)
	} while(mpz_cmp(p1, p2) > 0);
	//
	//9.	Zeroize the internally generated seeds: 
	//9.1	pseed = 0; 
	//9.2	qseed = 0; 
	//9.3	working_seed = 0. 
	//10.	Return (SUCCESS, p, q). 
	status = true;
	//
l_return:
	mpz_clears(seed, pseed, p1, p2, NULL);
	return status;
}



enum mutex_state
{
	MUTEX_FREE = 0,
	MUTEX_BUSY = 1
};
static volatile long buf_mutex = MUTEX_FREE;
static BYTE	buf[3072 / 8];	// practically it is for storing temporary random value, indeterminance harms little
static const int outlen = 224;



// Given
//	_Uint32t	[_Out_] placeholder of the random 32-bit words to be generated
//	int			number of the random 32-bit words to be gererated
// Do
//	Apply SHA3 to a pseudom-random seed and copy out the result
// Remark
//	Indeterminancy due to multi-threading do no harm
//	The caller should make sure n > 0 or else memory corruption may occur
extern "C" void rand_w32(unsigned int *p, int n)	//_Uint32t
{
	int hashLen = n < 224/32 ? 224 : n < 256/32 ? 256 : n < 384/32 ? 384 : 512;
	struct
	{
		int		r;
		time_t	f1;
		clock_t f2;
	} m	= { n, time(NULL), clock() };	// key material, pseudo-randomly
	Hash(hashLen, (BitSequence *) & m, sizeof(m) * 8, buf);
	memcpy(p, buf, n << 2);		// as each _Uint32t is 4 bytes
}


// Given
//	x		[_Out_] placeholder of the random number to be generated
//	bits	the lenth of random number size, may not exceed 3 times of maximum out length of SHA3
// Return
//	true if Hash SUCCESS, false if parameter error
// Remark
//	length in bits of x is guarenteed to be == bits
bool PseudoRandom(mpz_t x, int bits)
{
	int hashLen = bits < 224 ? 224 : bits < 256 ? 256 : bits < 384 ? 384 : 512;
	struct
	{
		int		r;
		time_t	f1;
		clock_t f2;
	} m	= { bits, time(NULL), clock() };	// key material, pseudo-randomly

	// as we have check the parameter bits shouldn't fail
	Hash(hashLen, (BitSequence *) & m, sizeof(m) * 8, buf);
	m.r -= hashLen;
	if(m.r > 0)
	{
		Hash(hashLen, (BitSequence *) & m, sizeof(m) * 8, buf + hashLen / 8);
		m.r -= hashLen;
	}
	if(m.r > 0)
	{
		Hash(hashLen, (BitSequence *) & m, sizeof(m) * 8, buf + hashLen / 8 * 2);
		m.r -= hashLen;
	}
	//
	if(m.r > 0)
		return false;

	// make it multi-thread safe [while consume less stack space][could exploit it in kernel driver?]
	while(_InterlockedCompareExchange(& buf_mutex, MUTEX_BUSY, MUTEX_FREE))
		_sleep(1);
	// make sure MSb-s are set and cleared properly (in case bits is not a multiple of 8)
	m.r = bits + 7;
	if((m.r & 7) == 7)
	{
		buf[0] |= 0x80;
	}
	else
	{
		buf[0] &= (1 << (bits & 7)) - 1;
		buf[0] |= 1 << ((bits & 7) - 1);
	}
	mpz_import(x, m.r >> 3, 1, 1, 0, 0, buf);
	buf_mutex = MUTEX_FREE;

	return true;
}


/**
 * Trial Division
 *
 
 An integer is proven to be prime by showing that it has no prime factors less than or equal to its square root.
 This procedure is not recommended for testing any integers longer than 10 digits. 
 To prove that c is prime: 
 1. Prepare a table of primes less than sqrt(c).
 2. Divide c by every prime in the table. If c is divisible by one of the primes, then declare that c is composite and exit.
    If convenient, c may be divided by composite numbers. For example, rather than preparing a table of primes,
	it might be more convenient to divide by all integers except those divisible by 3 or 5. 
 3. Otherwise, declare that cis prime and exit.

 */
#define NUM_OF_BOOTSTRAP_PRIMES	54	// finally number of short primes is 6320
static unsigned short shortPrimes[6320] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71	// 1~20
	, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173	//21~40
	, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,	// 41~54
	};
static int	nShortPrime = NUM_OF_BOOTSTRAP_PRIMES;

static void PrepareTableOfShortPrimes()
{
	register unsigned int i;
	register unsigned int k;
	for(k = shortPrimes[NUM_OF_BOOTSTRAP_PRIMES - 1] + 2; k < USHRT_MAX; k += 2)
	{
		for(i = 0; i < NUM_OF_BOOTSTRAP_PRIMES; i++)
		{
			// assume the optimizer would eliminate redundant division
			if(k / shortPrimes[i] < shortPrimes[i])
			{
				shortPrimes[nShortPrime++] = k;
				break;
			}
			//
			if(k % shortPrimes[i] == 0) break;
		}
	}	// a brute force method to find all of the short primes
	assert(nShortPrime <= sizeof(shortPrimes) / sizeof(unsigned short));
}

static bool TestPrimeByTrialDivision(unsigned int c)	//_Uint32t
{
	for(register int i = 0; i < nShortPrime; i++)
	{
		// assume the optimizer would eliminate redundant division
 		if(c / shortPrimes[i] < shortPrimes[i])
			return true;
		if(c % shortPrimes[i] == 0)
			return false;
	}
	return true;
}


//Shawe-Taylor Random_Prime Routine 
//Input:   
// 1.	length 	The length of the prime to be generated. 
// 2.	input_seed 	The seed to be used for the generation of the requested prime. 
//Output:   
// 1.	status 	The status returned from the generation routine, where status is either SUCCESS or FAILURE.
// 2.	prime 	The requested prime.  
// 3.	prime_seed 	A seed determined during generation. 
// 4.	prime_gen_counter 	(Optional) A counter determined during the generation of the prime. 
bool ST_Random_Prime(mpz_t prime, mpz_t prime_seed, int & prime_gen_counter, int length, const mpz_t input_seed)
{
	//1.	If (length < 2), then return (FAILURE, 0, 0 {, 0}). 
	if(length < 2)
	{
l_fail:
		prime_gen_counter = 0;
		mpz_set_ui(prime, 0);
		mpz_set_ui(prime_seed, 0);
		return false;
	}

	//2.	If (length ≥ 33), then go to step 14. 
	if(length < 33)
	{
		static BYTE	hashValue1[outlen / 8];	// no, temporary hash result needn't to be stored on stack
		static BYTE	hashValue2[outlen / 8];
		unsigned int c;	//_Uint32t
		//3.	prime_seed = input_seed.
		mpz_set(prime_seed, input_seed);
		//4.	prime_gen_counter = 0.
		prime_gen_counter = 0;
		// this extra preparation add negligible burden to the whole function
		if(nShortPrime <= NUM_OF_BOOTSTRAP_PRIMES)
			PrepareTableOfShortPrimes();
		//
		do
		{
			//Comment: Generate a pseudorandom integer c of length bits. 
			//5.	c = Hash(prime_seed) ⊕ Hash(prime_seed + 1). 
			//6.	c = 2^^(length – 1) + (c mod 2^^(length – 1)). 
			//7.	c = (2 ∗⎣ c / 2⎦ ) + 1.
			Hash(outlen
				, (BitSequence *)prime_seed->_mp_d
				, prime_seed->_mp_size * sizeof(mp_limb_t) << 3
				, hashValue1);
			mpz_add_ui(prime_seed, prime_seed, 1);
			Hash(outlen
				, (BitSequence *)prime_seed->_mp_d
				, prime_seed->_mp_size  * sizeof(mp_limb_t) << 3
				, hashValue2);
			c = *(unsigned int *) hashValue1 ^ *(unsigned int *) hashValue2;	//_Uint32t
			c &= (2 << (length - 1)) - 1;
			c |= 2 << (length - 1);
			c |= 1;
			//Comment: Set prime to the least odd integer greater than or equal to c. 

			//8.	prime_gen_counter = prime_gen_counter + 1. 
			//9.	prime_seed = prime_seed + 2. 
			prime_gen_counter++;
			mpz_add_ui(prime_seed, prime_seed, 1);	// note that it has already been incremented by 1

			//10.	Perform a deterministic primality test on c.
			//11.	If (c is a prime number), then  
			//11.1	prime = c. 
			//11.2	Return (SUCCESS, prime, prime_seed {, prime_gen_counter}). 
			if(TestPrimeByTrialDivision(c))
			{
				mpz_set_ui(prime, c);
				return true;
			}

			//12.	If (prime_gen_counter > (4 ∗ length)), then return (FAILURE, 0, 0 {, 0}). 
			//13.	Go to step 5. 
		} while(prime_gen_counter <= 4 * length);

		goto l_fail;
	}

	//14.	(status, c0, prime_seed, prime_gen_counter) = (ST_Random_Prime (( ⎡length / 2⎤ + 1), input_seed). 
	//15.	If FAILURE is returned, return (FAILURE, 0, 0 {, 0}). 
	mpz_t	c0;
	mpz_init(c0);
	if(! ST_Random_Prime(c0, prime_seed, prime_gen_counter, (length + 3) >> 1, input_seed))
	{
		mpz_clear(c0);
		goto l_fail;
	}

	//16.	iterations = ⎡length / outlen⎤ – 1. 
	//17.	old_counter = prime_gen_counter. 
	int		iteration_blocks = (length + outlen - 1) / outlen;
	int		old_counter = prime_gen_counter;
	bool	status = false;
	mpz_t	c, t, x, z, tmp;
	mpz_inits(c, t, x, z, tmp, NULL);
		
	//Comment: Generate a pseudorandom integer x in the interval [2length – 1, 2length]. 
	//18.	x = 0. 
	//19.	For i = 0 to iterations do x = x + (Hash(prime_seed + i) ∗ 2^^(i × outlen)).
	//20.	prime_seed = prime_seed + iterations + 1. 
	//21.	x = 2^^(length – 1) + (x mod 2^^(length – 1)). 
	for(register int i = 0; i < iteration_blocks; i++)
	{
		Hash(outlen
			, (BitSequence *)prime_seed->_mp_d
			, prime_seed->_mp_size * sizeof(mp_limb_t) * 8
			, & buf[outlen/8 * i]);
		mpz_add_ui(prime_seed, prime_seed, 1); 
	}
	mpz_import(tmp, iteration_blocks * outlen / 8, 1, 1, 0, 0, buf);
	mpz_fdiv_r_2exp(x, tmp, length - 1);
	mpz_setbit(x, length - 1);

	//Comment: Generate a candidate prime c in the interval [2^^(length – 1), 2^^length]. 
	//22.	t = ⎡x / (2c0)⎤. 
	mpz_mul_ui(c0, c0, 2);	// c0 <== 2c0
	mpz_add(tmp, x, c0);
	mpz_sub_ui(x, tmp, 1);
	mpz_div(t, x, c0);		// now x ceased to be meaningful
	do
	{
		//23.	If (2tc0 + 1 > 2^^length), then t = ⎡2^^(length – 1) / (2c0)⎤. 
		//24.	c = 2tc0 + 1.
		mpz_mul(tmp, t, c0);	// note that c0 has already been doubled
		mpz_add_ui(c, tmp, 1);
		if(mpz_sizeinbase(c, 2) > (size_t)length)
		{
			mpz_set_ui(tmp, 0);
			mpz_setbit(tmp, length - 1);
			mpz_add(c, tmp, c0);
			mpz_sub_ui(tmp, c, 1);
			mpz_div(t, tmp, c0);
			mpz_mul(tmp, t, c0);
			mpz_add_ui(c, tmp, 1);
		}

		//25.	prime_gen_counter = prime_gen_counter + 1. 
		prime_gen_counter++;

		//Comment: Test the candidate prime c for primality; first pick an integer a between 2 and c – 2. 
		//26.	a = 0. 
		//27.	For i = 0 to iterations do a = a + (Hash(prime_seed + i) ∗ 2^^(i * outlen)). 
		//28.	prime_seed = prime_seed + iterations + 1. 
		for(register int i = 0; i < iteration_blocks; i++)
		{
			Hash(outlen
				, (BitSequence *)prime_seed->_mp_d
				, prime_seed->_mp_size * sizeof(mp_limb_t) * 8
				, & buf[outlen/8 * i]);
			mpz_add_ui(prime_seed, prime_seed, 1); 
		}
		// we reuse x as 'a'(a temporary variable)
		mpz_import(x, iteration_blocks * outlen / 8, 1, 1, 0, 0, buf);
		//29.	a = 2 + (a mod (c – 3)). 
		//30.	z = a^^2t mod c.
		mpz_sub_ui(tmp, c, 3);
		mpz_mod(z, x, tmp);
		mpz_add_ui(x, z, 2);
		mpz_mul_ui(tmp, t, 2);
		mpz_powm(z, x, tmp, c);

		//31.	If ((1 = GCD(z – 1, c)) and (1 = z^^c0  mod c)), then 
		//31.1	prime = c. 
		//31.2	Return (SUCCESS, prime, prime_seed {, prime_gen_counter}). 
		mpz_sub_ui(tmp, z, 1);
		mpz_gcd(x, tmp, c);
		if(mpz_cmp_ui(x, 1) == 0)
		{
			mpz_powm(x, z, c0, c);
			if(mpz_cmp_ui(x, 1) == 0)
			{
				mpz_set(prime, c);
				status = true;
				goto l_return;
			}
		}

		//32.	If (prime_gen_counter ≥ ((4 ∗ length) + old_counter)), then return (FAILURE, 0, 0 {, 0}).  
		//33.	t = t + 1. 
		//34.	Go to step 23. 
		mpz_add_ui(t, t, 1);
	} while(prime_gen_counter < ((4 * length) + old_counter));

	prime_gen_counter = 0;
	mpz_set_ui(prime, 0);
	mpz_set_ui(prime_seed, 0);

l_return:
	mpz_clears(tmp, z, x, t, c, c0, NULL);
	return status;
}





/*
 * C.10 Construct a Provable Prime (possibly with Conditions), Based on Contemporaneously Constructed Auxiliary Provable Primes 
 *
 The following process (or its equivalent) shall be used to generate an L-bit provable prime p
 (a candidate for one of the prime factors of an RSA modulus). Note that the use of p in this
 specification is used generically; both RSA prime factors p and q may be generated using this method. 

 If a so-called “strong prime” is required, this process can generate primes p1 and p2 (of specified bit-lengths N1 and N2)
 that divide p−1 and p+1, respectively. The resulting prime p will satisfy the conditions traditionally required of a
 strong prime, provided that the requested bit-lengths for p1  and p2 have appropriate sizes. 
 Regardless of the bit-lengths selected for p1  and p2, the quantity p−1 will have a prime divisor p0
 whose bit-length is slightly more than half that of p. In addition, the quantity p0 − 1 will have a prime divisor
 whose bit-length is slightly more than half that of p0. 

 This algorithm requires that N1  + N2  ≤ L – ⎡L/2⎤ – 4. Values for N1 and N2  should be chosen such that
 N1  + N2  ≤ (L/2) – log2(L) – 7, to ensure that the algorithm can generate as many as 5L distinct candidates for p.
 
 Let Hash be the selected hash function to be used, and let outlen be the bit length of the hash function output block. 

 */

//Input:  
//1.	L 	A positive integer equal to the requested bit-length for p. Note that acceptable values for L= nlen/2 are computed as specified in Appendix B.3.1, criteria 2(b) and (c), with nlen assuming a value specified in Table B.1. 
//2.	N1  	A positive integer equal to the requested bit-length for p1.
//				If N1  ≥ 2, then p1 is an odd prime of N1 bits; otherwise, p1 = 1.
//				Acceptable values for N1  ≥ 2 are provided in Table B.1 
//3.	N2  	A positive integer equal to the requested bit-length for p2.
//				If N2  ≥ 2, then p2 is an odd prime of N2 bits; otherwise, p2 = 1. 
//				Acceptable values for N2  ≥ 2 are provided in Table B.1 
//4.	firstseed 	 	A bit string equal to the first seed to be used. 
//5.	e 	 	The public verification exponent. 
//Output:   
//1.	status 	The status returned from the generation procedure, where status is either SUCCESS or FAILURE.
//				If FAILURE is returned, then zeros are returned as the other output values. 
//2.	p, p1, p2  	The required prime p, along with p1 and p2 having the property that p1 divides p−1 and p2 divides p+1. 
//3.	pseed 	A seed determined during generation. 
//Remark
//	because of a small bug in FIPS 186-3, checking of N1, N2 was extracted out to be enforced by caller
bool Provable_Prime_Construction(mpz_t p, mpz_t p1, mpz_t p2, mpz_t pseed, int L, int N1, int N2, const mpz_t firstseed, const mpz_t e)
{
	//1.	If L, N1, and N2  are not acceptable, then, return (FAILURE, 0, 0, 0, 0).{extracted}
	//Comment: Generate p1 and p2, as well as the prime p0. 
	//2.	If N1 = 1, then 
	//2.1	p1 = 1. 
	//2.2	p2seed = firstseed. 
	//3.	If N1  ≥ 2, then 
	//3.1	Using N1 as the length and firstseed as the input_seed, use the random prime generation routine in
	//		Appendix C.6 to obtain p1 and p2seed.   
	//3.2	If FAILURE is returned, then return (FAILURE, 0, 0, 0, 0). 
	//4.	If N2 = 1, then 
	//4.1	p2 = 1. 
	//4.2	p0seed = p2seed. 
	//5.	If N2  ≥ 2, then
	//5.1	Using N2 as the length and p2seed as the input_seed, use the random prime generation routine in
	//		Appendix C.6 to obtain p2 and p0seed. 
	//5.2	If FAILURE is returned, then return (FAILURE, 0, 0, 0, 0). 
	//6.	Using ⎡L / 2⎤ + 1 as the length and p0seed as the input_seed, use the random prime generation routine in
	//		Appendix C.6 to obtain p0 and pseed. If FAILURE is returned, then return (FAILURE, 0, 0, 0, 0). 
	mpz_t	p2seed, p0seed, p0, t, tmp, x, y, z, _2p0p1, _2p0p1p2, _tp2_y;
	int		pgen_counter = 0;
	bool	status = false;
	mpz_inits(p2seed, p0seed, p0, t, tmp, x, y, z, _2p0p1, _2p0p1p2, _tp2_y, NULL);
	//
	if(N1 == 1)
	{
		mpz_set_ui(p1, 1);
		mpz_set(p2seed, firstseed);
	}
	else if(! ST_Random_Prime(p1, p2seed, pgen_counter = 0, N1, firstseed))
	{
		goto l_false;
	}
	//
	if(N2 == 1)
	{
		mpz_set_ui(p2, 1);
		mpz_set(p0seed, p2seed);
	}
	else if(! ST_Random_Prime(p2, p0seed, pgen_counter = 0, N2, p2seed))
	{
		goto l_false;
	}
	//
	if(! ST_Random_Prime(p0, pseed, pgen_counter = 0, (L + 3) >> 1, p0seed))
		goto l_false;

	//Comment: Generate a (strong) prime p in the interval [( 2 )(2L−1), 2L −1]. 
	//7.	iterations = ⎡L / outlen⎤− 1. 
	//8.	pgen_counter = 0. 
	int		iteration_blocks = (L + outlen - 1) / outlen;
	pgen_counter = 0;
	
	//Comment: Generate pseudo-random x in the interval [sqrt(2)(2^^(L−1)−1, 2^^L −1]. 
	//9.	x = 0. 
	//10.	For i = 0 to iterations do  
	//x = x + (Hash(pseed + i))∗ 2^^(i * outlen). 
	//11.	pseed = pseed + iterations + 1. 
	//12.	x = ⎣sqrt(2)*(2^^(L−1)⎦ + ( x mod (2^^L − ⎣sqrt(2)(2^^L−1)⎦ ) ). 
	for(register int i = 0; i < iteration_blocks; i++)
	{
		Hash(outlen
			, (BitSequence *)pseed->_mp_d
			, pseed->_mp_size * sizeof(mp_limb_t) * 8
			, & buf[outlen/8 * i]);
		mpz_add_ui(pseed, pseed, 1);
	}
	mpz_import(x, iteration_blocks * outlen / 8, 1, 1, 0, 0, buf);
	mpz_set_ui(t, 0);
	mpz_setbit(t, 2*L - 1);
	mpz_sqrt(tmp, t);	// tmp = sqrt(2) * 2^^(L-1) = sqrt(2 ^^ (2L - 1))
	mpz_set_ui(t, 0);
	mpz_setbit(t, L);
	mpz_sub(y, t, tmp);	// y = 2^^L - sqrt(2 ^^ (2L-1))
	mpz_fdiv_r(t, x, y);
	mpz_add(x, tmp, t);
	// x should be kept till to the begin of the loop

	//Comment: Generate a candidate for the prime p. 
	//13.	If (GCD(p0p1, p2) ≠ 1), then return (FAILURE, 0, 0, 0, 0). 
	//14.	Compute y in the interval [1, p2] such that 0 = (  y p0 p1 – 1) mod p2. 
	mpz_mul(tmp, p0, p1);	// tmp = p0 * p1
	mpz_gcd(t, tmp, p2);
	if(mpz_cmp_ui(t, 1) != 0) goto l_false;
	//^ only could happen if p2 == p0 or p2 == p1?
	if(N2 == 1)	// where mpz_cmp_ui(p2, 1) == 0
	{
		mpz_set_ui(y, 1);
	}
	else
	{
		mpz_fdiv_r(t, tmp, p2);
		if(! mpz_invert(y, t, p2))
		{
			// how could it happen
			assert(false);
			goto l_false;
		}
	}
	// y now has a persistent value

	//15.	t = ⎡((2  y p0 p1) + x)/(2 p0 p1 p2)⎤.
	mpz_mul_ui(_2p0p1, tmp, 2);	// tmp = p0 * p1, still
	mpz_mul(_2p0p1p2, _2p0p1, p2);
	mpz_mul(z, y, _2p0p1);
	mpz_add(tmp, z, x);
	mpz_cdiv_q(t, tmp, _2p0p1p2);
	// we reuse x as 'a'(a temporary variable). t must be treated as a persistent variable
	do
	{
		//16.	If ((2(t p2 − y) p0 p1  + 1) > 2^^L), then t = ⎡( (2  y p0 p1) + ⎣sqrt(2)(2^^L−1)⎦ ) / (2 p0 p1 p2)⎤.
		//Comment: p satisfies 0 = (p – 1) mod (2p0 p1) and 0 = (p + 1) mod p2. 
		//17.	p = 2(t p2 − y) p0 p1  + 1.
		mpz_mul(tmp, t, p2);
		mpz_sub(_tp2_y, tmp, y);
		mpz_mul(tmp, _tp2_y, _2p0p1);	// tmp = 2(t p2 - y) p0 p1
		//
		mpz_set_ui(x, 0);
		mpz_setbit(x, L);
		if(mpz_cmp(tmp, x) >= 0)
		{
			mpz_mul(x, y, _2p0p1);
			mpz_set_ui(t, 0);
			mpz_setbit(t, 2*L - 1);
			mpz_sqrt(tmp, t);	// tmp = sqrt(2) * 2^^(L-1) = sqrt(2 ^^ (2L - 1))
			mpz_add(z, x, tmp);	// z = 2 y p0 p1 + sqrt(2 ^^ (2L - 1))
			mpz_cdiv_q(t, z, _2p0p1p2);
			//
			mpz_mul(tmp, t, p2);
			mpz_sub(_tp2_y, tmp, y);
			mpz_mul(tmp, x, _2p0p1);	// tmp = 2(t p2 - y) p0 p1
		}
		mpz_add_ui(p, tmp, 1);	// note that tmp == p - 1 here

		//18.	pgen_counter = pgen_counter + 1. 
		//19.	If (GCD(p–1, e) = 1), then 
		pgen_counter++;
		mpz_gcd(x, tmp, e);
		if(mpz_cmp_ui(x, 1) == 0)
		{
			//Comment: Choose an integer a in the interval [2, p – 2]. 
			//19.1	a = 0 
			//19.2	For 	i = 0 to iterations do
			//a = a + (Hash(pseed + i))∗ 2 ^^(i * outlen)
			//19.3	pseed = pseed + iterations + 1.
			//19.4	a = 2 + (a mod (p–3)).
			for(register int i = 0; i < iteration_blocks; i++)
			{
				Hash(outlen
					, (BitSequence *)pseed->_mp_d
					, pseed->_mp_size * sizeof(mp_limb_t) * 8
					, & buf[outlen/8 * i]);
				mpz_add_ui(pseed, pseed, 1);
			}
			mpz_import(x, iteration_blocks * outlen / 8, 1, 1, 0, 0, buf);
			mpz_sub_ui(tmp, p, 3);
			mpz_fdiv_r(z, x, tmp);
			mpz_add_ui(x, z, 2);
			//Comment: Test p for primality:  
			//19.5	z = a^^(2(t p2  − y) p1) mod p. 
			//19.6	If ((1 = GCD(z–1, p)) and (1 = (z^^p0  mod p)), then return (SUCCESS, p, p1, p2, pseed).
			mpz_mul(z, _tp2_y, p1);
			mpz_mul_ui(tmp, z, 2);
			mpz_powm(z, x, tmp, p);
			mpz_sub_ui(tmp, z, 1);
			mpz_gcd(x, tmp, p);	// tmp = z - 1
			if(mpz_cmp_ui(x, 1) == 0)
			{
				mpz_powm(x, z, p0, p);
				if(mpz_cmp_ui(x, 1) == 0)
				{
					status = true;
					goto l_return;
				}
			}
		}
		//20.	If (pgen_counter ≥ 5L), then return  (FAILURE, 0, 0, 0, 0).  
		//21.	t = t + 1. 
		//22.	Go to step 16. 
		mpz_add_ui(t, t, 1);
	} while(pgen_counter < 5 * L);
l_false:
	mpz_set_ui(p, 0);
	mpz_set_ui(p1, 0);
	mpz_set_ui(p2, 0);
	mpz_set_ui(pseed, 0);

l_return:
	mpz_clears(p2seed, p0seed, p0, t, tmp, x, y, z, _2p0p1, _2p0p1p2, _tp2_y, NULL);
	return status;
} 
