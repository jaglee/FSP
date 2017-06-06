/*
 * The build modules of CHallenge-response Authenticated Key Agreement protocol
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

#ifndef _CH_AUTH_KEY_AGREEMENT_H
#define _CH_AUTH_KEY_AGREEMENT_H

// To borrow some stdint definitions
#include "../gcm-aes.h"

#include "CryptoStub.h"
#include "sm3.h"

#define CRYPTO_SALT_LENGTH	16	// 128 bits
#define SESSION_KEY_SIZE	32	// 256 bits

struct SCHAKAPublicInfo
{
	octet			peerPublicKey[CRYPTO_NACL_KEYBYTES];
	octet			selfPublicKey[CRYPTO_NACL_KEYBYTES];
	timestamp_t		clientNonce;
	//^suffixed with the client's ID
	// received by the client in the first round:
	octet			salt[CRYPTO_SALT_LENGTH];
	timestamp_t		serverNonce;
	uint64_t		serverRandom;
	// suffixed with the server's response:
	octet			peerResponse[CRYPTO_NACL_HASHBYTES];
	//^received by the server in the second round: the client's response
};



/**
 * inline functions
 */

#ifdef __cplusplus
#define SINLINE static inline
#else
#define SINLINE static __inline__
#endif



SINLINE
int MakeSaltedPassword(octet clientInputHash[CRYPTO_NACL_HASHBYTES], const octet salt[CRYPTO_SALT_LENGTH], const char * inputPassword)
{
	const int len = strlen(inputPassword);
	octet *clientPasswordHashMaterial = (octet *)_alloca(CRYPTO_SALT_LENGTH + len);
	if(clientPasswordHashMaterial == NULL)
	{
#ifdef TRACE
		printf_s("Stack overflow in %s, line#%d\n", __FILE__, __LINE__ - 4);
#endif
		return -1;
	}

	memcpy(clientPasswordHashMaterial, salt, CRYPTO_SALT_LENGTH);
	memcpy(clientPasswordHashMaterial + CRYPTO_SALT_LENGTH, inputPassword, len);
	return CryptoNaClHash(clientInputHash, clientPasswordHashMaterial, CRYPTO_SALT_LENGTH + len);
}



SINLINE
void MakeResponse(octet cResponse[CRYPTO_NACL_HASHBYTES]
	, const octet passwordHash[CRYPTO_NACL_HASHBYTES]
	, const octet bufPublicKey[CRYPTO_NACL_KEYBYTES]
	, timestamp_t nonce
	, uint64_t mask)
{
	octet responseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(timestamp_t)];
	octet presponse[CRYPTO_NACL_HASHBYTES * 2];
	// To regenerate the hmac value with the user's input password
	memcpy(responseMaterial, bufPublicKey, CRYPTO_NACL_KEYBYTES);
	*(timestamp_t *)(responseMaterial + CRYPTO_NACL_KEYBYTES) = nonce;
	// we're definitely sure that the length of responseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(responseMaterial) / sizeof(uint64_t); i++)
	{
		((uint64_t *)responseMaterial)[i] ^= mask;
	}

	CryptoNaClHash(presponse + CRYPTO_NACL_HASHBYTES, responseMaterial, sizeof(responseMaterial));
	memcpy(presponse, passwordHash, CRYPTO_NACL_HASHBYTES);
	CryptoNaClHash(cResponse, presponse, sizeof(presponse));

}



SINLINE
void InitCHAKAServer(SCHAKAPublicInfo &chakaPubInfo, const octet bufPublicKey[CRYPTO_NACL_KEYBYTES])
{
	randombytes(& chakaPubInfo.serverRandom, sizeof(chakaPubInfo.serverRandom));
	memcpy(chakaPubInfo.selfPublicKey, bufPublicKey, CRYPTO_NACL_KEYBYTES);
	chakaPubInfo.serverNonce = htobe64(NowUTC());
}

// *S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S


SINLINE
void InitCHAKAClient(SCHAKAPublicInfo &chakaPubInfo, octet bufPrivateKey[CRYPTO_NACL_KEYBYTES])
{
	CryptoNaClKeyPair(chakaPubInfo.selfPublicKey, bufPrivateKey);
	chakaPubInfo.clientNonce = htobe64(NowUTC()); 
}

// *C --> S, [in FSP's PERSIST, had better with EoT]: /Public Key_C/Timestamp_C/Greeting/Encrypted identity of C


// Remark
//	The server both answers the client's initial challenge and pushes back its own challenge
SINLINE
bool CHAKAChallengeByServer(SCHAKAPublicInfo &chakaPubInfo,
							octet serverResponse[CRYPTO_NACL_HASHBYTES],
							const octet passwordHash[CRYPTO_NACL_HASHBYTES])
{
	// The server precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	if(d < -60000000 || d > 60000000)	// i.e. 60 seconds
	{
#ifdef TRACE
		printf_s("Protocol is broken: timer difference exceeds 1 minute.\n");
#endif
		return false;
	}

	MakeResponse(serverResponse, passwordHash, chakaPubInfo.peerPublicKey, chakaPubInfo.clientNonce, chakaPubInfo.serverRandom);
	return true;
}

//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))


// Suppose the client get the salt
SINLINE
bool CHAKAResponseByClient(SCHAKAPublicInfo &chakaPubInfo
	, octet clientInputHash[CRYPTO_NACL_HASHBYTES]
	, octet cResponse[CRYPTO_NACL_HASHBYTES])
{
	// The client prechecks the validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	//
	//
	if(d < -60000000 || d > 60000000)
	{
#ifdef TRACE
		printf_s("Protocol is broken: timer difference exceeds 1 minute.\n");
#endif
		return false;
	}

	MakeResponse(cResponse, clientInputHash, chakaPubInfo.selfPublicKey, chakaPubInfo.clientNonce, chakaPubInfo.serverRandom);

	// The client check the response of the server
	if ( (memcmp(cResponse, chakaPubInfo.peerResponse, CRYPTO_NACL_HASHBYTES)) != 0)
	{
#ifdef TRACE
		printf_s("Username or password is wrong.\n");
#endif
		return false;
	}

	// generate the client's response
	MakeResponse(cResponse, clientInputHash, chakaPubInfo.peerPublicKey, chakaPubInfo.serverNonce, chakaPubInfo.serverRandom);

	return true;
}

//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))


SINLINE
bool CHAKAValidateByServer(SCHAKAPublicInfo &chakaPubInfo, const octet passwordHash[CRYPTO_NACL_HASHBYTES])
{
	octet expectedResponse[CRYPTO_NACL_HASHBYTES];
	MakeResponse(expectedResponse, passwordHash, chakaPubInfo.selfPublicKey, chakaPubInfo.serverNonce, chakaPubInfo.serverRandom);

	return (memcmp(expectedResponse, chakaPubInfo.peerResponse, CRYPTO_NACL_HASHBYTES) == 0);
}



SINLINE
void ChakaDeriveKey(octet sessionKey[SESSION_KEY_SIZE]
	, const octet saltedPassword[CRYPTO_NACL_HASHBYTES]
	, const SCHAKAPublicInfo &chakaPubInfo
	, const octet bufPrivateKey[CRYPTO_NACL_KEYBYTES])
{
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
	sm3_context ctx;
	CryptoNaClGetSharedSecret(bufSharedKey, chakaPubInfo.peerPublicKey, bufPrivateKey);
	//
	sm3_hmac_starts(& ctx, (octet *)saltedPassword, CRYPTO_NACL_HASHBYTES);
	sm3_hmac_update(& ctx, bufSharedKey, sizeof(bufSharedKey));
	sm3_hmac_update(& ctx, (octet *)& chakaPubInfo.serverRandom, sizeof(uint64_t));
	sm3_hmac_finish(& ctx, sessionKey);
}



// A very simple stream encryption/decryption meant to protect privacy of a short message such as a user's name/client's id
SINLINE
void ChakaStreamcrypt(octet *buf
	, uint64_t nonce
	, const octet *input, int32_t len
	, const octet peerPublicKey[CRYPTO_NACL_KEYBYTES], const octet bufPrivateKey[CRYPTO_NACL_KEYBYTES])
{
	const int HASH_BLOCK_SIZE = 32;
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, peerPublicKey, bufPrivateKey);

	octet hashValue[HASH_BLOCK_SIZE];
	octet hashAsInput[HASH_BLOCK_SIZE];

	sm3_hmac(bufSharedKey, CRYPTO_NACL_KEYBYTES, (unsigned char *) & nonce, sizeof(nonce), hashValue);

	for(register int32_t i = 0;
		i < len;
		memcpy(hashAsInput, hashValue, HASH_BLOCK_SIZE),
		sm3_hmac(bufSharedKey, CRYPTO_NACL_KEYBYTES, hashAsInput, HASH_BLOCK_SIZE, hashValue))
	{
		register int32_t k = min(HASH_BLOCK_SIZE, len);
		for(register int32_t j = 0; j < k; j++)
		{
			buf[i] = input[i] ^ hashValue[j];
			i++;
		}
	}
}

#endif
