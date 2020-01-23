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

#include <stdio.h>
#include "CryptoStub.h"

#define CRYPTO_SALT_LENGTH		16	// 128 bits
#define USER_PASSPHRASE_MAXLEN	48	// effectively maximum 47 octets, including the terminating zero

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



SINLINE
int MakeSaltedPassword(octet clientInputHash[CRYPTO_NACL_HASHBYTES], const octet salt[CRYPTO_SALT_LENGTH], const char* inputPassword)
{
	const int len = (int)strlen(inputPassword);
	octet clientPasswordHashMaterial[CRYPTO_SALT_LENGTH + USER_PASSPHRASE_MAXLEN];

	memcpy(clientPasswordHashMaterial + CRYPTO_SALT_LENGTH, inputPassword
		, (len >= USER_PASSPHRASE_MAXLEN ? USER_PASSPHRASE_MAXLEN : len));
	memcpy(clientPasswordHashMaterial, salt, CRYPTO_SALT_LENGTH);
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
	for (register unsigned i = 0; i < sizeof(responseMaterial) / sizeof(uint64_t); i++)
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

// *S --> C, [in FSP's ACK_CONNECT_REQ]: /Welcome and identity of S/Public Key_S


SINLINE
void InitCHAKAClient(SCHAKAPublicInfo &chakaPubInfo, octet *bufPrivateKey)
{
	CryptoNaClKeyPair(chakaPubInfo.selfPublicKey, bufPrivateKey);
	chakaPubInfo.clientNonce = htobe64(NowUTC()); 
}

// *C --> S, [in FSP's PERSIST, had better with EoT]: /Public Key_C/Timestamp_C/Greeting/Encrypted identity of C


// Remark
//	The server both answers the client's initial challenge and pushes back its own challenge
SINLINE
bool CHAKAChallengeByServer(SCHAKAPublicInfo &chakaPubInfo
	, octet *serverResponse, const octet passwordHash[CRYPTO_NACL_HASHBYTES])
{
	// The server precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	if(d < -300000000 || d > 300000000)	// i.e. 300 seconds
	{
#ifndef NDEBUG
		printf_s("Protocol is broken: timer difference exceeds 5 minute.\n");
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
bool CHAKAResponseByClient(SCHAKAPublicInfo &chakaPubInfo, octet * clientInputHash, octet *cResponse)
{
	// The client prechecks the validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	if(d < -300000000 || d > 300000000)	// i.e. 300 seconds
	{
#ifndef NDEBUG
		printf_s("Protocol is broken: timer difference exceeds 5 minute.\n");
#endif
		return false;
	}

	MakeResponse(cResponse, clientInputHash, chakaPubInfo.selfPublicKey, chakaPubInfo.clientNonce, chakaPubInfo.serverRandom);

	// The client check the response of the server
	if ( (memcmp(cResponse, chakaPubInfo.peerResponse, CRYPTO_NACL_HASHBYTES)) != 0)
		return false;

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


// A very simple stream encryption/decryption meant to protect privacy of a short message such as a user's name/client's id
// Remark
//	May overwrite content point by bufSharedKey given in the structured parameter
SINLINE
void ChakaStreamcrypt(octet *buf
	, const octet *input, int32_t len
	, uint64_t nonce, const octet bufSharedKey[CRYPTO_NACL_KEYBYTES])
{
	struct
	{
		uint64_t nonce;
		octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
	} km;
	km.nonce = nonce;
	memcpy(km.bufSharedKey, bufSharedKey, CRYPTO_NACL_KEYBYTES);
	//^Let's the compiler optimize off additional copy
	octet hashValue[SHA256_DIGEST_SIZE];
	register int32_t k;
	for (register int32_t i = 0; len > 0; len -= k)
	{
		km.nonce ^= htobe64((uint64_t)i + 1);
		sha256_hash(hashValue, (octet *)& km, sizeof(km));
		//
		k = (len >= SHA256_DIGEST_SIZE ? len : SHA256_DIGEST_SIZE);
		for(register int32_t j = 0; j < k; j++)
		{
			buf[i] = input[i] ^ hashValue[j];
			i++;
		}
		//
		memcpy(km.bufSharedKey, hashValue, SHA256_DIGEST_SIZE);
	}
}

#endif
