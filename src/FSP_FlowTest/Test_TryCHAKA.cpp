#include "stdafx.h"

//Challenge-responde Handshake Authenticated Key Agreement [/Signature: certificate is out-of-band]
//	S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
//	C --> S, [in FSP's PERSIST, had better with EoT]: /Greeting and identity of C/Public Key_C/Timestamp_C
//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret]
//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret]
// Well, SRP6 leaks salt as well. Data collected in network together with shadow file spoofed could break the protocol
// To be implemented: EdDSA?
// CryptoNaClScalarMult();	// the signaure?
// HMAC: H(K XOR opad, H(K XOR ipad, text))
void TryCHAKA()
{
	const int CRYPT_NACL_HASHBYTES = 64;
	//^ crypto_hash_sha512_tweet_BYTES
	const char *salt = "\001\002\003\004\005\006\007\010";
	const char *U = "FSP_FlowTest";
	const char *S = "FSP_Srv";
	const char *password = "Passw0rd";

	// prepare password shadow
	ALIGN(8)
	static uint8_t passwordHash[CRYPT_NACL_HASHBYTES];
	uint8_t *shadowMaterial = (uint8_t *)_alloca(strlen(salt) + strlen(password));
	memcpy(shadowMaterial, salt, strlen(salt));
	memcpy(shadowMaterial + strlen(salt), password, strlen(password));
	CryptoNaClHash(passwordHash, shadowMaterial, strlen(salt) + strlen(password));

	// first round S->C
	ALIGN(8)
	static uint8_t serverPrivateKey[CRYPTO_NACL_KEYBYTES];
	static uint8_t serverPublicKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClKeyPair(serverPublicKey, serverPrivateKey);

	// first round C->S
	static uint8_t clientPrivateKey[CRYPTO_NACL_KEYBYTES];
	static uint8_t clientPublicKey[CRYPTO_NACL_KEYBYTES];
	timestamp_t clientNonce = NowUTC();
	CryptoNaClKeyPair(clientPublicKey, clientPrivateKey);
	// together with client's identity

	// TODO: the server should precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	// TODO: the server should make sure that the clientPublicKey is not a reflection of serverPublicKey
	timestamp_t serverNonce = NowUTC();
	// prepare the random bits (as an alternative to HMAC)
	uint32_t serverRandom[2];
	rand_w32(serverRandom, 2);
	// second round S->C
	ALIGN(8)
	uint8_t serverResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(clientNonce)];
	uint8_t serverPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t serverReponse[CRYPT_NACL_HASHBYTES];
	memcpy(serverResponseMaterial, clientPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(serverResponseMaterial + CRYPTO_NACL_KEYBYTES) = (uint64_t)htobe64(clientNonce);
	// we're definitely sure that the length of serverResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(serverResponseMaterial) / sizeof(serverRandom); i++)
	{
		((uint64_t *)serverResponseMaterial)[i] ^= *((uint64_t *)serverRandom);
	}

	CryptoNaClHash(serverPresponse + CRYPT_NACL_HASHBYTES, serverResponseMaterial, sizeof(serverResponseMaterial));
	memcpy(serverPresponse, passwordHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(serverReponse, serverPresponse, sizeof(serverPresponse));

	// second round C->S
	char inputPassword[80];
	fputs("Please input the password: ", stdout);
	gets_s<80>(inputPassword);	// this is just a demonstration, so don't hide the input

	// Suppose the client get the salt
	ALIGN(8) uint8_t clientInputHash[CRYPT_NACL_HASHBYTES];
	uint8_t *clientPasswordHashMaterial = (uint8_t *)_alloca(strlen(salt) + strlen(inputPassword));
	memcpy(clientPasswordHashMaterial, salt, strlen(salt));
	memcpy(clientPasswordHashMaterial + strlen(salt), inputPassword, strlen(inputPassword));
	CryptoNaClHash(clientInputHash, clientPasswordHashMaterial, strlen(salt) + strlen(inputPassword));
	//

	// TODO: the client should precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	// The client check the response of the server
	ALIGN(8)
	uint8_t clientResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(serverNonce)];
	uint8_t clientPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t clientResponse[CRYPT_NACL_HASHBYTES];
	memcpy(clientResponseMaterial, serverPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(clientResponseMaterial + CRYPTO_NACL_KEYBYTES) = (uint64_t)htobe64(serverNonce);
	// we're definitely sure that the length of clientResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(clientResponseMaterial) / sizeof(serverRandom); i++)
	{
		((uint64_t *)clientResponseMaterial)[i] ^= *((uint64_t *)serverRandom);
	}
	CryptoNaClHash(clientPresponse + CRYPT_NACL_HASHBYTES, clientResponseMaterial, sizeof(clientResponseMaterial));
	memcpy(clientPresponse, clientInputHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(clientResponse, clientPresponse, sizeof(clientPresponse));

	// The response of the client is sent to the server and the user agent is authenticated.
	ALIGN(8)
	uint8_t expectedPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t expectedResponse[CRYPT_NACL_HASHBYTES];
	memcpy(expectedPresponse + CRYPT_NACL_HASHBYTES, clientPresponse + CRYPT_NACL_HASHBYTES, CRYPT_NACL_HASHBYTES);
	memcpy(expectedPresponse, passwordHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(expectedResponse, expectedPresponse, sizeof(expectedPresponse));

	int r = memcmp(expectedResponse, clientResponse, CRYPT_NACL_HASHBYTES);
	assert(strcmp(inputPassword, password) == 0 && r == 0 || strcmp(inputPassword, password) != 0 && r != 0);
}
