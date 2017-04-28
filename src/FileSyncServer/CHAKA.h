// To borrow some stdint definitions
#include "../gcm-aes.h"

// TODO: for client side the key-pair is definitely ephemeral
const int CRYPT_NACL_HASHBYTES = 64;
//^ crypto_hash_sha512_tweet_BYTES

struct SCHAKAPublicInfo
{
	// received by the client in ACK_CONNECT_REQUEST:
	unsigned char	serverPublicKey[CRYPTO_NACL_KEYBYTES];
	// received by the server in the first round
	unsigned char	clientPublicKey[CRYPTO_NACL_KEYBYTES];
	timestamp_t		clientNonce;
	//^suffixed with the client's ID
	// received by the client in the first round:
	unsigned char	salt[CRYPT_NACL_HASHBYTES];
	timestamp_t		serverNonce;
	uint64_t		serverRandom;
	// suffixed with the server's response:
	unsigned char	peerResponse[CRYPT_NACL_HASHBYTES];
	//^received by the server in the second round: the client's response
};
