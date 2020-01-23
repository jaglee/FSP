#include "../Crypto/CryptoStub.h"
#include "../FSP_SRV/blake2b.h"
#include "../FSP_SRV/fsp_srv.h"

static octet	keyInternalRand[FSP_MAX_KEY_SIZE];

int main(int argc, char *argv[])
{
	// assume length of pid_t is no greater than FSP_MAX_KEY_SIZE
	u32 key32[FSP_MAX_KEY_SIZE / sizeof(u32)];
	*(pid_t *)keyInternalRand = getpid();
	rand_w32(key32, FSP_MAX_KEY_SIZE / sizeof(u32));
	memcpy(keyInternalRand, key32, FSP_MAX_KEY_SIZE);

	u32 words[4];
	for(int i = 0; i < argc; i++)
	{
		rand_w32(words, 4);
		printf("%08X %08X %08X %08X\n", words[0], words[1], words[2], words[3]);
	}

	octet block513[513];
	randombytes(block513, sizeof(block513));
	for(unsigned i = 0; i < sizeof(block513); i ++)
	{
		printf("%02X ", block513[i]);
		if((i + 1)%32 == 0)
			printf("\n");
	}
	printf("\n");
}


// Given
//	u32 *	pointer to the buffer to store the random 32-bit word
//	int		number of 32-bit words to generate
// Do
//	Generate (pseudo) random number of designated length and store it in the buffer given
extern "C" void rand_w32(u32 *p, int n)
{
	static uint64_t nonce;
	struct
	{
		struct timeval tv;
		uint64_t nonce;
	} _rm;	// random material
	_rm.nonce = _InterlockedIncrement(&nonce);
	gettimeofday(&_rm.tv, NULL);
	blake2b(p, n * sizeof(u32), keyInternalRand, sizeof(keyInternalRand), &_rm, sizeof(_rm));
}
