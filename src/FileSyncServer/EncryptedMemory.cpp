#include "stdafx.h"


// assume that address space layout randomization keep the secret hard to find
static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];

static char		*fileName = "$memory.^";
static uint8_t	*bytesToSend;
static size_t	sizeOfBuffer = TEST_MEM_SIZE;


void SendMemoryPatternEncyrpted()
{
	bytesToSend = (uint8_t *)malloc(sizeOfBuffer);
	if(bytesToSend == NULL)
	{
		printf_s("Cannot allocate memory block size of %zu bytes\n", sizeOfBuffer);
		return;
	}

	for(register int i = 0; (size_t)i < sizeOfBuffer / sizeof(uint32_t); i++)
	{
		* (uint32_t *) & bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}

	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	unsigned char *bufPublicKey = (unsigned char *)thisWelcome + mLen;;
	memcpy(thisWelcome, defaultWelcome, mLen);	//+\000012345678901234567890123456789012
	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

	WaitConnection(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES, onAccepted);
}


static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nEncyrptedMemory onAccepted: handle of FSP session/Fiber ID = 0x%X\n", (uint32_t)(intptr_t)h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}


static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);

	printf_s("\nTo install the negotiated shared key instantly...\n");
	InstallAuthenticKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX);

	printf_s("\tTo send filename to the remote end...\n");
	WriteTo(h, fileName, (int)strlen(fileName) + 1, EOF, onFileNameSent);
}


// for memory pattern this is a 'virtual' filename
static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");

	// We insisted on sending even if only a small buffer of 1 octet is available
	r = GetSendBuffer(h, 1, toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		finished = true;
		Dispose(h);
		return;
	}

	//// Besides, open another reverse-connection to send the signature
	//StartToSendSignature(h);

	printf_s("And we expected success acknowledgement\n");
	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	static int offset = 0;
	if(capacity <= 0)
	{
		finished = true;
		return -ENOMEM;
	}

	int bytesRead = __min(sizeOfBuffer - offset, (size_t)capacity);
	memcpy(batchBuffer, bytesToSend + offset, bytesRead);
	printf_s("To send %d bytes to the remote end, %d bytes have been sent\n", bytesRead, offset);

	offset += bytesRead;

	// Would wait until acknowledgement is received. Shutdown is called in onResponseReceived
	bool r = (offset >= (int)sizeOfBuffer);
	int err = SendInline(h, batchBuffer, bytesRead, (int8_t)r);
	if(r)
	{
		printf("All content has been sent. To wait acknowledgement and shutdown.\n");
		return EOF;
	}

	return err;	// == 0 meaning no error and continue to process next block
}
