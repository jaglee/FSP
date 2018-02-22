/**
 * A group of chained functions within FileSyncServer. The group meant to send
 * to the remote end a large memory block filled with some certern pattern
 * with encryption turned on.
 */

#include "stdafx.h"
#include "defs.h"

static char	*fileName = "$memory.^";
static uint8_t	*bytesToSend;
static size_t	sizeOfBuffer;


void PrepareMemoryPattern(size_t sz1)
{
	bytesToSend = (uint8_t *)malloc(sizeOfBuffer = sz1);
	if(bytesToSend == NULL)
	{
		printf_s("Cannot allocate memory block size of %zu bytes\n", sizeOfBuffer);
		return;
	}

	for(register int i = 0; (size_t)i < sizeOfBuffer / sizeof(uint32_t); i++)
	{
		* (uint32_t *) & bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}
}



int FSPAPI SendMemory_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nEncryptedMemory onAccepted: handle of FSP session %p\n", h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}


// On receive peer's public key establish the shared session key
// and write to the remote end the hard-coded special filename
// for memory pattern this is a 'virtual' filename
static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);

	printf_s("\nTo install the negotiated shared key instantly...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	printf_s("\tTo send filename to the remote end...\n");
	// multi-byte character set only:
	WriteTo(h, fileName, (int)strlen(fileName) + 1, TO_END_TRANSACTION, onFileNameSent);
}



// Besides, open another reverse-connection to send the signature
static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");

	// We insisted on sending even if only a small buffer of 1 octet is available
	r = GetSendBuffer(h, toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		Dispose(h);
		return;
	}

	StartToSendSignature(h);

	printf_s("And we expected success acknowledgement\n");
	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



// the iteration body that transfer to the remote end the segments of the memory block one by one
static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	static int offset = 0;
	if(capacity < 0)
	{
		Dispose(h);
		return -ENOMEM;
	}

	int bytesRead = __min((int32_t)sizeOfBuffer - offset, capacity);
	memcpy(batchBuffer, bytesToSend + offset, bytesRead);
	offset += bytesRead;

	// Would wait until acknowledgement is received. Shutdown is called in onResponseReceived
	bool r = (offset >= (int)sizeOfBuffer);
	int n = SendInline(h, batchBuffer, bytesRead, r);
	printf_s("%d bytes sent to the remote end in %d block(s). Totally %d bytes sent.\n", bytesRead, n, offset);
	if(r)
	{
		printf("All content has been sent. To wait acknowledgement and shutdown.\n");
		return EOF;
	}

	return n;	// non negative meaning no error and continue to process next block
}
