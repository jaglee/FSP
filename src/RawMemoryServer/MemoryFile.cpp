/**
 * A group of chained functions within FileSyncServer. The group meant to send
 * to the remote end a large memory block filled with some certern pattern.
 */
#include "stdafx.h"

extern const char* defaultWelcome;
extern unsigned char	bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];
extern unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];

extern volatile bool	toMultiply;
extern volatile bool	finished;
extern volatile	bool	r2Finish;

extern FSPHANDLE		hFspListen;
extern char				linebuf[80];


// Following file scope variables and functions have limited access border 
static uint64_t nRequested;
static uint64_t nPrepared;



// The iteration body that transfers the segments of the large memory block one by one
// The large memory block is segmented by available buffer space memory each time the
// function is called. Here the buffer space memory is shared between ULA and LLS.
static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	if(capacity <= 0)
	{
		Dispose(h);
		return -ENOMEM;
	}

	int32_t nToSend = (int32_t)__min(nRequested - nPrepared, capacity);
	if (nToSend <= 0)
		return EOF;

	// Set the memory pattern on fly; very long stream (whose length may be up to 2^64 -1 ) is possible
	int nDWord = nToSend / (int)sizeof(uint32_t);
	for (register int i = 0; i < nDWord; i++)
	{
		((uint32_t *)batchBuffer)[i] = htobe32(uint32_t(nPrepared + i));
	}
	// to make life easier just apply zero padding; let the optimizer make the code effecient 
	for (register int i = 0; i < nToSend - (int)sizeof(uint32_t) * nDWord; i++)
	{
		((octet *)batchBuffer)[sizeof(uint32_t) * nDWord + i] = 0;
	}

	printf_s("To send %d bytes to the remote end. %llu bytes have been sent before.\n", nToSend, nPrepared);
	nPrepared += nToSend;

	return SendInline(h, batchBuffer, nToSend, (nPrepared >= nRequested), NULL);
}



// Request send buffer to send the content of the large memory block
// when it is acknowledged that the filename has been sent.
// We insisted on sending even if only a small buffer of 1 octet is available
// And we expected success acknowledgement on the application layer
static void FSPAPI onRequestedSizeReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if (r < 0)
	{
		Dispose(h);
		return;
	}

	// No needs to preallocate memory! Arbitrarily long stream might be sent
	printf_s("To send memory segment of %llu octets.\n", nRequested);
	//
	r = GetSendBuffer(h, toSendNextBlock);
	if (r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		Dispose(h);
		return;
	}
}



// If the request of the connection by the remote end is accepted send the hard-coded
// filename designated a large memory block to the remote end
// (for memory pattern this is a 'virtual' filename)
int FSPAPI WeakSecurity_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nMemoryFile onAccepted: handle of FSP session %p\n", h);
	printf_s("To send memory pattern to the remote end directly:\n");

	// Suppose the host byte orders of the peers are the same
	// Read length of request memory pattern length.
	nPrepared = 0;
	ReadFrom(h, &nRequested, sizeof(nRequested), onRequestedSizeReceived);

	return 0;
}
