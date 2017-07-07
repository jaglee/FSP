/**
 * A group of chained functions within FileSyncServer. The group meant to send
 * to the remote end a large memory block filled with some certern pattern.
 */
#include "stdafx.h"
#include "defs.h"

static int FSPAPI onAccepted(FSPHANDLE, PFSP_Context);

static char		*fileName = "$memory.^";
static uint8_t	bytesToSend[TEST_MEM_SIZE];


// The entry function of the group
void SendMemoryPattern()
{
	for(register int i = 0; i < sizeof(bytesToSend) / sizeof(uint32_t); i++)
	{
		* (uint32_t *) & bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}

	WaitConnection(defaultWelcome, strlen(defaultWelcome) + 1, onAccepted);
}



// If the request of the connection by the remote end is accepted send the hard-coded
// filename designated a large memory block to the remote end
// (for memory pattern this is a 'virtual' filename)
static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nMemoryFile onAccepted: handle of FSP session %p\n", h);
	// TODO: check connection context

	printf_s("\tTo send filename to the remote end...\n");
	WriteTo(h, fileName, (int)strlen(fileName) + 1, EOF, onFileNameSent);

	return 0;
}



// Request send buffer to send the content of the large memory block
// when it is acknowledged that the filename has been sent.
// We insisted on sending even if only a small buffer of 1 octet is available
// And we expected success acknowledgement on the application layer
static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");

	r = GetSendBuffer(h, sizeof(bytesToSend), toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		Dispose(h);
		return;
	}

	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



// The iteration body that transfers the segments of the large memory block one by one
// The large memory block is segmented by available buffer space memory each time the
// function is called. Here the buffer space memory is shared between ULA and LLS.
static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	static int offset = 0;
	if(capacity < 0)
	{
		Dispose(h);
		return -ENOMEM;
	}

	int bytesRead = __min(sizeof(bytesToSend) - offset, (size_t)capacity);
	memcpy(batchBuffer, bytesToSend + offset, bytesRead);
	printf_s("To send %d bytes to the remote end. %d bytes have been sent before.\n", bytesRead, offset);

	offset += bytesRead;

	return SendInline(h, batchBuffer, bytesRead, (int8_t)(offset >= sizeof(bytesToSend)));
}
