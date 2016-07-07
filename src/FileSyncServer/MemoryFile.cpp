#include "stdafx.h"


static char		*fileName = "$memory.^";
static uint8_t	bytesToSend[TEST_MEM_SIZE];

void SendMemoryPattern()
{
	for(register int i = 0; i < sizeof(bytesToSend) / sizeof(uint32_t); i++)
	{
		* (uint32_t *) & bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}

	WaitConnection(defaultWelcome, strlen(defaultWelcome) + 1, onAccepted);
}



static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nMemoryFile onAccepted: handle of FSP session/Fiber ID = 0x%X\n", (uint32_t)(intptr_t)h);
	// TODO: check connection context

	printf_s("\tTo send filename to the remote end...\n");
	WriteTo(h, fileName, (int)strlen(fileName) + 1, END_OF_MESSAGE, onFileNameSent);

	return 0;
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

	// And we expected success acknowledgement
	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	static int offset = 0;
	if(capacity <= 0)
	{
		finished = true;
		return -1;
	}

	int bytesRead = __min(sizeof(bytesToSend) - offset, (size_t)capacity);
	memcpy(batchBuffer, bytesToSend + offset, bytesRead);
	printf_s("To send %d bytes to the remote end, %d bytes have been sent\n", bytesRead, offset);

	offset += bytesRead;
	bool r = (offset >= sizeof(bytesToSend));

	SendInline(h, batchBuffer, bytesRead, r ? END_OF_MESSAGE : NOT_END_ANYWAY);
	if(r)
	{
		printf("All content has been sent. To shutdown.\n");
		if(Shutdown(h, onFinished) != 0)
		{
			Dispose(h);
			finished = true;
		}
		return -1;
	}

	return 0;
}
