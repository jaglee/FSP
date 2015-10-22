#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../FSP_API.h"

extern	const char		*defaultWelcome;

extern volatile bool	finished;
extern FSPHANDLE		hFspListen;

extern void FSPAPI WaitConnection(const char *, unsigned short, CallbackConnected);
extern int	FSPAPI onAccepting(FSPHANDLE, void *, PFSP_IN6_ADDR);
extern void FSPAPI onReturn(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value);

static int	FSPAPI	onAccepted(FSPHANDLE, PFSP_Context);
static void FSPAPI	onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI	toSendNextBlock(FSPHANDLE, void *, int32_t);

static char		*fileName = "$memory.^";
static	uint8_t	bytesToSend[0x20000];	// 128KB

void SendMemoryPattern()
{
	for(register int i = 0; i < sizeof(bytesToSend) / sizeof(uint32_t); i++)
	{
		* (uint32_t *) & bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}

	WaitConnection(defaultWelcome, strlen(defaultWelcome) + 1, onAccepted);
}


// This function is for tracing purpose
static int	FSPAPI onAccepting(FSPHANDLE h, void *p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept handle of FSP session: 0x%08X\n", h);
	const FSP_PKTINFO & pktInfo = *(FSP_PKTINFO *)p;
	printf_s("Interface: %d, session Id: %u\n", pktInfo.ipi6_ifindex, pktInfo.idALF);
	printf_s("Remote address: 0x%llX::%X::%X\n", remoteAddr->u.subnet, remoteAddr->idHost, remoteAddr->idALF);
	return 0;	// no opposition
}



static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: Fiber ID = %u\n", (uint32_t)(intptr_t)h);
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
