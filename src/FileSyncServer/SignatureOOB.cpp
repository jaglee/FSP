#include "stdafx.h"

static	char	signature[] = "the session is finished";

//
static int FSPAPI onMultiplied(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: Fiber ID = %u", (uint32_t)(intptr_t)h);
	if(h == NULL)
	{
		printf_s("\nConnection failure.\n");
		return -1;
	}

	return 0;
}



static void FSPAPI onShutdown(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Fiber ID = 0x%X, the session has been shutdown.\n", (uint32_t)(intptr_t)h);
	if(code != FSP_NotifyToFinish)
	{
		printf_s("Should got TO_FINISH, but service code = %d, return %d\n", code, value);
		return;
	}

	Dispose(h);
	return;
}


// The near end finished the work, close th
static void FSPAPI onSignatureSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the signature: %d\n", r);
	Dispose(h);
	Shutdown(h, onShutdown);
	return;
}



void StartToSendSignature(FSPHANDLE h)
{
	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	// parms.onAccepting = NULL;
	parms.onAccepted = onMultiplied;
	parms.onError = onNotice;
	parms.recvSize = 0;	// the underlying service would give the minimum, however
	parms.sendSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.welcome = signature;
	parms.len = (unsigned short)sizeof(signature);
	if(MultiplyAndWrite(h, & parms, END_OF_TRANSACTION, onSignatureSent) == NULL)
	{
		printf("Warning!? Failed to multiply the connection.\n");
		return;
	}
}
