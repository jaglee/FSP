#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../FSP_API.h"


static	bool	finished;
static	char	signature[] = "the session is finished";


static int FSPAPI onMultiplied(FSPHANDLE h, PFSP_Context ctx);
static void FSPAPI onSignatureSent(FSPHANDLE h, FSP_ServiceCode c, int r);


static void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: Fiber ID = %u, service code = %d, return %d\n", (uint32_t)(intptr_t)h, code, value);
	if(value < 0)
	{
		Dispose(h);
		finished = true;
		return;
	}
}



////
//static void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
//{
//	printf_s("Fiber ID = %u, session was to shut down.\n", (uint32_t)(intptr_t)h);
//	if(code != FSP_NotifyRecycled)
//	{
//		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);
//		return;
//	}
//
//	Dispose(h);
//	finished = true;
//	return;
//}



//
static void FSPAPI onPeerClose(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Fiber ID = %u, the server shutdown the session.\n", (uint32_t)(intptr_t)h);
	if(code != FSP_NotifyToFinish)
	{
		printf_s("Should got TO_FINISH, but service code = %d, return %d\n", code, value);
		return;
	}

	Dispose(h);	// should be graceful 'close' socket
	finished = true;
	return;
}



void StartToSendSignature(FSPHANDLE h)
{
	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	// parms.beforeAccept = NULL;
	parms.afterAccept = onMultiplied;
	parms.onError = onNotice;
	parms.onFinish = onPeerClose;
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



//
static int FSPAPI onMultiplied(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: Fiber ID = %u", (uint32_t)(intptr_t)h);
	if(h == NULL)
	{
		printf_s("\nConnection failure.\n");
		finished = true;
		return -1;
	}

	return 0;
}




static void FSPAPI onSignatureSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the signature: %d\n", r);
	finished = true;
	Dispose(h);
	return;
}
