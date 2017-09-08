/**
 * A small group of functions in FileSyncServer. The group meant to handle the connection multiplication instance
 */
#include "stdafx.h"
#include "defs.h"

volatile bool	r2Finish = true;	// by default there is no reverse socket and it is assume to be finished
static	char	signature[] = "the session is finished";

// The call back function for reporting progress during connection multiplication
static int FSPAPI onMultiplied(FSPHANDLE hRev, PFSP_Context ctx)
{
	printf_s("\nHandle of the FSP session clone: %p\n", hRev);
	if(hRev == NULL)
	{
		printf_s("\tConnection multication failed.\n");
		return -1;
	}

	return 0;
}



// The function called back when the FSP clone connection was released. Parameters are self-describing
static void FSPAPI onShutdown(FSPHANDLE hRev, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, the clone session has been shutdown.\n", hRev);
	if(code != FSP_NotifyRecycled)
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);

	r2Finish = true;
	return;
}



static void FSPAPI onError(FSPHANDLE hRev, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, the clone session has been reset (%d, %d).\n", hRev, code, value);
	r2Finish = true;
	return;
}



// The near end finished the work, close the socket
static void FSPAPI onSignatureSent(FSPHANDLE hRev, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the signature: %d\n", r);
	Shutdown(hRev, onShutdown);
	return;
}



// The sub-toplevel function that inaugurate connection multipliction
void StartToSendSignature(FSPHANDLE h)
{
	r2Finish = false;	// there IS a reverse socket so we may not assume it is finished
	//
	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	// parms.onAccepting = NULL;
	parms.onAccepted = onMultiplied;
	parms.onError = onError;
	parms.recvSize = 0;	// the underlying service would give the minimum, however
	parms.sendSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.welcome = signature;
	parms.len = (unsigned short)sizeof(signature);
	if(MultiplyAndWrite(h, & parms, TO_END_TRANSACTION, onSignatureSent) == NULL)
	{
		printf("Warning!? Failed to multiply the connection.\n");
		return;
	}
}
