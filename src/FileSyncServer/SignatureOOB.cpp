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
	printf_s("\nSocket handle of the clone session: %p\n", hRev);
	if(hRev == NULL)
	{
		printf_s("\tConnection multiplication failed.\n");
		return -1;
	}

	int r = Shutdown(hRev, NULL);
	Dispose(hRev);
	if (r < 0)
		printf_s("Failed to commit the transmit transaction.\n");
	else
		printf_s("The signature was sent successfully.\n");
	r2Finish = true;
	return r;
}



static void FSPAPI onError(FSPHANDLE hRev, FSP_ServiceCode code, int value)
{
	printf_s("Clone session, socket %p has been reset (%d, %d).\n", hRev, code, value);
	Dispose(hRev);
	r2Finish = finished = true;
}



// The sub-top level function that inaugurate connection multiplication
void StartToSendSignature(FSPHANDLE h)
{
	r2Finish = false;	// there IS a reverse socket so we may not assume it is finished
	//
	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = onAccepting;
	parms.onAccepted = onMultiplied;
	parms.onError = onError;
	parms.recvSize = 0;	// the underlying service would give the minimum, however
	parms.sendSize = 500;	// no, not USHRT_MAX. We just want to send a arbitrary short acknowledgement
	parms.welcome = signature;
	parms.len = (unsigned short)sizeof(signature);
	if (Multiply(h, &parms) == NULL)
	{
		printf("Warning!? Failed to multiply the connection.\n");
		return;
	}

	printf_s("Start to clone the main session to send the signature\n");
}
