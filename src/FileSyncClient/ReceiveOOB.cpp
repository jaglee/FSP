/**
 * A small group of functions in FileSyncClient. The group meant to handle the connection multiplication instance
 */
#include "stdafx.h"

extern int32_t ticksToWait;
extern bool r2finish;

// The call back function to be executed when the clone connection is closed
static void FSPAPI onShutdown(FSPHANDLE hRev, FSP_ServiceCode code, int value)
{
	printf_s("Clone session, socket %p has been shutdown.\n", hRev);
	r2finish = true;
	return;
}



// The call back function to be executed when data expected in the clone connection has been received.
static bool FSPAPI onSignatureReceived(FSPHANDLE hRev, void * buf, int32_t length, bool eot)
{
	printf_s("Cloned session, socket %p, %d bytes received, message:\n", hRev, length);
	if(buf != NULL)
		printf_s("%s\n", (CHAR *)buf);
	// assert(eot);
	Shutdown(hRev, NULL);
	return false;
}



// The entry function of the group. Most statements in this function is for tracing purpose.
int	FSPAPI onMultiplying(FSPHANDLE hRev, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	ticksToWait = INT32_MAX;	// wait shutdown almost forever
	r2finish = false;
	//
	printf_s("\nTo accept FSP session multiplication, socket handle: %p\n", hRev);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	printf_s("Remote address: 0x%X::%X::%X::%X\n"
		, be32toh(*(u_long*)& remoteAddr->subnet)
		, be32toh(*((u_long*)& remoteAddr->subnet + 1))
		, be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	//
	RecvInline(hRev, onSignatureReceived);
	return 0;	// no opposition
}
