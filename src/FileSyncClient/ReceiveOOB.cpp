#include "stdafx.h"

int32_t count2Finish = 2000;	// by default there is no reverse socket and wait for about 100 seconds to wait one. see also main()

static void FSPAPI onShutdown(FSPHANDLE hRev, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, the clone session has been shutdown.\n", hRev);
	if(code != FSP_NotifyRecycled)
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);

	count2Finish = 0;
	return;
}


static int FSPAPI  onSignatureReceived(FSPHANDLE hRev, void * buf, int32_t length, BOOL eot)
{
	printf_s("Socket %p, %d bytes received, message:\n", hRev, length);
	printf_s("%s\n", (CHAR *)buf);
	// assert(eot);
	Shutdown(hRev, onShutdown);
	return 1;
}


// This function is for tracing purpose
int	FSPAPI onMultiplying(FSPHANDLE hRev, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	count2Finish = INT32_MAX;	// wait shutdown almost forever
	//
	printf_s("\nTo accept multiplied handle of FSP session: %p\n", hRev);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->u.subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));

	RecvInline(hRev, onSignatureReceived);
	return 0;	// no opposition
}
