#include "stdafx.h"

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


static int FSPAPI  onSignatureReceived(FSPHANDLE h, void * buf, int32_t length, BOOL eot)
{
	printf_s("Fiber ID = 0x%X, %d bytes recevied, message:\n", (uint32_t)(intptr_t)h, length);
	printf_s("%s\n", (CHAR *)buf);
	// assert(eot);
	Shutdown(h, onShutdown);
	return TRUE;
}


// This function is for tracing purpose
int	FSPAPI onMultiplying(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept multiplied handle of FSP session: 0x%08X\n", h);
	printf_s("Interface: %d, session Id: 0x%X\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->u.subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));

	RecvInline(h, onSignatureReceived);
	return 0;	// no opposition
}
