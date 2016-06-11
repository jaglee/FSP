#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../FSP_API.h"


// This function is for tracing purpose
int	FSPAPI onMultiplying(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept multiplied handle of FSP session: 0x%08X\n", h);
	printf_s("Interface: %d, session Id: %u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->u.subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	return 0;	// no opposition
}
