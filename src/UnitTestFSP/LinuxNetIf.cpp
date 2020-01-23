#include "../FSP_Impl.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

int main(int argc, char *argv[])
{
    char strAddr[INET6_ADDRSTRLEN];
    struct ifaddrs *ifap;
    int r = getifaddrs(& ifap);
    if(r != 0)
    {
        perror("Cannot get the interface/address list");
        exit(-1);
    }

    for(register struct ifaddrs *pIf = ifap; pIf != NULL; pIf = pIf->ifa_next)
    {
		PSOCKADDR_IN p = (PSOCKADDR_IN)pIf->ifa_addr;
		if (p->sin_family == AF_INET6)
		{
			printf("Non IPv4 address for %s, %s\n"
            , pIf->ifa_name
            , inet_ntop(AF_INET6, &((PSOCKADDR_IN6)p)->sin6_addr, strAddr, sizeof(SOCKADDR_IN6) ) );
			continue;
		}
        if (p->sin_family != AF_INET)   // define PF_PACKET	17
        {
			printf("Address family %d not cared for %s\n", p->sin_family, pIf->ifa_name);
			continue;
        }
		printf("%s ", pIf->ifa_name);
		p->sin_port = DEFAULT_FSP_UDPPORT;
    	printf("bind to listen at UDP socket address: %s:%d\n"
		    , inet_ntoa(p->sin_addr), be16toh(p->sin_port));
    }

    freeifaddrs(ifap);
    return 0;
}
