/**
  FSP http accelerator, SOCKS gateway and tunnel server

  FSP Relay Request:
	+---+---+---+---+---+---+----+
	|VER|RSV| DST.ADDR  |DST.PORT|
	+---+---+---+---+---+----+---+
	| 1 |'0'|    4      |    2   |
	+---+---+---+---+---+--------+

  FSP Relay Response:
    +---+---+-----------+----+---+
    |VER|REP| BND.ADDR  |BND.PORT|
    +---+---+---+---+---+----+---+
    | 1 | 1 |    4      |    2   |
	+---+---+---+---+---+--------+

 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <WinSock2.h>
#include <mstcpip.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <sys/wait.h>
#define _strcmpi strcasecmp
#endif


/**
  How does it work:
  Each tunnel client makes one master connection with the tunnel end-server

  FSP tunnel request is directly passes via a clone connection

  Inet4 tunnel request or domain name tunnel request is transported via the master connection
  if failed to do domain name resolution,
  failure reason is returned in the reverse stream of the master connection
  if succeeded, domain name/target address: real network address, requested port number, 
  together with bind address, bind port number is returned through a reverse multiplied connection

  Tunnel requests might be sent in a batch transmit transaction (further optimization yet to implement).

 */


// Yet to be implemented
FSPHANDLE TunnelForInet4(in_addr ipAddr, uint16_t port)
{
	char *str = inet_ntoa(ipAddr);
	if (str == NULL)
		return NULL;
	printf_s(__FUNCDNAME__ "called, %s, port = %d\n", str, port);

	// TODO
	return NULL;
}
