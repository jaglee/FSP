/**

  FSP http accelerator, SOCKS gateway and tunnel server

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

#include "defs.h"

/**
  How does it work:
  Each tunnel client makes one master connection with the tunnel end-server
	CONNECT server.example.com:80 HTTP/1.1
	Host: server.example.com:80
	Proxy-Authorization: basic aGVsbG86d29ybGQ=
-->
	TUNNEL registered.fsp.tunnel.end.point:80 FSP/0\r\n
	[Authorization User Id\r\n]
	\r\n

  The registered.fsp.tunnel.end.point:80 SHOULD be the tunnel server itself
  But it MAY be chaining tunnel endpoint

  FSP tunnel request is directly passes via a clone connection
  The master connection is utilised to
  1.shutdown the clone connection gracefully
  2.re-keying
  3.accounting/report statistics

  Inet4 tunnel request or domain name tunnel request is transported via the master connection
  if failed to do domain name resolution,
  failure reason is returned in the reverse stream of the master connection
  if succeeded, domain name/target address: real network address, requested port number, 
  together with bind address, bind port number is returned through a reverse multiplied connection

  Tunnel requests might be sent in a batch transmit transaction (further optimization yet to implement).

 */

// It is either client-to-tunnel SOCKS-interface side, or tunnel-to-server transparent TCP-interface side
// But not both
RequestPool	requestPool;


static bool FSPAPI onRequestArrived(FSPHANDLE, void *, int32_t, bool);


// This is an I/O routine which rely on the full-duplex mode
bool FSPAPI onFSPDataAvailable(FSPHANDLE h, void * buf, int32_t len, bool eot)
{
	SRequestPoolItem *pReq = requestPool.FindItem(h);
	if(pReq == NULL)
		return false;	// but it may cause dead-locke!?
	//
	send(pReq->hSocket, (char *)buf, len, 0);
	// but if send error?
	if(eot && RecvInline(h, onFSPDataAvailable) < 0)
	{
		shutdown(pReq->hSocket, SD_BOTH);
		closesocket(pReq->hSocket);
		Dispose(h);
	}
	//
	return true;
}



// This is a long-run I/O routine which rely on the full-duplex mode heavily
int FSPAPI toReadTCPData(FSPHANDLE h, void *buf, int32_t capacity)
{
	SRequestPoolItem *pReq = requestPool.FindItem(h);
	if(pReq == NULL)
		return 0;

	int n = recv(pReq->hSocket, (char *)buf, capacity, 0);
	if(n <= 0)
	{
		shutdown(pReq->hSocket, SD_BOTH);
		closesocket(pReq->hSocket);
		Dispose(h);
		return -1;
	}

	SendInline(h, buf, n, true);
	return 0;
}



// Side-effect: cleanup if the 'error' code is not REP_SUCCEEDED
void ReportToRemoteClient(PRequestPoolItem p, ERepCode code)
{
	SRequestResponse rep;
	memset(& rep, 0, sizeof(rep));
	rep.rep = code;

	int r = WriteTo(p->hFSP, & rep, sizeof(rep), TO_END_TRANSACTION, NULL);
	if(code == REP_SUCCEEDED)
		return;
	//
	shutdown(p->hSocket, SD_BOTH);
	closesocket(p->hSocket);
	Shutdown(p->hFSP, NULL);
}



// Each tunnel request is send over a new clone of the master connection to prevent head-of-queue congestion
int	FSPAPI onMultiplying(FSPHANDLE hSrv, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
#ifdef TRACE
	printf_s("\nTo accept multiplied handle of FSP session: %p\n", hSrv);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n"
		, be64toh(remoteAddr->subnet)
		, be32toh(remoteAddr->idHost)
		, be32toh(remoteAddr->idALF));
#endif
	if(requestPool.AllocItem(hSrv) == NULL)
	{
		Dispose(hSrv);
		return -1;	// no more resource!
	}

	RecvInline(hSrv, onRequestArrived);
	return 0;	// no opposition
}



static bool FSPAPI onRequestArrived(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	PRequestPoolItem p = requestPool.FindItem(h);
	if(p == NULL)
		return false;	// but it may be deadlocked!?
	if(! eot || len < sizeof(SRequestResponse))
		return false;	// to report break of protocol!

	// following code should be put in the remote end point
	SOCKET toServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(toServer == SOCKET_ERROR)
	{
        printf_s("remote socket() failed with error: %d\n", WSAGetLastError());
		ReportToRemoteClient(p, REP_REJECTED);
		return false;
	}

	sockaddr_in remoteEnd;
	SRequestResponse *req = (SRequestResponse *)buf;
	remoteEnd.sin_addr = req->inet4Addr;
	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = req->nboPort;

	printf_s("Try to connect to %s:%d\n", inet_ntoa(remoteEnd.sin_addr), ntohs(remoteEnd.sin_port));

	int r = connect(toServer, (PSOCKADDR) & remoteEnd, sizeof(remoteEnd)); 
	if(r != 0)
	{
        printf_s("connect() failed with error: %d\n", WSAGetLastError());
		ReportToRemoteClient(p, REP_REJECTED);
		return TRUE;
	}
	
	ReportToRemoteClient(p, REP_SUCCEEDED);
	RecvInline(h, onFSPDataAvailable);
	GetSendBuffer(h, toReadTCPData);

	return true;
}
