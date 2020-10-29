/*
 * Implement the tunnel server role in FSP http accelerator, SOCKS gateway and tunnel server
 *
    Copyright (c) 2017, Jason Gao
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT,INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
 */

#include "fsp_http.h"

#if defined(__WINDOWS__)
# include <ws2tcpip.h>
#elif defined(__linux__) || defined(__CYGWIN__)
# include <netdb.h>
#endif

/**
  How does it work:
  Each tunnel client makes one master connection with the tunnel end-server
	TUNNEL registered.fsp.tunnel.end.point:80 HTTP/1.0\r\n
	[Authorization User Id\r\n]
	\r\n

  The registered.fsp.tunnel.end.point:80 SHOULD be the tunnel server itself
  But it MAY be chaining tunnel endpoint

  FSP tunnel request is directly passes via a clone connection
  The response is sent back via the clone connection of course.

  The master connection is utilized to
  1.shutdown the clone connection gracefully
  2.accounting/report statistics

 */

RequestPool	requestPool;

static bool FSPAPI onRequestArrived(FSPHANDLE, void *, int32_t, bool);

#ifdef _WIN32
static int ReportWSAError(const char *);
#else
# define ReportWSAError(msg) perror(msg)
#endif


// Given
//	SOCKET	the handle of the TCP socket that connected to the SOCKS client
// Do
//	Shutdown the connection to the SOCKS client gracefully
void CloseGracefully(SOCKET client)
{
	shutdown(client, SD_BOTH);
	int r;
	do
	{
		char c;
		r = recv(client, &c, 1, 0);
	} while (r > 0);
	// until either nothing may be received or the peer has closed the connection
	closesocket(client);
}



void FreeRequestItem(PRequestPoolItem p, bool graceful)
{
	if(p->hSocket != (SOCKET)SOCKET_ERROR && ! graceful)
	{
		shutdown(p->hSocket, SD_BOTH);
		closesocket(p->hSocket);
	}
	else if (p->hSocket != (SOCKET)SOCKET_ERROR)
	{
		CloseGracefully(p->hSocket);
	}
	p->hSocket = SOCKET_ERROR;
	//
	if(p->hFSP != NULL)
	{
		Shutdown(p->hFSP, NULL);
		Dispose(p->hFSP);
		p->hFSP = NULL;
	}
	//
	requestPool.FreeItem(p);
}



// This is an I/O routine which rely on the full-duplex mode
bool FSPAPI onFSPDataAvailable(FSPHANDLE h, void * buf, int32_t len, bool eot)
{
	PRequestPoolItem pReq = requestPool.FindItem(h);
	if (pReq == NULL)
	{
		printf_s("Broken protocol pipe! Cannot get the request state related to the FSP socket.\n");
		return false;
	}
	if (len < 0)
	{
		printf_s("Broken protocol pipe! Callback function get error code %d\n", len);
		FreeRequestItem(pReq);
		return false;
	}

#ifdef _DEBUG_PEEK
	printf_s("%d bytes received from the remote FSP peer\n", len);
#endif
	if (len == 0)
		return true;

#ifdef _DEBUG_PEEK
	if (pReq->countFSPreceived == 0)
		printf_s("Remote status report: version = %d, error code = %d\n", *(octet *)buf, *((octet *)buf + 1));
#endif
	pReq->countFSPreceived += len;

	int r = send(pReq->hSocket, (char *)buf, len, 0);
	if (r < 0)
	{
		ReportWSAError("TCP side send error");
		FreeRequestItem(pReq);
		return false;
	}

	return true;
}



// Only when the server side close the TCP socket would the tunnel be closed gracefully.
int FSPAPI toReadTCPData(FSPHANDLE h, void* buf, int32_t capacity)
{
	SRequestPoolItem* pReq = requestPool.FindItem(h);
	if (pReq == NULL)
		return -1;	// do not continue

	int n = recv(pReq->hSocket, (char*)buf, capacity, 0);
	if (n <= 0)
	{
#ifndef NDEBUG
		if (n < 0)
			ReportWSAError("TCP side receive error");
		else
			printf("TCP side: no further data available.\n");
#endif
		FreeRequestItem(pReq, (n == 0));
		return -1;	// do not continue
	}

#ifdef _DEBUG_PEEK
	printf_s("%d bytes read from the TCP end\n", n);
	if (pReq->countTCPreceived == 0)
		printf_s("First 300 chars:\n%.300s\n", (char*)buf);
#endif

	pReq->countTCPreceived += n;
	int r;
	do
	{
		r = SendInline(h, (char *)buf, n, true, NULL);
		if (r >= 0)
			break;
		Sleep(1);	// yield CPU out for at least 1ms/one time slice
	} while (r == -EBUSY);
	if (r < 0)
	{
#ifndef NDEBUG
		printf_s("SendInline() in toReadTCPData failed!? Error code: %d\n", r);
#endif
		FreeRequestItem(pReq);
	}

	return 0;
}



// The version of the reply code should be zero while DSTPORT and DSTIP are ignored
static bool ReportSuccessViaFSPv4(PRequestPoolItem p)
{
	SRequestResponse_v4 rep;
	SOCKADDR_IN boundAddr;
	socklen_t	namelen = sizeof(boundAddr);

	int r = getsockname(p->hSocket, (SOCKADDR *)& boundAddr, &namelen);
	if (r < 0)
		return false;

	rep.inet4Addr = boundAddr.sin_addr;
	rep.nboPort = boundAddr.sin_port;
	rep.rep = REP_SUCCEEDED;
	rep._reserved = 0;

	r = WriteTo(p->hFSP, &rep, sizeof(rep), TO_END_TRANSACTION, NULL);
	return (r > 0);
}



static void ReportFailureRemotelyV4(PRequestPoolItem p)
{
	SRequestResponse_v4 rep;
	memset(& rep, 0, sizeof(rep));
	rep.rep = REP_REJECTED;

	WriteTo(p->hFSP, & rep, sizeof(rep), TO_END_TRANSACTION, NULL);

	FreeRequestItem(p, true);
}



static bool ReportSuccessViaFSP(PRequestPoolItem p)
{
#ifdef _DEBUG_PEEK
	printf("%s: saved socks version = %d\n", __func__, p->socks_version);
#endif
	if (p->socks_version != SOCKS_VERSION_5)
		return ReportSuccessViaFSPv4(p);

	SRequestResponseV5 &rep = p->rqV5;
	int r;
	// version and reserved field are kept
	rep.rep = SOCKS_SERVICE_NOERROR;
	if(rep.addrType == ADDRTYPE_IPv4)
	{
		SOCKADDR_IN boundAddr;
		socklen_t	namelen = sizeof(boundAddr);

		r = getsockname(p->hSocket, (SOCKADDR *)& boundAddr, &namelen);
		if (r < 0)
			return false;

		rep.inet4Addr = boundAddr.sin_addr;
		rep.nboPort = boundAddr.sin_port;
		r = int(offsetof(SRequestResponseV5, nboPort) + sizeof(rep.nboPort));
	}
	else if(rep.addrType == ADDRTYPE_DOMAINNAME)
	{
		r = rep.domainName.len + int(offsetof(SRequestResponseV5, domainName) + 3);
	}
	else	// unsupported address type should have been filtered
	{
		return false;
	}
#ifdef _DEBUG_PEEK
	printf("To write %d octets to the remote FSP end.\n", r);
#endif

	r = WriteTo(p->hFSP, &rep, r, TO_END_TRANSACTION, NULL);
#ifdef _DEBUG_PEEK
	printf("Report success to the SOCKS client, %d octets sent.\n", r);
#endif
	return (r > 0);
}



static void ReportFailureRemotely(PRequestPoolItem p)
{
	if (p->socks_version != SOCKS_VERSION_5)
	{
		ReportFailureRemotelyV4(p);
		return;
	}

	size_t offsetOfPort = offsetof(SRequestResponseV5, nboPort);
	SRequestResponseV5 &rep = p->rqV5;
	rep.rep = SOCKS_HOST_UNREACHABLE;
	rep.addrType = ADDRTYPE_IPv4;
	rep.inet4Addr.s_addr = INADDR_ANY; 
	rep.nboPort = 0;
	WriteTo(p->hFSP, &rep, offsetOfPort + 2, TO_END_TRANSACTION, NULL);

	FreeRequestItem(p, true);
}



// Each tunnel request is send over a new clone of the master connection to prevent head-of-queue congestion
int	FSPAPI onMultiplying(FSPHANDLE hSrv, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
#ifdef TRACE
	printf_s("\nTo accept multiplied handle of FSP session: %p\n", hSrv);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%" PRIx64 "::%X::%X\n"
		, (uint64_t)be64toh(remoteAddr->subnet)	// but in cygwin64 __bswap_64 return unsigned long long which is not PRIx64
		, be32toh(remoteAddr->idHost)
		, be32toh(remoteAddr->idALF));
#endif
	if(requestPool.AllocItem(hSrv) == NULL)
		return -1;	// no more resource!
	
	SetOnError(hSrv, onBranchError);
	SetOnRelease(hSrv, onRelease);

	RecvInline(hSrv, onRequestArrived);
	return 0;	// no opposition
}



// Handler of error notification for branch connection cloned from the authenticated main connection 
void FSPAPI onBranchError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
#ifdef TRACE
	printf_s("Notification: socket %p, service code = %d, return %d\n", h, code, value);
#endif
	PRequestPoolItem p = requestPool.FindItem(h);
	if (p != NULL)
		FreeRequestItem(p);
	else
		Dispose(h);
}



// Given
//	FSPHANDLE		the handle of the FSP socket that connecting the two tunnel ends
//	FSP_ServiceCode the notification code that close the FSP socket
//	int				the notification value accompanying the code
// Do
//	Shutdown the connection on demand of the release-connection request of the peer
void FSPAPI onRelease(FSPHANDLE h, FSP_ServiceCode code, int value)
{
#ifdef TRACE
	printf_s("SOCKS service terminated on request of the peer, FSP handle is %p\n", h);
#endif
	PRequestPoolItem p = (PRequestPoolItem)GetExtPointer(h);
	if (p == NULL)
	{
		Dispose(h);
		return;
	}
	FreeRequestItem(p, true);
}



static in_addr ResolveIPv4Address(const char* nodeName)
{
	static const struct addrinfo hints = { 0, AF_INET, };
	const in_addr ADDR_ZERO = *(in_addr*)&hints.ai_addr;
	struct addrinfo* pAddrInfo;

	if (getaddrinfo(nodeName, NULL, &hints, &pAddrInfo) != 0)
		return ADDR_ZERO;

	if (pAddrInfo == NULL)
		return ADDR_ZERO;

	const in_addr ret = ((sockaddr_in*)pAddrInfo->ai_addr)->sin_addr;
	freeaddrinfo(pAddrInfo);
	return ret;
}



static bool HandleSOCKSRequestV4(PRequestPoolItem p, PRequestResponse_v4 q, int32_t len)
{
	if(len < (int)sizeof(SRequestResponse_v4) || len > (int)sizeof(SRequestResponseV4a))
		return false;

	p->socks_version = q->version;

	char* s = (char*)&q->inet4Addr;
	sockaddr_in remoteEnd;
	memset(&remoteEnd, 0, sizeof(sockaddr_in));
	if (s[0] == 0 && s[1] == 0 && s[2] == 0)
	{
		s = ((SRequestResponseV4a*)q)->domainName;
		s[MAX_LEN_DOMAIN_NAME - 1] = 0;
#ifndef NDEBUG
		printf_s("To resolve IP address of %s\n", s);
#endif
		remoteEnd.sin_addr = ResolveIPv4Address(s);
	}
	else
	{
		remoteEnd.sin_addr = q->inet4Addr;
	}
	if (*(uint32_t*)&remoteEnd.sin_addr == 0)
		return false;

	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = q->nboPort;
#ifndef NDEBUG
	printf_s("Version %d, command code %d, try to connect to %s:%d\n"
		, q->version
		, q->cmd
		, inet_ntoa(q->inet4Addr)
		, be16toh(q->nboPort));
#endif

	p->hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (p->hSocket == (SOCKET)SOCKET_ERROR)
	{
		ReportWSAError("Remote socket() failed");
		return false;
	}

	int r = connect(p->hSocket, (PSOCKADDR)&remoteEnd, sizeof(remoteEnd));
	if (r != 0)
	{
		ReportWSAError("Remote connect() failed");
		return false;
	}

	return true;
}



// Only support CONNECT request
static bool HandleSOCKSv5Request(PRequestPoolItem p, PRequestResponseV5 q, int32_t len)
{
	int offset = (int)offsetof(SRequestResponseV5, nboPort);
	if (len < offset + (int)sizeof(q->nboPort) || q->cmd != SOCKS_CMD_CONNECT)
		return false;

	sockaddr_in remoteEnd;
	memset(&remoteEnd, 0, sizeof(sockaddr_in));
	remoteEnd.sin_family = AF_INET;

	if (q->addrType == ADDRTYPE_IPv4)
	{
		remoteEnd.sin_addr = q->inet4Addr;
		remoteEnd.sin_port = q->nboPort;
	}
	else if(q->addrType == ADDRTYPE_DOMAINNAME && q->domainName.len > 0)
	{
		offset -= (int)sizeof(in_addr) - 1;
		offset += q->domainName.len;
		// save the first octet of the port number in case that domain name length is the maximum
		char c = *((octet*)q + offset);
		q->domainName.txt[q->domainName.len] = '\0';
#ifdef _DEBUG_PEEK
		printf("Domain name length = %d, try to resolve IPv4 address of %s\n", q->domainName.len, q->domainName.txt);
#endif
		remoteEnd.sin_addr = ResolveIPv4Address(q->domainName.txt);
		if(*(uint32_t*)&remoteEnd.sin_addr == 0)
			return false;
		// recover the first octet of the port number, avoid alignment error
		*(octet*)&remoteEnd.sin_port = *((octet*)q + offset) = c;
		*((octet*)&remoteEnd.sin_port + 1) = *((octet*)q + offset + 1);
	}
	else
	{
		p->socks_version = q->version;
		return false;	// Address type not supported, should be filtered by the request end.
	}
	memcpy(&p->rqV5, q, offset + sizeof(q->nboPort));

#ifndef NDEBUG
	printf_s("Version %d, command code %d, try to connect to %s:%d\n"
		, q->version
		, q->cmd
		, inet_ntoa(remoteEnd.sin_addr)
		, be16toh(remoteEnd.sin_port));
#endif

	p->hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (p->hSocket == (SOCKET)SOCKET_ERROR)
	{
		ReportWSAError("Remote socket() failed");
		return false;
	}

	int r = connect(p->hSocket, (PSOCKADDR)&remoteEnd, sizeof(sockaddr_in));
	if (r != 0)
	{
		ReportWSAError("Remote connect() failed");
		return false;
	}

	return true;
}



static bool FSPAPI onRequestArrived(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	PRequestPoolItem p = requestPool.FindItem(h);
	if(p == NULL)
		return false;	// but it may be deadlocked!?
	if(! eot)
		return false;	// to report break of protocol!

	bool b;
	if (*(octet *)buf == SOCKS_VERSION_5)
		b = HandleSOCKSv5Request(p, (PRequestResponseV5)buf, len);
	else
		b = HandleSOCKSRequestV4(p, (PRequestResponse_v4)buf, len);

	if (!b)
	{
		ReportFailureRemotely(p);
		return false;
	}
	// Bytes in the request matter
	p->countFSPreceived = len;

	if (!ReportSuccessViaFSP(p)
	 || (RecvInline(h, onFSPDataAvailable) < 0)
	 || (GetSendBuffer(h, toReadTCPData) < 0))
	{
		FreeRequestItem(p);
	}

	return false;	// do not chain the previous call-back function
}



#ifdef _WIN32
// Given
//	char *		The error message prefix string in multi-byte character set
// Do
//	Print the system message mapped to the last error to the standard output, prefixed by the given message prefix
// Return
//	the WSA error number, which is greater than zero. may be zero if no error at all.
static int ReportWSAError(const char * msg)
{
	int	err = WSAGetLastError();

	printf("%s, error code = %d:\n", msg, err);

	LPVOID lpMsgBuf;
	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL))
	{
		printf("%s\n", (char *)lpMsgBuf);
		LocalFree(lpMsgBuf);
	}

	return err;
}
#endif