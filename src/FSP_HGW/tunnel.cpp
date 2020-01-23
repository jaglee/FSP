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
	struct timeval timeout;
	timeout.tv_sec = RECV_TIME_OUT;
	timeout.tv_usec = 0;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	//
	shutdown(client, SD_SEND); 
	int r;
	do
	{
		char c;
		r = recv(client, &c, 1, 0);
	} while (r > 0);
	// until either nothing may be received or the peer has closed the connection
	closesocket(client);
}



static void FreeRequestItem(PRequestPoolItem p, bool graceful = false)
{
	if(p->hSocket != SOCKET_ERROR && ! graceful)
	{
		shutdown(p->hSocket, SD_BOTH);
		closesocket(p->hSocket);
	}
	else if (p->hSocket != SOCKET_ERROR)
	{
		CloseGracefully(p->hSocket);
	}
	//
	if(p->hFSP != NULL)
	{
		if(graceful)
			Shutdown(p->hFSP, NULL);
		else
			Dispose(p->hFSP);
	}
	//
	requestPool.FreeItem(p);
}



// This is an I/O routine which rely on the full-duplex mode
bool FSPAPI onFSPDataAvailable(FSPHANDLE h, void * buf, int32_t len, bool eot)
{
	SRequestPoolItem *pReq = requestPool.FindItem(h);
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

#ifndef NDEBUG
	printf_s("%d bytes received from the remote FSP peer\n", len);
#endif
	if (len == 0)
		return true;

#ifndef NDEBUG
	if (pReq->countFSPreceived == 0)
		printf_s("%.300s\n", (char *)buf);
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
// This is a long-run I/O routine which rely on the full-duplex mode heavily
int FSPAPI toReadTCPData(FSPHANDLE h, void *buf, int32_t capacity)
{
	SRequestPoolItem *pReq = requestPool.FindItem(h);
	if(pReq == NULL)
		return 0;

	int n = recv(pReq->hSocket, (char *)buf, capacity, 0);
	if (n <= 0)
	{
#ifndef NDEBUG
		if (n < 0)
			ReportWSAError("TCP side receive error");
		else
			printf("TCP side: no further data available.\n");
#endif
		Shutdown(h, NULL);
		FreeRequestItem(pReq, (n == 0));
		return 0;
	}

#if defined(_DEBUG_PEEK)
	printf_s("%d bytes read from the TCP end, first 300 chars:\n", n);
	if (pReq->countTCPreceived == 0)
		printf_s("%.300s\n", (char*)buf);
#endif

	pReq->countTCPreceived += n;
	int r;
	do
	{
		r = SendInline(h, buf, n, true, NULL);
		if (r >= 0)
			break;
		Sleep(1);	// yield CPU out for at least 1ms/one time slice
	} while (r == -EBUSY);
	if(r < 0)
	{
#ifndef NDEBUG
		printf_s("SendInline() in toReadTCPData failed!? Error code: %d\n", r);
#endif
		FreeRequestItem(pReq);
	}

	return 0;
}



// The version of the reply code should be zero while DSTPORT and DSTIP are ignored
// Side-effect: cleanup if the 'error' code is not REP_SUCCEEDED
void ReportSuccessViaFSP(PRequestPoolItem p)
{
	SRequestResponse rep;
	SOCKADDR_IN boundAddr;
	socklen_t	namelen = sizeof(boundAddr);

	int r = getsockname(p->hSocket, (SOCKADDR *)& boundAddr, &namelen);
	if (r < 0)
	{
		FreeRequestItem(p);
		return;
	}
	rep.inet4Addr = boundAddr.sin_addr;
	rep.nboPort = boundAddr.sin_port;
	rep.rep = REP_SUCCEEDED;
	rep._reserved = 0;

	r = WriteTo(p->hFSP, &rep, sizeof(rep), TO_END_TRANSACTION, NULL);
	if(r <= 0)
		FreeRequestItem(p);
}



void ReportToRemoteClient(PRequestPoolItem p, ERepCode code)
{
	SRequestResponse rep;
	memset(& rep, 0, sizeof(rep));
	rep.rep = code;

	WriteTo(p->hFSP, & rep, sizeof(rep), TO_END_TRANSACTION, NULL);

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

	RecvInline(hSrv, onRequestArrived);
	return 0;	// no opposition
}



static bool FSPAPI onRequestArrived(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	PRequestPoolItem p = requestPool.FindItem(h);
	if(p == NULL)
		return false;	// but it may be deadlocked!?
	if(! eot || len < (int)sizeof(SRequestResponse))
		return false;	// to report break of protocol!

	// following code should be put in the remote end point
	p->hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(p->hSocket == SOCKET_ERROR)
	{
		ReportWSAError("Remote socket() failed");
		ReportToRemoteClient(p, REP_REJECTED);
		return false;
	}

	sockaddr_in remoteEnd;
	SRequestResponse *q = (SRequestResponse *)buf;
	memset(&remoteEnd, 0, sizeof(sockaddr_in));
	remoteEnd.sin_addr = q->inet4Addr;
	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = q->nboPort;
#ifndef NDEBUG
	printf_s("Version %d, command code %d, try to connect to %s:%d\n"
		, q->version
		, q->cmd
		, inet_ntoa(q->inet4Addr)
		, be16toh(q->nboPort));
#endif

	int r = connect(p->hSocket, (PSOCKADDR) & remoteEnd, sizeof(remoteEnd));
	if(r != 0)
	{
		ReportWSAError("Remote connect() failed");
		ReportToRemoteClient(p, REP_REJECTED);
		return false;
	}
	ReportSuccessViaFSP(p);

	RecvInline(h, onFSPDataAvailable);
	GetSendBuffer(h, toReadTCPData);

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