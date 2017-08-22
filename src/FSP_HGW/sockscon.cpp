/**
  FSP http accelerator, SOCKS gateway and tunnel server

	SOCKS4a extends the SOCKS4 protocol to allow a client to specify a destination domain name rather than an IP address;
	This is useful when the client itself cannot resolve the destination host's domain name to an IP address.
	client should set the first three bytes of DSTIP to NULL and the last byte to a non-zero value.
	Following the NULL byte terminating USERID, the client must send the destination domain name
	and terminate it with another NULL byte. This is used for both "connect" and "bind" requests.

	Client to SOCKS server:

	field 1: SOCKS version number, 1 byte, must be 0x04 for this version
	field 2: command code, 1 byte:
	0x01 = establish a TCP/IP stream connection
	0x02 = establish a TCP/IP port binding
	field 3: port number, 2 bytes
	field 4: deliberate invalid IP address, 4 bytes, first three must be 0x00 and the last one must not be 0x00
	field 5: the user ID string, variable length, terminated with a null (0x00)
	field 6: the domain name of the host to contact, variable length, terminated with a null (0x00)

	Server to SOCKS client:

	field 1: null byte
	field 2: status, 1 byte:
		0x5A = request granted
		0x5B = request rejected or failed
		0x5C = request failed because client is not running identd (or not reachable from the server)
		0x5D = request failed because client's identd could not confirm the user ID string in the request
	field 3: port number, 2 bytes (in network byte order)
	field 4: IP address, 4 bytes (in network byte order)

	A server using protocol SOCKS4a must check the DSTIP in the request packet.
	If it represents address 0.0.0.x with nonzero x, the server must read in the domain name that the client sends in the packet.
	The server should resolve the domain name and make connection to the destination host if it can.

  Process
	### IPv4: check ruleset
	   white-list: direct FSP/IPv6 access (TCP/IPv4->FSP/IPv6, transmit via SOCKS)
	   {TODO: download the whitelist}
	   { /// UNRESOLVED! As a transit method:
	   if not in white-list, try search PTR, [DnsQuery], if get the _FSP exception-list: direct connect
	   }
	   not in the white-list: FSP-relay

	### domain name: favor FSP/IPv6
	search the 'white list' (local memory cache), make FSP connection if matched;
	otherwise
	  if port number = 18003 ('F''S'), try to resolve AAAA only
	    if succeeded, make FSP connection first
		  if succeeded, put into white list
		--if failed, fall to resolve IPv4 address
	  otherwise if started with '_FSP.', try to resolve AAAA only
	    if succeeded, make FSP connection first
		  if succeeded, put into white list
		--if failed, fall to resolve IPv4 address
	otherwise, try to resolve both AAAA AND A address
	  if there's IPv6 address resolved, try to make FSP connection
	    if succeeded, put into white list
	  --if failed, try IPv4 address
	if IPv4 address resolving failed, or TCP connect failed, return failure information



  Further streaming:
    transparent HTTP acceleration!
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
#include <MSWSock.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"
#pragma comment(lib, "Ws2_32.lib")
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

#define SOCKS_VERSION		4
#define MAX_WORKING_THREAD	4	// fine tuning this value to half number of workable hyper-thread of the platform
#define RECV_TIME_OUT		30	// half a miniute


enum ERepCode: octet
{
	REP_SUCCEEDED = 0x5A,
	REP_REJECTED = 0x5B,
	REP_NO_IDENTD = 0x5C,
	REP_AUTH_FAILED = 0x5D
};

#define SOCKS_CMD_CONNECT 1	// only support CONNECT

#include <pshpack1.h>
typedef struct SRequestResponse
{
	union
	{
		octet version;	// for request
		octet _reserved;// for response
	};
	union
	{
		octet cmd;
		octet rep;
	};
	uint16_t nboPort;	// port number in network byte order
	in_addr inet4Addr;
	// char	userId[2];	// just a placeholder
	// char _dName[2];	// just a placeholder
} *PRequestResponse;
#include <poppack.h>


void ProcessIPv4Connect(SOCKET, PRequestResponse);
void ProcessDNameConnect(SOCKET, PRequestResponse);

//
FSPHANDLE TunnelForInet4(in_addr, uint16_t);
void ReportErrorToClient(SOCKET, ERepCode);


//
// Thread pool wait callback function template
//
VOID
CALLBACK
MyWaitCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID                 Parameter,
    PTP_WAIT              Wait,
    TP_WAIT_RESULT        WaitResult
    )
{
    // Instance, Parameter, Wait, and WaitResult not used in this example.
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(WaitResult);

    //
    // Do something when the wait is over.
    //
}


//
// Thread pool timer callback function template
//
VOID
CALLBACK
MyTimerCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID                 Parameter,
    PTP_TIMER             Timer
    )
{
    // Instance, Parameter, and Timer not used in this example.
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Timer);

    //
    // Do something when the timer fires.
    //
}


//
// This is the thread pool work callback function, forward declaration.
//
VOID CALLBACK TpWorkCallBack(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK Work);



void ToServeSOCKS(int port)
{
    PTP_POOL pool = NULL;
    TP_CALLBACK_ENVIRON envCallBack;
    PTP_CLEANUP_GROUP cleanupgroup = NULL;
    //FILETIME FileDueTime;
    //ULARGE_INTEGER ulDueTime;
    //PTP_TIMER timer = NULL;
    BOOL bRet = FALSE;

	InitializeThreadpoolEnvironment(& envCallBack);
	pool = CreateThreadpool(NULL);
	if (pool == NULL)
	{
		printf_s("CreateThreadpool failed. LastError: %u\n", GetLastError());
		return;
	}

    SetThreadpoolThreadMaximum(pool, MAX_WORKING_THREAD);
    bRet = SetThreadpoolThreadMinimum(pool, 1);
    if (!bRet)
	{
        printf_s("SetThreadpoolThreadMinimum failed. LastError: %d\n", GetLastError());
        goto l_bailout1;
    }

    cleanupgroup = CreateThreadpoolCleanupGroup();
    if (cleanupgroup == NULL)
	{
        printf_s("CreateThreadpoolCleanupGroup failed. LastError: %d\n", GetLastError());
        goto l_bailout1; 
    }

    SetThreadpoolCallbackPool(& envCallBack, pool);
    SetThreadpoolCallbackCleanupGroup(& envCallBack, cleanupgroup, NULL);

	//timer = CreateThreadpoolTimer(MyTimerCallback, NULL,  & envCallBack);
	//if (timer == NULL)
	//{
	//    printf_s("CreateThreadpoolTimer failed. LastError: %d\n", GetLastError());
	//    goto l_bailout2;
	//}

    //ulDueTime.QuadPart = (ULONGLONG) -(1 * 10 * 1000 * 1000);
    //FileDueTime.dwHighDateTime = ulDueTime.HighPart;
    //FileDueTime.dwLowDateTime  = ulDueTime.LowPart;
    //SetThreadpoolTimer(timer, &FileDueTime, 0, 0);

	//
	WSADATA wsaData;
	int r;

	if ((r = WSAStartup(0x202, &wsaData)) < 0)
	{
		printf_s("Cannot start up Windows socket service provider.\n");
		goto l_bailout4;
	}

	SOCKET hListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(hListener == SOCKET_ERROR)
	{
        printf_s("socket() failed with error: %d\n", WSAGetLastError() );
		goto l_bailout5;
	}

	sockaddr_in localEnd;
	localEnd.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	localEnd.sin_family = AF_INET;
	localEnd.sin_port = htons(port);
	memset(localEnd.sin_zero, 0, sizeof(localEnd.sin_zero));

    r = bind(hListener, (SOCKADDR *) &localEnd, sizeof(SOCKADDR));
    if (r == SOCKET_ERROR)
	{
        printf_s("bind() failed with error: %d\n", WSAGetLastError() );
		goto l_bailout6;
    }
  
    r = listen(hListener, 5);
    if (r == SOCKET_ERROR)
	{  
        printf_s("listen() failed with error: %d\n", WSAGetLastError() );
		goto l_bailout6;
    }

	do
	{
		int iClientSize = sizeof(sockaddr_in);
		sockaddr_in saClient;
		PTP_WORK work = NULL;
		SOCKET hAccepted = accept(hListener, (SOCKADDR*) &saClient, &iClientSize);
		if(hAccepted == INVALID_SOCKET)
		{
		    printf_s("accept() failed with error: %d\n", WSAGetLastError());
			break;
		}
		//
		work = CreateThreadpoolWork(TpWorkCallBack, (PVOID)hAccepted, & envCallBack);
		if (work == NULL)
			ReportErrorToClient(hAccepted, REP_REJECTED);
		else
			SubmitThreadpoolWork(work);
	} while(true);

    // Clean up in reverse order.
l_bailout6:
    closesocket(hListener);
l_bailout5:
    WSACleanup();

l_bailout4:
	//SetThreadpoolTimer(timer, NULL, 0, 0); // cancel waiting queued callback
	//WaitForThreadpoolTimerCallbacks(timer, true);
	////CloseThreadpoolTimer(timer); // unnecessary.
l_bailout3:
	// CloseThreadpoolCleanupGroupMembers also releases objects
	// that are members of the cleanup group, so it is not necessary 
	// to call close functions on individual objects 
	// after calling CloseThreadpoolCleanupGroupMembers.
    CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
l_bailout2:
	CloseThreadpoolCleanupGroup(cleanupgroup);
l_bailout1:
    CloseThreadpool(pool);
}



void
CALLBACK
TpWorkCallBack(PTP_CALLBACK_INSTANCE Instance, PVOID parameter, PTP_WORK Work)
{
    // Instance, Parameter, and Work not used in this example.
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

	SOCKET client = (SOCKET)parameter;
	SRequestResponse req;

	int r = recv(client, (char *) & req, sizeof(req), 0);
	if(r == SOCKET_ERROR)
	{  
        printf_s("recv() socks version failed with error: %d\n", WSAGetLastError());
		ReportErrorToClient(client, REP_REJECTED);
        return;
    }

	// the implicit ruleset says that only socks version 4a supported
	if(req.version != SOCKS_VERSION)
	{
        printf_s("%d: unsupport version\n", req.version);
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}
	if(req.cmd != SOCKS_CMD_CONNECT)
	{
        printf_s("%d: unsupport command\n", req.version);
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}

	printf_s("Skipped user Id: ");
	char c;
	do
	{
		r = recv(client, & c, 1, 0);
		if(c == 0)
			break;
		putchar(c);
	} while(r > 0);
	//
	if(r < 0)
	{
		printf_s("recv() failed with error: %d\n", WSAGetLastError());
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}
	printf_s("\n");

	const in_addr & a = req.inet4Addr;
	if(a.S_un.S_un_w.s_w1 == 0 && a.S_un.S_un_b.s_b3 == 0 && a.S_un.S_un_b.s_b4 != 0)
		ProcessDNameConnect(client, & req);
	else if(a.S_un.S_addr != 0)
		ProcessIPv4Connect(client, & req);
	else
		ReportErrorToClient(client, REP_REJECTED);
}



void ProcessIPv4Connect(SOCKET client, PRequestResponse req)
{
	struct timeval timeout;
	timeout.tv_sec = RECV_TIME_OUT;
	timeout.tv_usec = 0;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	//FSPHANDLE hTunnel = TunnelForInet4(req->inet4Addr, req->nboPort);
	// tunnel the address to the remote end, directly

	// following code should be put in the remote end point
	SOCKET toServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(toServer == SOCKET_ERROR)
	{
        printf_s("remote socket() failed with error: %d\n", WSAGetLastError());
		ReportErrorToClient(client, REP_REJECTED);
	}

	sockaddr_in remoteEnd;
	remoteEnd.sin_addr = req->inet4Addr;
	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = req->nboPort;

	printf_s("Try to connect to %s:%d\n", inet_ntoa(remoteEnd.sin_addr), ntohs(remoteEnd.sin_port));

	int r = connect(toServer, (PSOCKADDR) & remoteEnd, sizeof(remoteEnd)); 
	if(r != 0)
	{
        printf_s("connect() failed with error: %d\n", WSAGetLastError());
		ReportErrorToClient(client, REP_REJECTED);
	}
	// Should be tunneled
	ReportErrorToClient(client, REP_SUCCEEDED);

	char buf[BUFSIZ];

	// following are prototype, actually
	FD_SET rdSet;
	do
	{
		FD_ZERO(& rdSet);
		FD_SET(client, & rdSet);
		FD_SET(toServer, & rdSet);
		if(select(0, & rdSet, NULL, NULL, NULL) <= 0)
		{
	        printf_s("select() failed with error: %d\n", WSAGetLastError());
			break;
		}
		if(FD_ISSET(client, & rdSet))
		{
			r = recv(client, buf, sizeof(buf), 0);
			if(r <= 0)
				break;
			r = send(toServer, buf, r, 0);
			if(r <= 0)
				break;
		}
		if(FD_ISSET(toServer, & rdSet))
		{
			r = recv(toServer, buf, sizeof(buf), 0);
			if(r <= 0)
				break;
			r = send(client, buf, r, 0);
			if(r <= 0)
				break;
		}
	} while(true);
	//ReportErrorToClient(client, REP_REJECTED);

	// The shutdown function does not block regardless of the SO_LINGER setting on the socket.
	shutdown(toServer, SD_SEND);
	//
	shutdown(client, SD_SEND);
	while(r > 0)
	{
		r = recv(client, buf, sizeof(buf), 0);
	}
	// until either nothing may be received or the peer has closed the connection
	closesocket(client);
	//
	closesocket(toServer);
}



void ProcessDNameConnect(SOCKET client, PRequestResponse buf)
{
	printf_s("Unimplemented yet.\n");
}


void ReportErrorToClient(SOCKET client, ERepCode code)
{
	SRequestResponse rep;
	memset(& rep, 0, sizeof(rep));
	rep.rep = code;

	int r = send(client, (char *) & rep, sizeof(rep), 0);
	if(r == SOCKET_ERROR)
        printf_s("send() socks response failed with error: %d\n", WSAGetLastError());
	// or just silently return?
}