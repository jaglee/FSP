/*
 * Implement the SOCKSv4 interface of FSP http accelerator, SOCKS gateway and tunnel server
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

 /*
  * SOCKS4 protocol, Client to SOCKS server:
  *
	field 1: SOCKS version number, 1 byte, must be 0x04 for this version
	field 2: command code, 1 byte:
		0x01 = establish a TCP/IP stream connection
		0x02 = establish a TCP/IP port binding
	field 3: port number, 2 bytes
	field 4: IPv4 address, 4 bytes
	field 5: the user ID string, variable length, terminated with a null (0x00)
 *
 *	Server to SOCKS client:
 *
	field 1: null byte
	field 2: status, 1 byte:
		0x5A = request granted
		0x5B = request rejected or failed
		0x5C = request failed because client is not running identd (or not reachable from the server)
		0x5D = request failed because client's identd could not confirm the user ID string in the request
	field 3: 2 bytes (should better be zero)
	field 4: 4 bytes (should better be zero)

 */

/*
 *
 *	TODO: download the whitelist
 *
	Process
	### IPv4: check ruleset
	white - list : direct FSP / IPv6 access(TCP / IPv4->FSP / IPv6, transmit via SOCKS)
	not in the white - list: FSP - relay
	{ /// UNRESOLVED! As a transit method:
	if not in white - list, try search PTR, [DnsQuery], if get the _FSP exception - list: direct connect
	}
	Further streaming :
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

#include "defs.h"


// Storage of private key SHOULD be allocated with random address layout
static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];

// Request string towards the remote tunnel server
static char tunnelRequest[80];

// FSP handle of the master connection that the client side, which accept the SOCKS4 service request,
// made towards the tunnel server. It is the client in the sense that it made tunnel service request
static FSPHANDLE hClientMaster;

// TCP socket to listen for SOCKSv4 service request
static SOCKET hListener;

// shared by master connection and child connection
static void FSPAPI onError(FSPHANDLE, FSP_ServiceCode, int);

// for master connection
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeySent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onRequestSent(FSPHANDLE, FSP_ServiceCode, int);
static bool	FSPAPI onResponseReceived(FSPHANDLE, void *, int32_t, bool);

// for child connection
static void FSPAPI onSubrequestSent(FSPHANDLE, FSP_ServiceCode, int);


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



// Given
//	char *	Remote FSP application name such as 192.168.9.125:80 or www.lt-x61t.home.net
//	int		The TCP port number on which the socket is listening for SOCKSv4 service request
// Do
//	Create a thread pool to service SOCKS request in a multi-threaded parallel fashion
void ToServeSOCKS(char *nameAppLayer, int port)
{
	int len = sprintf_s(tunnelRequest, sizeof(tunnelRequest), "TUNNEL %s HTTP/1.0\r\n", nameAppLayer);
	if(len < 0)
	{
		printf_s("Invalid name of remote tunnel server end-poine: %s\n", nameAppLayer);
		return;
	}

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = NULL;
	parms.onAccepted = onConnected;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE/2;
	parms.sendSize = MAX_FSP_SHM_SIZE/2;
	hClientMaster = Connect2(nameAppLayer, & parms);
	if(hClientMaster == NULL)
	{
		printf_s("Failed to initialize the FSP connection towards the tunnel server\n");
		return;
	}
	//
	if(! requestPool.Init(MAX_WORKING_THREADS))
	{
		printf_s("Failed to allocate tunnel service request pool\n");
		goto l_bailout;
	}

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
		goto l_bailout;
	}

    SetThreadpoolThreadMaximum(pool, MAX_WORKING_THREADS);
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

	hListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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

	printf_s("Ready to serve SOCKSv4 request at %s:%d\n", inet_ntoa(localEnd.sin_addr), be16toh(localEnd.sin_port));
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
//l_bailout3:
	// CloseThreadpoolCleanupGroupMembers also releases objects
	// that are members of the cleanup group, so it is not necessary 
	// to call close functions on individual objects 
	// after calling CloseThreadpoolCleanupGroupMembers.
    CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
//l_bailout2:
	CloseThreadpoolCleanupGroup(cleanupgroup);
l_bailout1:
    CloseThreadpool(pool);
l_bailout:
	Dispose(hClientMaster);
}



void
CALLBACK
TpWorkCallBack(PTP_CALLBACK_INSTANCE Instance, PVOID parameter, PTP_WORK Work)
{
    // Instance, Parameter, and Work not used in this example.
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

	PRequestPoolItem p = requestPool.AllocItem();
	SOCKET client = (SOCKET)parameter;
	if(p == NULL)
	{
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}	
	SRequestResponse & req = p->req;

	int r = recv(client, (char *) & req, sizeof(req), 0);
	if(r == SOCKET_ERROR)
	{  
        printf_s("recv() socks version failed with error: %d\n", WSAGetLastError());
		requestPool.FreeItem(p);
		ReportErrorToClient(client, REP_REJECTED);
        return;
    }

	// the implicit ruleset says that only socks version 4a supported
	if(req.version != SOCKS_VERSION)
	{
        printf_s("%d: unsupport version\n", req.version);
		requestPool.FreeItem(p);
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}
	if(req.cmd != SOCKS_CMD_CONNECT)
	{
        printf_s("%d: unsupport command\n", req.version);
		requestPool.FreeItem(p);
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}

#ifndef NDEBUG
	printf_s("Version %d, command code %d, target at %s:%d\n"
		, req.version
		, req.cmd
		, inet_ntoa(req.inet4Addr)
		, be16toh(req.nboPort));
#endif

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
		requestPool.FreeItem(p);
		ReportErrorToClient(client, REP_REJECTED);
		return;
	}
	printf_s("\n");
	//
	p->hSocket = client;

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = NULL;
	parms.onAccepted = NULL;
	parms.onError = onError;
	parms.recvSize = BUFFER_POOL_SIZE;
	parms.sendSize = BUFFER_POOL_SIZE;
	parms.welcome = &p->req;
	parms.len = (unsigned short)sizeof(p->req);
	parms.signatureULA = (ulong_ptr)p;
	//^For 
	FSPHANDLE h = MultiplyAndWrite(hClientMaster, & parms, TO_END_TRANSACTION, onSubrequestSent);
	if(h == NULL)
	{
		requestPool.FreeItem(p);
		ReportErrorToClient(client, REP_REJECTED);
	}
}



void ReportErrorToClient(SOCKET client, ERepCode code)
{
	SRequestResponse rep;
	memset(& rep, 0, sizeof(rep));
	rep.rep = code;

	int r = send(client, (char *) & rep, sizeof(rep), 0);
	if(r == SOCKET_ERROR)
	{
        printf_s("send() socks response failed with error: %d\n", WSAGetLastError());
		closesocket(client);
	}
	else if(code != REP_SUCCEEDED)
	{
		CloseClient(client, false);
	}
}



// Given
//	SOCKET	the handle of the TCP socket that connected to the SOCKS client
//	bool	forceful
//			true if to force shutdown without waiting for receive buffer emptied
// Do
//	Shutdown the connection to the SOCKS client gracefully if forceful is false
void CloseClient(SOCKET client, bool forceful)
{
	int r = forceful ? 1 : 0;
	struct timeval timeout;
	timeout.tv_sec = RECV_TIME_OUT;
	timeout.tv_usec = 0;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	//
	shutdown(client, SD_SEND);
	while(r > 0)
	{
		char c;
		r = recv(client, & c, 1, 0);
	}
	// until either nothing may be received or the peer has closed the connection
	closesocket(client);
}


//
// 
//

// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
#ifdef TRACE
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
#endif
	if(h == hClientMaster)
	{
		printf_s("Fatal IPC %d, error %d encountered in the session with the tunnel server.\n", code, value);
		Dispose(h);
		closesocket(hListener);
	}
	return;
}



// On connected, send the public key to the remote end. We save the public key
// temporarily on the stack because we're sure that there is at least one
// buffer block available and the public key fits in one buffer block 
static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	unsigned char bufPublicKey[CRYPTO_NACL_KEYBYTES];
	unsigned char bufPeersKey[CRYPTO_NACL_KEYBYTES];
	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
#ifdef TRACE
	printf_s("\nHandle of FSP session: %p", h);
#endif
	if(h == NULL)
	{
		printf_s("\n\tConnection failed.\n");
		return -1;
	}

	int mLen = strlen((const char *)ctx->welcome) + 1;
#ifdef TRACE
	printf_s("\tWelcome message length: %d\n", ctx->len);
	printf_s("%s\n", ctx->welcome);
#endif
	memcpy(bufPeersKey, (const char *)ctx->welcome + mLen, CRYPTO_NACL_KEYBYTES);

	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

#ifdef TRACE
	printf_s("\nTo send the key material for shared key agreement...\n");
#endif
	WriteTo(h, bufPublicKey, CRYPTO_NACL_KEYBYTES, TO_END_TRANSACTION, onPublicKeySent);

#ifdef TRACE
	printf_s("\tTo install the shared key instantly...\n");
#endif
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeersKey, bufPrivateKey);
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	return 0;
}



static void FSPAPI onPublicKeySent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
#ifdef TRACE
	printf_s("Result of sending public key: %d\n", r);
#endif
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	printf_s("To send tunnel request towards the tunnel server (the remote tunnel end):\n");
	puts(tunnelRequest);
	WriteTo(h, tunnelRequest, strlen(tunnelRequest), TO_END_TRANSACTION, onRequestSent);
}



// TODO: client's side authentication & authorization
static void FSPAPI onRequestSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(RecvInline(h, onResponseReceived) < 0)
	{
		Dispose(h);
		return;
	}
}



// On receive the name of the remote file prepare to accept the content by receive 'inline'
// here 'inline' means ULA shares buffer memory with LLS
static bool FSPAPI onResponseReceived(FSPHANDLE h, void * buf, int32_t len, bool eot)
{
	if(buf == NULL || len <= 0 || h != hClientMaster)
	{
		Dispose(h);
		return FALSE;
	}
	//
	// TODO: process the buffer!
	//
	if(eot && RecvInline(h, onResponseReceived) < 0)
		Dispose(h);

	return TRUE;
}



static void FSPAPI onSubrequestSent(FSPHANDLE h, FSP_ServiceCode c, int value)
{
	PRequestPoolItem p;
	FSPControl(h, FSP_GET_EXT_POINTER, (ulong_ptr) & p);
	if(p == NULL)
	{
		Dispose(h);
		return;
	}
	if(p->hSocket == INVALID_SOCKET)
	{
		requestPool.FreeItem(p);
		Dispose(h);
		return;
	}
	if(value < 0)
	{
		ReportErrorToClient(p->hSocket, REP_REJECTED);
		requestPool.FreeItem(p);
		Dispose(h);
		return;
	}
	//
	p->hFSP = h;
	RecvInline(h, onFSPDataAvailable);
	GetSendBuffer(h, toReadTCPData);
}
