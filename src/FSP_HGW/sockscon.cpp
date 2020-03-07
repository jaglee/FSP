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

	For version 4A, if the first three bytes of DSTIP(IPv4 address) are null
	and the last byte is a non-zero value, following the null byte terminating
	the user id string there is the destination domain name termianted by
	another null byte.

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
#include "fsp_http.h"

// Storage of private key SHOULD be allocated with random address layout
static octet bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
static char	 inputPassword[80];

ALIGN(8)
static SCHAKAPublicInfo chakaPubInfo;

// Request string towards the remote tunnel server
static char		tunnelRequest[80];

// FSP handle of the master connection that the client side, which accept the SOCKS4 service request,
// made towards the tunnel server. It is the client in the sense that it made tunnel service request
static FSPHANDLE hClientMaster;
static bool		 isRemoteTunnelEndReady = false;

// shared by master connection and child connection
static void FSPAPI onError(FSPHANDLE, FSP_ServiceCode, int);

// for master connection
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onCHAKASRReceived(FSPHANDLE, FSP_ServiceCode, int);
static bool	FSPAPI onResponseReceived(FSPHANDLE, void *, int32_t, bool);

// for child connection
static void FSPAPI onSubrequestSent(FSPHANDLE, FSP_ServiceCode, int);

// The SOCKS(v4/v5) server reports general failure to the SOCKS client
static void ReportGeneralError(SOCKET, PRequestPoolItem);

// Get the username and password. The username is stored in the given buffer,
// the password is saved in some hidden place
static void GetUserCredential(char *, int);


// Given
//	PRequestPoolItem		pointer to the allocated storage entry for the tunneled SOCKS request/response
//	SOCKET					the socket handler; if 0, it has been stored in RequestPoolItem
// Return
//	SOCKET_ERROR if socket receive error
//	0 if non-conforming
//	number of bytes read into the buffer
static int GetSOCKSv4Request(PRequestPoolItem p, SOCKET client = 0)
{
	SRequestResponse_v4& req = p->req;
	int r;
	bool hasDomainName = false;
	if(client == 0)
	{
		client = p->hSocket;
		r = offsetof(SSocksV5AuthMethodsRequest, methods);
		r = recv(client, (char*)&req + r, sizeof(req) - r, 0);
		//^See also SOCKSv5.cpp
	}
	else
	{
		p->hSocket = client;
		r = recv(client, (char*)&req, sizeof(req), 0);
	}
	if (r == SOCKET_ERROR)
	{
		perror("Get SOCKSv4 request: recv() failed");
		return r;
	}
	// the implicit rule says that only socks version 4a supported
	if (req.version != SOCKS_VERSION)
	{
		printf_s("%d: unsupported version\n", req.version);
		return 0;
	}
	if (req.cmd != SOCKS_CMD_CONNECT)
	{
		printf_s("%d: unsupported command\n", req.cmd);
		return 0;
	}

	octet* s = (octet*)&req.inet4Addr;
	if (s[0] == 0 && s[1] == 0 && s[2] == 0)
	{
		if (s[3] == 0)
		{
			printf_s("Non-conforming SOCKS4a client.");
			return 0;
		}
		hasDomainName = true;
	}
#ifndef NDEBUG
	printf_s("Version %d, command code %d, target at %s:%d\n"
		, req.version
		, req.cmd
		, inet_ntoa(req.inet4Addr)
		, be16toh(req.nboPort));
	printf_s("Skipped user Id: ");
#endif

	char c = 0;
	do
	{
		r = recv(client, & c, 1, 0);
		if(c == 0)
			break;
#ifndef NDEBUG
		putchar(c);
#endif
	} while(r > 0);
	//
	if(r < 0)
	{
#ifndef NDEBUG
		perror("Skip user id recv() failed");
#endif
		return r;
	}
#ifndef NDEBUG
	putchar('\n');
#endif

	// SOCKS4a
	if (hasDomainName)
	{
		SRequestResponseV4a& rq4a = p->rqV4a;
		int i = 0;
		do
		{
			r = recv(client, &c, 1, 0);
			rq4a.domainName[i++] = c;
			if (i >= MAX_LEN_DOMAIN_NAME && c != 0)
			{
#ifndef NDEBUG
				printf("Domain name is too long.\n");
#endif
				return 0;
			}
		} while (r > 0 && c != 0);
		if (!(r > 0))
		{
#ifndef NDEBUG
			perror("Get domain name failed");
#endif
			return r;
		}
#ifndef NDEBUG
		printf_s("To visit: %s\n", rq4a.domainName);
#endif
		r = sizeof(req) + i;
	}
	else
	{
		r = sizeof(req);
	}

	return r;
}



static void RejectV4Client(SOCKET client)
{
	SRequestResponse_v4 rep;
	memset(&rep, 0, sizeof(rep));
	rep.rep = REP_REJECTED;

	int r = send(client, (char*)&rep, sizeof(rep), 0);
	if (r == SOCKET_ERROR)
	{
		perror("Response to client, send() failed");
		closesocket(client);
	}
	else
	{
		CloseGracefully(client);
	}
}



#if defined(__WINDOWS__)
# include <MSWSock.h>

//
// This is the thread pool work callback function, forward declaration.
//
VOID CALLBACK TpWorkCallBack(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK Work);


// Given
//	char *	Remote FSP application name such as 192.168.9.125:80 or www.lt-x61t.home.net
//	int		The TCP port number on which the socket is listening for SOCKSv4 service request
// Do
//	Create a thread pool to service SOCKS request in a multi-threaded parallel fashion
void ToServeSOCKS(const char *nameAppLayer, int port)
{
	int len = sprintf_s(tunnelRequest, sizeof(tunnelRequest), "TUNNEL %s HTTP/1.0\r\n", nameAppLayer);
	if(len < 0)
	{
		printf_s("Invalid name of remote tunnel server end-point: %s\n", nameAppLayer);
		return;
	}
	Sleep(2000);	// wait for the remote tunnel end ready

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	// blocking mode, both onAccepting and onAccepted are default to NULL
	// parms.onAccepted = onConnected;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE/2;
	parms.sendSize = MAX_FSP_SHM_SIZE/2;
	hClientMaster = Connect2(nameAppLayer, & parms);
	if(hClientMaster == NULL)
	{
		printf_s("Failed to initialize the FSP connection towards the tunnel server\n");
		return;
	}

	// synchronous mode
	if (parms.onAccepted == NULL)
		onConnected(hClientMaster, GetFSPContext(hClientMaster));

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

	SOCKET	 hListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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

    int r = bind(hListener, (SOCKADDR *) &localEnd, sizeof(SOCKADDR));
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

	while(! isRemoteTunnelEndReady && hClientMaster != NULL)
		Sleep(50);
	if(hClientMaster == NULL)
		goto l_bailout6;

	printf_s("Ready to serve SOCKSv4 request at %s:%d\n", inet_ntoa(localEnd.sin_addr), be16toh(localEnd.sin_port));
	do
	{
		int iClientSize = sizeof(sockaddr_in);
		sockaddr_in saClient;
		PTP_WORK work = NULL;
		SOCKET hAccepted = accept(hListener, (SOCKADDR*) &saClient, &iClientSize);
		if(hAccepted == INVALID_SOCKET)
		{
			int r = WSAGetLastError();
		    printf_s("accept() failed with error: %d\n", r);
			if(r == WSAECONNRESET || r == WSAEINTR)
				continue;
			// If an incoming connection was indicated, but was subsequently terminated
			// by the remote peer prior to accepting the call, it was not a failure of the near end.
			// And it did happen that
			// 'A blocking Windows Sockets 1.1 call was canceled through WSACancelBlockingCall'!
			if(r != WSAENOBUFS)
				break;
			//
			Sleep(50);	// Simply refuse to serve more request for a while if there's no buffer temporarily
			continue;
		}
		//
		work = CreateThreadpoolWork(TpWorkCallBack, (PVOID)hAccepted, & envCallBack);
		if (work == NULL)
			RejectV4Client(hAccepted);
		else
			SubmitThreadpoolWork(work);
	} while(true);

    // Clean up in reverse order.
l_bailout6:
    closesocket(hListener);
l_bailout5:
    WSACleanup();

	// CloseThreadpoolCleanupGroupMembers also releases objects
	// that are members of the cleanup group, so it is not necessary 
	// to call close functions on individual objects 
	// after calling CloseThreadpoolCleanupGroupMembers.
    CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
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

	PRequestPoolItem p = requestPool.AllocItem();
	SOCKET client = (SOCKET)parameter;
	if(p == NULL)
	{
		closesocket(client);
		return;
	}
	p->hThread = (HANDLE)Work;

	int n = GetSOCKSv4Request(p, client);
	if(n <= 0)
	{
		requestPool.FreeItem(p);
		RejectV4Client(client);
		return;
	}

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = NULL;
	parms.onAccepted = NULL;
	parms.onError = onError;
	parms.keepAlive = 1;
	parms.recvSize = BUFFER_POOL_SIZE;
	parms.sendSize = BUFFER_POOL_SIZE;
	parms.welcome = &p->req;
	parms.len = (unsigned short)n;
	parms.extentI64ULA = (ULONG_PTR)p;
	//
	FSPHANDLE h = MultiplyAndWrite(hClientMaster, & parms, TO_END_TRANSACTION, onSubrequestSent);
	if(h == NULL)
	{
		requestPool.FreeItem(p);
		RejectV4Client(client);
	}
}



static void SetStdinEcho(bool enable = true)
{
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);
}



static void GetUserCredential(char *userName, int capacity)
{
	printf_s("Please input the username: ");
	scanf_s("%s", userName, capacity);

	printf_s("Please input the password: ");
	SetStdinEcho(false);

	scanf_s("%s", inputPassword, _countof(inputPassword));
	fgetc(stdin);	// Skip Carriage Return
	SetStdinEcho();
}


// For SOCKSv4 client only
static void ReportGeneralError(SOCKET client, PRequestPoolItem) { RejectV4Client(client); }


//
// TODO: timeout! for SOCKSv4, it is 2 minutes (120 seconds) 
//
#endif


// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
#ifdef TRACE
	printf_s("Notification: socket %p, service code = %d, return %d\n", h, code, value);
#endif
	if (value < 0)
		requestPool.FreeItem(h);
}



// On connected, send the public key to the remote end. We save the public key
// temporarily on the stack because we're sure that there is at least one
// buffer block available and the public key fits in one buffer block 
static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nConnecting to remote FSP SOCKS tunnel server...");
	if (h == NULL)
	{
		Abort("\n\tConnection failed.\n");
		return -1;
	}
	printf_s("Handle of FSP session : %p, error flag: %X\n", h, ctx->flags);

	int32_t recvSize;
	bool eot;
	char* msg = (char*)TryRecvInline(h, &recvSize, &eot);

	if (msg == NULL || !eot)
	{
		Abort("\nApplication Protocol Broken: server does not welcome new connection?!\n");
		return -1;
	}

	int i = 0;
	while (i < recvSize)
	{
		if (msg[i++] == 0)
			break;
	}
	if (recvSize - i != CRYPTO_NACL_KEYBYTES)
	{
		Abort("\nApplication Protocol Broken: server does not provide public key.\n");
		return -1;
	}
	printf_s("Welcome message received: %s\n", msg);

	InitCHAKAClient(chakaPubInfo, bufPrivateKey);
	memcpy(chakaPubInfo.peerPublicKey, msg + i, CRYPTO_NACL_KEYBYTES);

	WriteTo(h, chakaPubInfo.selfPublicKey, sizeof(chakaPubInfo.selfPublicKey), 0, NULL);
	WriteTo(h, &chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), 0, NULL);
	// And suffixed with the client's identity

	char userName[80];
	GetUserCredential(userName, (int)sizeof(userName));

	int nBytes = (int)strlen(userName) + 1;
	octet buf[MAX_PATH];
	// assert(strlen(theUserId) + 1 <= sizeof(buf));
	CryptoNaClGetSharedSecret(bufSharedKey, chakaPubInfo.peerPublicKey, bufPrivateKey);
	ChakaStreamcrypt(buf, (octet*)userName, nBytes, chakaPubInfo.clientNonce, bufSharedKey);
	WriteTo(h, buf, nBytes, TO_END_TRANSACTION, NULL);

	ReadFrom(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt), onCHAKASRReceived);

	return 0;
}



// second round C->S
static void FSPAPI onCHAKASRReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, & chakaPubInfo.serverNonce, sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), NULL);
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), NULL);
	// The peer should have commit the transmit transaction. Integrity is assured
	if (!HasReadEoT(h))
	{
		Dispose(h);
		Abort("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
	}

	octet clientInputHash[CRYPTO_NACL_HASHBYTES];
	MakeSaltedPassword(clientInputHash, chakaPubInfo.salt, inputPassword);

	octet clientResponse[CRYPTO_NACL_HASHBYTES];
	if(! CHAKAResponseByClient(chakaPubInfo, clientInputHash, clientResponse))
	{
		Dispose(h);
		Abort("Server authentication error.\n");
	}

	WriteTo(h, clientResponse, sizeof(clientResponse), TO_END_TRANSACTION, NULL);

	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);
	memset(bufSharedKey, 0, CRYPTO_NACL_KEYBYTES);
	memset(bufPrivateKey, 0, CRYPTO_NACL_KEYBYTES);
	printf_s("\nThe session key to be authenticated has been pre-installed.\n");

	printf_s("To send tunnel request towards the tunnel server (the remote tunnel end):\n");
	puts(tunnelRequest);
	r = WriteTo(h, tunnelRequest, strlen(tunnelRequest), TO_END_TRANSACTION, NULL);
	printf_s("%d octets sent.\n", r);

	if(RecvInline(h, onResponseReceived) < 0)
		Dispose(h);
}



// On receive the name of the remote file prepare to accept the content by receive 'inline'
// here 'inline' means ULA shares buffer memory with LLS
static bool FSPAPI onResponseReceived(FSPHANDLE h, void * buf, int32_t len, bool eot)
{
	if(buf == NULL || len <= 0 || h != hClientMaster)
	{
		Dispose(h);
		return false;
	}

	printf_s("%s\n", (char *)buf);
	if(strcmp((char *)buf, HTTP_SUCCESS_HEADER) == 0)
		isRemoteTunnelEndReady = true;

	if(eot && RecvInline(h, onResponseReceived) < 0)
	{
		Dispose(h);
		return false;
	}

	return true;
}



static void FSPAPI onSubrequestSent(FSPHANDLE h, FSP_ServiceCode c, int value)
{
#ifdef TRACE
	printf_s("SOCKS service request send, FSP handle is %p\n", h);
#endif
	PRequestPoolItem p = (PRequestPoolItem)GetExtPointer(h);
	if(p == NULL)
	{
		Dispose(h);
		return;
	}
	if(p->hSocket == (SOCKET)(SOCKET_ERROR))
	{
		requestPool.FreeItem(p);
		Dispose(h);
		return;
	}
	if(value < 0)
	{
		ReportGeneralError(p->hSocket, p);
		requestPool.FreeItem(p);
		Dispose(h);
		return;
	}
	//
	p->hFSP = h;
	if (SetOnRelease(h, onRelease) < 0
	 || RecvInline(h, onFSPDataAvailable) < 0
	 || GetSendBuffer(h, toReadTCPData) < 0)
	{
		ReportGeneralError(p->hSocket, p);
		requestPool.FreeItem(p);
		Dispose(h);
	}
}
