/*
 * Implement the SOCKSv4 interface of FSP http accelerator, SOCKS gateway and tunnel server
 * Usage fsp_socks -p <port number> [Remote FSP address]
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

#ifndef MAX_WORKING_THREADS
# define MAX_WORKING_THREADS	40
#endif

ALIGN(8)
static SCHAKAPublicInfo chakaPubInfo;

// FSP handle of the master connection that the client side, which accept the SOCKS4 service request,
// made towards the tunnel server. It is the client in the sense that it made tunnel service request
static FSPHANDLE hClientMaster;

// for master connection
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);

// for child connection
static int	FSPAPI onSubrequestSent(FSPHANDLE, PFSP_Context);

// The SOCKS(v4/v5) server reports general failure to the SOCKS client
static void ReportGeneralError(SOCKET, PRequestPoolItem);

// Get the username and password. The username is stored in the given buffer,
// the password is saved in some hidden place
static void GetUserCredential(char *, int, char[]);

// Forward declaration of the top level function that implements service interface for SOCKS gateway
static void	ToServeSOCKS(const char*, int);

// Forward declaration of the function that negotiates with the remote tunnel end via FSP
static int MakeRequest(FSPHANDLE, const char *);

int main(int argc, char* argv[])
{
	int r = -1;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(0x202, &wsaData) < 0)
	{
		printf_s("Cannot start up Windows socket service provider.\n");
		return r;
	}
#endif

	if (!requestPool.Init(MAX_WORKING_THREADS))
	{
		printf_s("Failed to allocate tunnel service request pool\n");
		goto l_return;
	}
	Sleep(2000);	// wait for the remote tunnel end ready

	if (argc <= 1)
	{
		printf_s("To serve SOCKS"
#if defined(__WINDOWS__)
			"v4"
#elif defined(__linux__) || defined(__CYGWIN__)
			"v5"
#endif
			" request at port %d\n", DEFAULT_SOCKS_PORT);
		ToServeSOCKS("localhost:80", DEFAULT_SOCKS_PORT);
		r = 0;
	}
	else if (strcmp(argv[1], "-p") == 0)
	{
		if (argc != 3 && argc != 4)
		{
			printf_s("Usage: %s -p <port number> [remote fsp app-name, e.g. 192.168.9.125:80]", argv[0]);
			goto l_return;
		}

		int port = atoi(argv[2]);
		if (port == 0 || port > USHRT_MAX)
		{
			printf_s("Port number should be a value between 1 and %d\n", USHRT_MAX);
			goto l_return;
		}

		const char* nameAppLayer = (argc == 4 ? argv[3] : "localhost:80");
		printf_s("To serve SOCKS"
#if defined(__WINDOWS__)
			"v4"
#elif defined(__linux__) || defined(__CYGWIN__)
			"v5"
#endif
			" request at port %d\n", port);
		ToServeSOCKS(nameAppLayer, port);
		r = 0;
	}
	else
	{
		printf_s("Usage: %s [-p <port number> [remote fsp url]]\n", argv[0]);
		goto l_return;
	}

	printf("\n\nPress Enter to exit...");
	getchar();

l_return:
#ifdef _WIN32
	WSACleanup();
#endif
	exit(r);
}



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

	return (p->lenReq = r);
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



static bool ForkFSPThread(PRequestPoolItem p)
{
	FSP_SocketParameter parms;
	memset(&parms, 0, sizeof(parms));
	parms.onAccepting = NULL;
	parms.onAccepted = onSubrequestSent;
	parms.onError = onBranchError;
	parms.keepAlive = 1;
	parms.recvSize = BUFFER_POOL_SIZE;
	parms.sendSize = BUFFER_POOL_SIZE;
	parms.welcome = &p->req;
	parms.len = (unsigned short)p->lenReq;
	parms.extentI64ULA = (uint64_t)(ULONG_PTR)p;
	//
	p->hFSP = Multiply(hClientMaster, &parms);
	return (p->hFSP != NULL);
}



#if defined(__WINDOWS__)
# include <MSWSock.h>

// Given
//	char *	Remote FSP application name such as 192.168.9.125:80 or www.lt-x61t.home.net
//	int		The TCP port number on which the socket is listening for SOCKSv4 service request
// Do
//	Create a thread pool to service SOCKS request in a multi-threaded parallel fashion
static void ToServeSOCKS(const char* nameAppLayer, int port)
{
	printf_s("\nConnecting to remote FSP SOCKS tunnel server...");
	// Block 1
	FSP_SocketParameter parms;
	memset(&parms, 0, sizeof(parms));
	// blocking mode, both onAccepting and onAccepted are default to NULL
	parms.onError = NULL;
	parms.recvSize = MAX_FSP_SHM_SIZE / 2;
	parms.sendSize = MAX_FSP_SHM_SIZE / 2;
	hClientMaster = Connect2(nameAppLayer, &parms);
	if (hClientMaster == NULL)
	{
		printf_s("Failed to initialize the FSP connection towards the tunnel server\n");
		return;
	}
	onConnected(hClientMaster, GetFSPContext(hClientMaster));

	// Block 2, make local SOCKS ready to serve
	SOCKET	 hListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (hListener == SOCKET_ERROR)
	{
		printf_s("socket() failed with error: %d\n", WSAGetLastError());
		goto l_bailout;
	}

	sockaddr_in localEnd;
	localEnd.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	localEnd.sin_family = AF_INET;
	localEnd.sin_port = htons(port);
	memset(localEnd.sin_zero, 0, sizeof(localEnd.sin_zero));

	int r = bind(hListener, (SOCKADDR*)&localEnd, sizeof(SOCKADDR));
	if (r == SOCKET_ERROR)
	{
		printf_s("bind() failed with error: %d\n", WSAGetLastError());
		goto l_bailout6;
	}

	r = listen(hListener, 5);
	if (r == SOCKET_ERROR)
	{
		printf_s("listen() failed with error: %d\n", WSAGetLastError());
		goto l_bailout6;
	}

	if(MakeRequest(hClientMaster, nameAppLayer) != 0)
		goto l_bailout6;

	printf_s("Ready to serve SOCKSv4 request at %s:%d\n", inet_ntoa(localEnd.sin_addr), be16toh(localEnd.sin_port));
	do
	{
		int iClientSize = sizeof(sockaddr_in);
		sockaddr_in saClient;
		SOCKET hAccepted = accept(hListener, (SOCKADDR*)&saClient, &iClientSize);
		if (hAccepted == INVALID_SOCKET)
		{
			int r = WSAGetLastError();
			printf_s("accept() failed with error: %d\n", r);
			if (r == WSAECONNRESET || r == WSAEINTR)
				continue;
			// If an incoming connection was indicated, but was subsequently terminated
			// by the remote peer prior to accepting the call, it was not a failure of the near end.
			// And it did happen that
			// 'A blocking Windows Sockets 1.1 call was canceled through WSACancelBlockingCall'!
			if (r != WSAENOBUFS)
				break;
			//
			Sleep(50);	// Simply refuse to serve more request for a while if there's no buffer temporarily
			continue;
		}

		PRequestPoolItem p = requestPool.AllocItem();
		if (p == NULL)
		{
			closesocket(hAccepted);
			Sleep(50);
			continue;
		}
		p->hSocket = hAccepted;

		DWORD timeout = RECV_TIME_OUT * 1000;
		setsockopt(hAccepted, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

		if (GetSOCKSv4Request(p, hAccepted) <= 0 || !ForkFSPThread(p))
		{
			RejectV4Client(hAccepted);
			requestPool.FreeItem(p);
		}
	} while (true);

	// Clean up in reverse order.
l_bailout6:
	closesocket(hListener);

l_bailout:
	Dispose(hClientMaster);
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



static void GetUserCredential(char *userName, int capacity, char inputPassword[])
{
	printf_s("Please input the username: ");
	fgets(userName, capacity, stdin);
	// Skip Carriage Return
	for (register int i = 0; i < capacity; i++)
	{
		if (userName[i] == '\n' || userName[i] == '\r')
		{
			userName[i] = 0;
			break;
		}
	}

	printf_s("Please input the password: ");
	SetStdinEcho(false);

	fgets(inputPassword, MAX_PASSWORD_LENGTH, stdin);
	// Skip Carriage Return
	for (register int i = 0; i < MAX_PASSWORD_LENGTH; i++)
	{
		if (inputPassword[i] == '\n' || inputPassword[i] == '\r')
		{
			inputPassword[i] = 0;
			break;
		}
	}

	SetStdinEcho();
}



// For SOCKSv4 client only
static void ReportGeneralError(SOCKET client, PRequestPoolItem) { RejectV4Client(client); }

#endif


//
// TODO: timeout! for SOCKSv4, it is 2 minutes (120 seconds) 
//
#define Abort(s)	{ puts(s); return -1; }

static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("Handle of FSP session : %p, error flag: %X\n", h, ctx->flags);

	int32_t recvSize;
	bool eot;
	int r;
	int n;
	char* msg = (char*)TryRecvInline(h, &recvSize, &eot);

	if (msg == NULL || !eot)
		Abort("\nApplication Protocol Broken: server does not welcome new connection?!\n");

	int i = 0;
	while (i < recvSize)
	{
		if (msg[i++] == 0)
			break;
	}
	if (recvSize - i != CRYPTO_NACL_KEYBYTES)
		Abort("\nApplication Protocol Broken: server does not provide public key.\n");
	printf_s("Welcome message received: %s\n", msg);

	// CHAKA step 1, public key to shared key and encrpted id exchange, C->S
	octet bufPrivateKey[CRYPTO_NACL_KEYBYTES];
	char  inputPassword[MAX_PASSWORD_LENGTH];
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
	InitCHAKAClient(chakaPubInfo, bufPrivateKey);
	memcpy(chakaPubInfo.peerPublicKey, msg + i, CRYPTO_NACL_KEYBYTES);

	r = WriteTo(h, chakaPubInfo.selfPublicKey, sizeof(chakaPubInfo.selfPublicKey), 0, NULL);
	if (r < 0)
		Abort("Failed to send the near end's public key");
	n = r;
	r = WriteTo(h, &chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), 0, NULL);
	if (r < 0)
		Abort("Failed to send the near end's nonce");
	n += r;

	// And suffixed with the client's identity, encrypted with the shared secret:
	char	userName[MAX_NAME_LENGTH];
	octet	buf[MAX_NAME_LENGTH];
	GetUserCredential(userName, (int)sizeof(userName), inputPassword);
	CryptoNaClGetSharedSecret(bufSharedKey, chakaPubInfo.peerPublicKey, bufPrivateKey);
	// The real length of the client's identity string is hidden
	ChakaStreamcrypt(buf, (octet*)userName, MAX_NAME_LENGTH, chakaPubInfo.clientNonce, bufSharedKey);
	printf("--user name %s is encrypted.\n", userName);

	r = WriteTo(h, buf, MAX_NAME_LENGTH, TO_END_TRANSACTION, NULL);
	if (r < 0)
		Abort("Failed to send the near end's encrypted identity");
	n += r;
	printf("%d octets written to the remote end.\n", n);

	// CHAKA step 2, first round S->C
	r = ReadFrom(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt), NULL);
	if (r < 0)
		Abort("Cannot get the saved salt");
	r = ReadFrom(h, &chakaPubInfo.serverNonce, sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), NULL);
	if (r < 0)
		Abort("Cannot get the remote end's challenging nonce");
	r = ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), NULL);
	if (r < 0)
		Abort("Cannot get the remote end's response of near end's challenge");
	// The peer should have commit the transmit transaction. Integrity is assured
	if (!HasReadEoT(h))
	{
		Dispose(h);
		Abort("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
	}
	printf("Salt, peer's challenge, and peer's response to the challeng of the near end received.\n");

	// CHAKA step 3, second round C->S
	octet clientInputHash[CRYPTO_NACL_HASHBYTES];
	MakeSaltedPassword(clientInputHash, chakaPubInfo.salt, inputPassword);

	octet clientResponse[CRYPTO_NACL_HASHBYTES];
	if (!CHAKAResponseByClient(chakaPubInfo, clientInputHash, clientResponse))
	{
		Dispose(h);
		Abort("Server authentication error.\n");
	}

	r = WriteTo(h, clientResponse, sizeof(clientResponse), TO_END_TRANSACTION, NULL);
	if (r < 0)
		Abort("Failed to send near end's response of server's challenge");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);
	memset(bufSharedKey, 0, CRYPTO_NACL_KEYBYTES);
	memset(inputPassword, 0, MAX_PASSWORD_LENGTH);
	memset(bufPrivateKey, 0, CRYPTO_NACL_KEYBYTES);
	printf_s("\nThe session key to be authenticated has been pre-installed.\n");

	return 0;
}



static int MakeRequest(FSPHANDLE h, const char *nameAppLayer)
{
	char	tunnelRequest[MAX_PATH];
	int r = snprintf(tunnelRequest, sizeof(tunnelRequest), "TUNNEL %s HTTP/1.0\r\n", nameAppLayer);
	if(r < 0)
	{
		puts(nameAppLayer);
		Abort("invalid name of remote tunnel server end-point.");
	}

	// Tunnel request and response:
	puts("To send tunnel request towards the tunnel server (the remote tunnel end):");
	puts(tunnelRequest);
	r = WriteTo(h, tunnelRequest, strlen(tunnelRequest), TO_END_TRANSACTION, NULL);
	if (r < 0)
		Abort("Failed to send the tunnel request");
	printf_s("%d octets sent.\n", r);

	r = ReadFrom(h, tunnelRequest, sizeof(tunnelRequest), NULL);
	if (r < 0)
		Abort("Tunnel negotiation failed.");
	tunnelRequest[sizeof(tunnelRequest) - 1] = 0;
	puts(tunnelRequest);	// The response, actually.

	return 0;
}



static int FSPAPI onSubrequestSent(FSPHANDLE h, PFSP_Context)
{
#ifdef TRACE
	printf_s("SOCKS service request send, FSP handle is %p\n", h);
#endif
	PRequestPoolItem p = (PRequestPoolItem)GetExtPointer(h);
	if(p == NULL)
	{
		Dispose(h);
		return -1;
	}
	if(p->hSocket == (SOCKET)(SOCKET_ERROR))
	{
		requestPool.FreeItem(p);
		Dispose(h);
		return -1;
	}
	//
	p->hFSP = h;	// In case this function was called back before Multiply return
	if (SetOnRelease(h, onRelease) < 0
	 || GetSendBuffer(h, toReadTCPData) < 0 
	 || RecvInline(h, onFSPDataAvailable) < 0)
	{
		ReportGeneralError(p->hSocket, p);
		FreeRequestItem(p);
		return -1;
	}

	return 0;
}
