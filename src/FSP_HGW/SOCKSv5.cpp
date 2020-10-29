/*
 * Implement the SOCKSv5 interface of FSP SOCKS gateway, complementing SOCKSv4a in Linux
 *
    Copyright (c) 2020, Jason Gao
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
  * SOCKSv5 protocol, Client to SOCKS server:
  *
	field 1: SOCKS version number, 1 byte, must be 0x05 for this version
	field 2: NMETHOD supported authentication method, 1 byte
	field 3: 1~255 nmethod
		X'00': No authentication required
		X'01': GSSAPI (not supported here)
		X'02': USERNAME/PASSWORD
		X'03'-X'7E': IANA assigned
		X'80'-X'FE': Reserved for private methods
	
	Server to client:
	field 1: SOCKS version number, 1 byte, must be 0x05 for this version
	field 2: METHOD supported by the server

	Request:
	field 1: SOCKS version number, 1 byte, must be 0x05 for this version
	field 2: command code, 1 byte:
		0x01 = establish a TCP/IP stream connection
		0x02 = establish a TCP/IP port binding (/)
		0x03 = UDP associate (does not support here)
	field 3: reserved, shall be 0x00
	field 4: address type
		0x01 = IPv4
		0x03 = domain name
		0x04 = IPv6 (does not support here)
	field 5: IPv4 address, 4 bytes;
			 domain name, first octets is the length
	field 6: port number in network byte order, 2 bytes
 *
 *	Server to SOCKS client:
 *
	field 1: version number, 1 byte, must be 0x05 for this version
	field 2: status, 1 byte:
		0x00 = succeed
		0x01 = general SOCKS server failure
		0x02 = connection not allowed by ruleset
		0x03 = network unreachable
		0x04 = host unreachable
		0x05 = connection refused
		0x06 = TTL expired
		0x07 = command not supported
		0x08 = address type not supported
		0x09-0xFF: reserved
		This must be no more than 10 seconds after detecting the condition that caused a failure.
	field 3: reserved, 1 byte, 0
	field 4: ATYP, 1 byte, address type
		0x01 = IPv4, otherwise unsupported for this implementation
	field 5: server bound address
	field 6: server bound port number in network byte order, 2 bytes

 */

// To provide SOCKSv4 service for Windows platform
// share the same build blocks for FSP tunnel
#include "sockscon.cpp"


#if defined(__linux__) || defined(__CYGWIN__)

// Side-effect: close the socket gracefully if error sent successfully, reset the socket if not
static void ReportV5ErrorToClient(SOCKET client, PRequestPoolItem p, ERepCode code)
{
	if(client == SOCKET_ERROR)
	{
		printf("What? the socket has already been closed.\n");
		return;
	}

	SRequestResponseV5 &rep = p->rqV5;
	int r;
	rep.rep = code;
	if(rep.addrType == ADDRTYPE_IPv4)
		r = int(offsetof(SRequestResponseV5, nboPort) + sizeof(rep.nboPort));
	else if(rep.addrType == ADDRTYPE_DOMAINNAME)
		r = int(offsetof(SRequestResponseV5, domainName) + 3) + rep.domainName.len;
	else if(rep.addrType == ADDRTYPE_IPv6)
		r = int(offsetof(SRequestResponseV5, domainName) + sizeof(in6_addr) + sizeof(rep.nboPort));
	else // if(rep.addrType == 0)
		r = int(offsetof(SRequestResponseV5, domainName));	// minimum

	r = (int)send(client, &rep, r, 0);
	if(r < 0)
	{
		perror("send() socks response failed\n");
		closesocket(client);
	}
	else
	{
		CloseGracefully(client);
	}
}



static inline void ReportGeneralError(SOCKET client, PRequestPoolItem p)
{
	if(p->socks_version == SOCKS_VERSION_5)
		ReportV5ErrorToClient(client, p, SOCKS_SERVER_FAILURE);
	else
		RejectV4Client(client);
}



// Return -1 if failed, or else number of octets of the requests to forward
static int NegotiateSOCKSv5(PRequestPoolItem p)
{
	SSocksV5AuthMethodsRequest &req = p->amr;
	SSocksV5AuthMethodResponse &rsp = p->ans;
#if defined(_DEBUG_PEEK)
	printf_s("Authentication request, version: %d, methods count: %d\n", req.version, req.count);
#endif

	if(req.count == 0)
	{
        printf_s("There should be at least one supported authentication method\n");
l_negotiation_failed:
		rsp.method = SOCKS_V5_NO_ACCEPTABLE;
		send(p->hSocket, &rsp, sizeof(rsp), 0);
		closesocket(p->hSocket);
		return 0;
	}

	int r = (int)recv(p->hSocket, req.methods, req.count, 0);
	if(r < 0)
	{  
        perror("Cannot fetch authentation method list from the client's request");
		closesocket(p->hSocket);
		return r;
    }

	int i = 0;
	do
	{
		if(req.methods[i] == SOCKS_V5_AUTH_NULL)
			break;
	} while(++i < (int)req.count);
	if(i >= (int)req.count)
	{
		printf("What? No default authentication method SOCKS_V5_AUTH_NULL.\n");
		goto l_negotiation_failed;
	}

	// This implementation does not support GSSAPI authentication yet. It does not conform to RFC1928:(
	rsp.method = SOCKS_V5_AUTH_NULL;
	r = (int)send(p->hSocket, &rsp, sizeof(rsp), 0);
	if(r != sizeof(rsp))
	{
		perror("Failed to send authentication method response");
		closesocket(p->hSocket);
		return 0;
	}

	// By default read the full IPv4 address, assume that no domain name is of length less than 3 characters
	SRequestResponseV5 & rq5 = p->rqV5;
	r = (int)recv(p->hSocket, &rq5, offsetof(SRequestResponseV5, nboPort) + sizeof(rq5.nboPort), 0);
	if(r < 0)
	{
		perror("Failed to read the SOCKv5 connect request");
		closesocket(p->hSocket);
		return r;
	}
#if defined(_DEBUG_PEEK)
	printf_s("Connect request, version: %d, command code: %d, address type:%d\n", rq5.version, rq5.cmd, rq5.addrType);
#endif

	// printf_s("%d: unsupported version of connect request\n", rq5.version);
	if(rq5.version != SOCKS_VERSION_5)
	{
		ReportV5ErrorToClient(p->hSocket, p, SOCKS_CONNECT_DISALLOWED);
		return 0;
	}
	// built-in rule: only CONNECT is supported in this implementation
	if(rq5.cmd != SOCKS_CMD_CONNECT)
	{
		ReportV5ErrorToClient(p->hSocket, p, SOCKS_COMMAND_UNSUPPORTED);
		return 0;
	}

	// built-in rule: do not support IPv6 in this implementation	
	if(rq5.addrType == ADDRTYPE_DOMAINNAME)
	{
		int m = int(rq5.domainName.len - (sizeof(in_addr) - 1));
		if(m < 0 || m >= MAX_LEN_DOMAIN_NAME - int(sizeof(in_addr) - 1))
		{
			ReportV5ErrorToClient(p->hSocket, p, SOCKS_ADDRESS_UPSUPPORTED);
			return m;
		}
		// to read octets yet to accept
		if(m > 0)
		{
			m = (int)recv(p->hSocket, (octet *)&rq5.nboPort + sizeof(rq5.nboPort), m, 0);
			if(m < 0)
			{
				perror("Cannot get the domain name from the request");
				return m;
			}
			r += m;
		}
#ifdef _DEBUG_PEEK
		printf("Domain name length = %d\n", rq5.domainName.len);
#endif
	}
	else if(rq5.addrType != ADDRTYPE_IPv4)
	{
		ReportV5ErrorToClient(p->hSocket, p, SOCKS_ADDRESS_UPSUPPORTED);
		return 0;
	}

	return (p->lenReq = r);
}



// Given
//	char *	Remote FSP application name such as 192.168.9.125:80 or www.lt-x61t.home.net
//	int		The TCP port number on which the socket is listening for SOCKSv4 service request
// Do
//	Allocate an entry in the request service pool and serve the request in parallel fashion
// Remark
//	Instead of create a thread pool in the counterpart Windows platform
void ToServeSOCKS(const char *nameAppLayer, int port)
{
	FSP_SocketParameter parms;
	int hListener;
	int r;
	sockaddr_in localEnd;

	memset(& parms, 0, sizeof(parms));
	// blocking mode, both onAccepting and onAccepted are default to NULL
	parms.onError = NULL;
	parms.recvSize = MAX_FSP_SHM_SIZE/2;
	parms.sendSize = MAX_FSP_SHM_SIZE/2;
	hClientMaster = Connect2(nameAppLayer, & parms);
	if(hClientMaster == NULL)
	{
		printf_s("Failed to initialize the FSP connection towards the tunnel server\n");
		return;
	}
	onConnected(hClientMaster, GetFSPContext(hClientMaster));

	hListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(hListener == SOCKET_ERROR)
	{
		perror("Create socket failed");
		goto l_bailout;
	}

	localEnd.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	localEnd.sin_family = AF_INET;
	localEnd.sin_port = htons(port);
	memset(localEnd.sin_zero, 0, sizeof(localEnd.sin_zero));

    r = bind(hListener, (SOCKADDR *) &localEnd, sizeof(SOCKADDR));
    if (r == SOCKET_ERROR)
	{
		perror("bind() failed");
		goto l_bailout6;
    }
  
    r = listen(hListener, 5);
    if (r == SOCKET_ERROR)
	{  
        perror("listen() failed");
		goto l_bailout6;
    }

	if(MakeRequest(hClientMaster, nameAppLayer) != 0)
		goto l_bailout6;

	printf_s("Ready to serve SOCKSv4/v5 request at %s:%d\n", inet_ntoa(localEnd.sin_addr), ntohs(localEnd.sin_port));
	do
	{
		socklen_t iClientSize = sizeof(sockaddr_in);
		sockaddr_in saClient;
		SOCKET hAccepted = accept(hListener, (SOCKADDR*) &saClient, &iClientSize);
		if(hAccepted == (SOCKET)SOCKET_ERROR)
		{
			r = errno;
			perror("accept() failed");
			if(r == ECONNABORTED || r == EINTR)
				continue;
			if(r != ENOBUFS)
				break;
			Sleep(2000);	// Simply refuse to serve more request for a while if there's no buffer temporily
			continue;
		}
		//
		PRequestPoolItem p = requestPool.AllocItem();
		if(p == NULL)
		{
			closesocket(hAccepted);
			Sleep(2000);
			continue;
		}

		struct timeval timeout;
		timeout.tv_sec = RECV_TIME_OUT;
		timeout.tv_usec = 0;
		setsockopt(hAccepted, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		//
		p->hSocket = hAccepted;
		SSocksV5AuthMethodsRequest &req = p->amr;
		int r = (int)recv(p->hSocket, &req, offsetof(SSocksV5AuthMethodsRequest, methods), 0);
		if(r <= 0)
		{  
			perror("recv() authentation method negation failed");
			closesocket(p->hSocket);
			requestPool.FreeItem(p);
			continue;
		}

		if(req.version == SOCKS_VERSION_5)
			r = NegotiateSOCKSv5(p);
		else if((r = GetSOCKSv4Request(p)) <= 0)
			RejectV4Client(hAccepted);
		//
		if(r <= 0)
		{
			requestPool.FreeItem(p);
			continue;
		}

		if (!ForkFSPThread(p))
		{
			perror("Cannot fork FSP thread");
			ReportGeneralError(hAccepted, p);
			requestPool.FreeItem(p);
		}
	} while(true);
	printf("The main loop terminated abruptly. Press Enter to exit...\n");
	getchar();

	// Clean up in reverse order.
l_bailout6:
    closesocket(hListener);
l_bailout:
	Dispose(hClientMaster);	
}



static void SetStdinEcho(bool enable = true)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}



static void GetUserCredential(char *userName, int capacity, char inputPassword[])
{
	printf_s("Please input the username: ");
	fgets(userName, capacity, stdin);
	// but newline, if any, must be filtered out
	char *c = index(userName, '\n');
	*c = '\0';

	printf_s("Please input the password: ");
	SetStdinEcho(false);
	fgets(inputPassword, MAX_PASSWORD_LENGTH, stdin);
	SetStdinEcho();
	c = index(inputPassword, '\n');
	*c = '\0';
}

#endif

