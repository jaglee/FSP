/*
 * Simple HTTP 1.0 server over FSP version 0. SOCKS gateway and tunnel server as well
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SERVER_STRING	"Server: fspgated/0.1\r\n"
#include "errstrs.hpp"
#include "fsp_http.h"

#ifdef WIN32
#include <WinSock2.h>
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
 * The key agreement block
 */

// assume that address space layout randomization keep the secret hard to find
static octet longTermPublicKey[CRYPTO_NACL_KEYBYTES];
static octet bufASLRPrivateKey[CRYPTO_NACL_KEYBYTES];

static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r);
static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r);

// The FSP handle that listens for tunnel service request
static FSPHANDLE hListener; 
static bool finished;
static char DEFAULT_ROOT[MAX_PATH];

static int	FSPAPI onAccepted(FSPHANDLE, PFSP_Context);
static void FSPAPI onNotice(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFinish(FSPHANDLE, FSP_ServiceCode, int);

static void FSPAPI onFirstLineRead(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFurtherTunnelRequest(FSPHANDLE, FSP_ServiceCode, int);

// Forward declaration of the default toplevel function of the
// HTTP server 1.0 over FSP version 0 AND tunnel server
void	StartHTTPoverFSP();

// Forward declaration of the toplevel function that implements service interface for SOCKS gateway
void	ToServeSOCKS(char *, int);

// Given
//	const *		the error message meant to be put on system console (and should be logged)
// Do
//	Exit the program abruptly for some fatal reason
void	Abort(const char *);

// Given
//	FSPHANDLE		The handle of the FSP connection that was made towards the browser
//					that supports HTTP over FSP, or the tunnel service client
//	const char *	path of the executable
//	const char *	invoke HTTP method of the executable. 'GET' or 'POST' only for this version
//	const char *	the query string in the original URL that was meant to pass to the executable
// Do
//	Execute the CGI executable that subjected to *FCGI* management
void	execute_cgi(FSPHANDLE, const char *, const char *, const char *);

// Given
//	FSPHANDLE	The handle of the FSP connection that was made towards the browser
//	char *		The buffer to hold the request line
//	int			The capacity of the buffer which should be more than 80, less than 32767
// Return
//	Non-negative:	number of octets read,
//	Negative:		the error number
// Remark
//	Request byte stream is further buffered internally
int		ReadLine(FSPHANDLE, char *, int);

// Given
//	FSPHANDLE		The handle of the FSP connection that was made towards the browser
//	const char *	the name of the file whose content is meant to be sent to the browser
// Do
//	Read the content of file and send the binary stream to the remote end
// Remark
//	For this version assume only the html content type is supported
void	SendRegFile(FSPHANDLE, const char *);


inline void WriteErrStr(FSPHANDLE client, const char *buf)
{
	WriteTo(client, buf, strlen(buf) + 1, TO_END_TRANSACTION, NULL);
}


inline void FreeExtent(FSPHANDLE h, bool disposing = false)
{
	void *p = GetExtPointer(h);
	if(p != NULL)
	{
		free(p);
		FSPControl(h, FSP_SET_EXT_POINTER, NULL);
	}
	//
	if(disposing)
		Dispose(h);
}


// [%s] ['-p' <port number>] | ['-d' <local web root>]
// Convention over configuration:
// By default it is a local SOCKS4a server that listen on the default port number 1080
// The port number could be configured on the command line only.
// If the command line specifies the port number, it could only be a local SOCKS4a server
// If the command line specifies the local web root, it is the remote end point of the tunnel
int main(int argc, char *argv[])
{
	WSADATA wsaData;
	int r = -1;
	//
	if (WSAStartup(0x202, &wsaData) < 0)
	{
		printf_s("Cannot start up Windows socket service provider.\n");
		return r;
	}

	if(argc <= 1)
	{
		printf_s("To serve SOCKS v4 request at port %d\n", DEFAULT_SOCKS_PORT);
		ToServeSOCKS("localhost:80", DEFAULT_SOCKS_PORT);
		r = 0;
	}
	else if (strcmp(argv[1], "-p") == 0)
	{
		if(argc != 3 && argc != 4)
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

		char *nameAppLayer = (argc == 4 ? argv[3] : "localhost:80");
		printf_s("To serve SOCKS v4 request at port %d\n", port);
		ToServeSOCKS(nameAppLayer, port);
		r = 0;
	}
	else if (strcmp(argv[1], "-d") == 0)
	{
		if (argc != 3 && argc != 4)
		{
			printf_s("Usage[as a tunnel remote-end and httpf server]: %s -d <root directory> [max-requests]\n", argv[0]);
			goto l_return;
		}
		//
		strcpy_s(DEFAULT_ROOT, sizeof(DEFAULT_ROOT), argv[2]);
		DEFAULT_ROOT[sizeof(DEFAULT_ROOT) - 1] = 0;
		//
		struct stat st;
		if (stat(DEFAULT_ROOT, &st) == -1 || (st.st_mode & S_IFMT) != S_IFDIR)
		{
			printf_s("Either the path is too long or the directory does not exist:\n\t%s\n", argv[2]);
			goto l_return;
		}
		//
		int n = argc > 3 ? atoi(argv[3]) : MAX_WORKING_THREADS;
		if (n <= 0 || !requestPool.Init(n))
		{
			printf_s("No enough resource to accept up to %d requests. Check configuration.\n", n);
			goto l_return;
		}
		//
		printf_s("To serve SOCKS tunneling request and Web Service over FSP at directory:\n%s\n\n", DEFAULT_ROOT);
		StartHTTPoverFSP();
		r = 0;
	}
	else
	{
		printf_s("Usage: %s [-p <port number> [remote fsp url]] | -d <web root directory>\n", argv[0]);
		goto l_return;
	}

	printf("\n\nPress Enter to exit...");
	getchar();

l_return:
	WSACleanup();
	exit(r);
}



// HTTP 1.0 over FSP version 0 with 'TUNNEL' extension
void StartHTTPoverFSP()
{
	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;

	unsigned short mLen = (unsigned short)strlen(SERVER_STRING) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	CryptoNaClKeyPair(longTermPublicKey, bufASLRPrivateKey);
	memcpy(thisWelcome, SERVER_STRING, mLen);
	memcpy(thisWelcome + mLen, longTermPublicKey, CRYPTO_NACL_KEYBYTES);
	mLen += CRYPTO_NACL_KEYBYTES;

	memset(&params, 0, sizeof(params));
	params.onAccepting = NULL;	// make it blocking
	params.onAccepted = onAccepted;
	params.onError = onNotice;
	params.onFinish = onFinish;
	params.welcome = thisWelcome;
	params.len = mLen;
	params.sendSize = BUFFER_POOL_SIZE;
	params.recvSize = BUFFER_POOL_SIZE;	

#ifdef _DEBUG
	TranslateFSPoverIPv4(&atAddress, 0, 80);	//INADDR_ANY
#else
	atAddress.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned
	atAddress.idHost = 0;
	atAddress.idALF = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 
#endif

	hListener = ListenAt(&atAddress, &params);
	if (hListener == NULL)
	{
		printf_s("Cannot start the FSP Listener.\n");
		return;
	}

	FSPHANDLE hService;
	while((hService = Accept1(hListener)) != NULL)
	{
		FSPControl(hService, FSP_SET_CALLBACK_ON_REQUEST, (ulong_ptr)onMultiplying);
	}

	if (hListener != NULL)
		Dispose(hListener);
}


// The callback function to handle general notification of LLS. Parameters are self-describing.
static void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	if(value >= 0)
		return;	// waring is simply ignored
	//
	if(h == hListener)
		finished = true;
	else
		FreeExtent(h);
}



// The function called back when an FSP connection was released. Parameters are self-describing
static void FSPAPI onFinish(FSPHANDLE h, FSP_ServiceCode code, int)
{
	printf_s("Socket %p, session was to shut down, service code = %d.\n", h, code);
	if(code == FSP_NotifyToFinish)
	{
		FSPControl(h, FSP_SET_CALLBACK_ON_FINISH, NULL);
		Shutdown(h);
	}
	return;
}



static int	FSPAPI onAccepted(FSPHANDLE client, PFSP_Context ctx)
{
	printf_s("\nAccepted: handle of FSP session is %p\n", client);

	PFSAData pdFSA = (PFSAData)malloc(sizeof(AssociatedData));
	if(pdFSA == NULL)
	{
		printf_s("Fatal! No enough memory.\n");
		return -1;
	}
	FSPControl(client, FSP_SET_EXT_POINTER, (ulong_ptr)pdFSA);

	pdFSA->firstOffset = pdFSA->lastOffset = 0;
	InitCHAKAServer(pdFSA->chakaPubInfo, longTermPublicKey);
	ReadFrom(client, pdFSA->chakaPubInfo.peerPublicKey, CRYPTO_NACL_KEYBYTES, onPublicKeyReceived);
	return 0;
}



static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		printf_s("Previous ReadFrom@ServiceSAWS_onAccepted asynchronously return %d.\n", r);
		FreeExtent(h, true);
		return;
	}

	PFSAData pdFSA = (PFSAData)GetExtPointer(h);
	ReadFrom(h, & pdFSA->chakaPubInfo.clientNonce, sizeof(timestamp_t), NULL);
	octet buf[_MAX_PATH];
	int nBytes = ReadFrom(h, buf, sizeof(buf), NULL);

	// assert(nBytes <= sizeof(sessionClientIdString));
	CryptoNaClGetSharedSecret(pdFSA->bufSharedKey, pdFSA->chakaPubInfo.peerPublicKey, bufASLRPrivateKey);
	ChakaStreamcrypt(pdFSA->sessionClientIdString, buf, nBytes, pdFSA->chakaPubInfo.clientNonce, pdFSA->bufSharedKey);

	// TODO: check connection context further
	if (!HasReadEoT(h))
	{
		printf_s("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
		FreeExtent(h, true);
		return;
	}

	// TODO: map the client's id to its salt and password hash value
	MakeSaltedPassword(pdFSA->passwordHash, sampleSalt, samplePassword);
	memcpy(pdFSA->chakaPubInfo.salt, sampleSalt, sizeof(sampleSalt));

	octet serverResponse[CRYPTO_NACL_HASHBYTES];
	if(! CHAKAChallengeByServer(pdFSA->chakaPubInfo, serverResponse, pdFSA->passwordHash))
	{
		FreeExtent(h, true);
		return;
	}

	int n = sizeof(pdFSA->chakaPubInfo.salt)
		+ sizeof(pdFSA->chakaPubInfo.serverNonce) + sizeof(pdFSA->chakaPubInfo.serverRandom);
	WriteTo(h, pdFSA->chakaPubInfo.salt, n, 0, NULL);
	WriteTo(h, serverResponse, sizeof(serverResponse), TO_END_TRANSACTION, onServerResponseSent);
}




static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	PFSAData pdFSA = (PFSAData)GetExtPointer(h);
	ReadFrom(h, pdFSA->chakaPubInfo.peerResponse, CRYPTO_NACL_HASHBYTES, NULL);
	if(! CHAKAValidateByServer(pdFSA->chakaPubInfo, pdFSA->passwordHash))
	{
		FreeExtent(h, true);
		return;
	}
	memset(pdFSA->passwordHash, 0, CRYPTO_NACL_HASHBYTES);	// clear memory trace for better security assurance

	InstallMasterKey(h, pdFSA->bufSharedKey, CRYPTO_NACL_KEYBYTES);
	memset(pdFSA->bufSharedKey, 0, CRYPTO_NACL_KEYBYTES);
	// Unlike the client side, private key of the server side is semi-static for sake of performance
	printf_s("Remote tunnel client authorized. The negotiated shared key installed.\n");

	ReadFrom(h, pdFSA->buf, BUFFER_POOL_SIZE, onFirstLineRead);
}



// Service the HTTP request, after authentication and get first request line.
// Given
//	FSPHANLDE	the handle of the connection to the client
// Do
//	Process the request
static void FSPAPI onFirstLineRead(FSPHANDLE client, FSP_ServiceCode c, int r)
{
	if (r < 0)
	{
		FreeExtent(client, true);
		return;
	}
	printf_s("First request line ready for %p\n", client);

	LineBuffer *lineBuf = (LineBuffer *)GetExtPointer(client);
	lineBuf->lastOffset += r;

	char buf[1024];
	char method[255];
	char url[255];
	char path[512];
	int i, j;
	struct stat st;
	int fcgi = 0;	// whether to pass the content via fast-cgi
	int tunnel = 0;
	char *query_string = NULL;

	int numchars = ReadLine(client, buf, sizeof(buf) - 1);
	if (numchars < 0)
	{
		printf_s("Cannot ReadLine in MasterService(), error number: %d\n", numchars);
		return;
	}
	for(i = 0, j = 0; j < numchars && !isspace(buf[j]) && (i < sizeof(method) - 1); i++, j++)
	{
		method[i] = buf[j];
	}
	method[i] = '\0';
	buf[numchars] = '\0';
	printf_s("Remote request:\n%s\n", buf);

	if(_strcmpi(method, "TUNNEL") == 0)
	{
		tunnel = 1;
	}
	else if (_strcmpi(method, "POST") == 0)
	{
		fcgi = 1;
	}
	else if (_strcmpi(method, "GET") != 0)
	{
		WriteErrStr(client, ERRSTR_UNIMPLEMENTED);
		return;
	}

	i = 0;
	while (isspace(buf[j]) && (j < sizeof(buf)))
		j++;
	for(; !isspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)); i++, j++)
	{
		url[i] = buf[j];
	}
	url[i] = '\0';

	if(tunnel)
	{
		printf_s("To serve tunnel request target at %s\n", url);
		//
		char *okStr = HTTP_SUCCESS_HEADER;
		WriteTo(client, okStr, strlen(okStr) + 1, TO_END_TRANSACTION, NULL);
		//
		lineBuf->firstOffset = lineBuf->lastOffset = 0;
		ReadFrom(client, lineBuf->buf, BUFFER_POOL_SIZE, onFurtherTunnelRequest);
		return;
	}

	if (_strcmpi(method, "GET") == 0)
	{
		query_string = url;
		while ((*query_string != '?') && (*query_string != '\0'))
			query_string++;

		if (*query_string == '?')
		{
			fcgi = 1;
			*query_string = '\0';
			query_string++;
		}
	}

	sprintf_s(path, sizeof(path), "%s%s", DEFAULT_ROOT, url);
	if (path[strlen(path) - 1] == '/')
		strcat_s(path, sizeof(path), DEFAULT_FILE);

	if (stat(path, &st) == -1)
	{
		while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
			numchars = ReadLine(client, buf, sizeof(buf));
		WriteErrStr(client, ERRSTR_NOT_FOUND);
	}
	else
	{
		if ((st.st_mode & S_IFMT) == S_IFDIR)
		{
			strcat_s(path, sizeof(path), "/");
			strcat_s(path, sizeof(path), DEFAULT_FILE);
		}
		//
		// TODO: built-in PHP fast-cgi support
		//
		if (!fcgi)
			SendRegFile(client, path);
		else
			execute_cgi(client, path, method, query_string);
	}

	FreeExtent(client);
	Shutdown(client);
}



// Print out an error message with perror() (for system errors; based
// on value of errno, which indicates system call errors) and exit the
// program indicating an error.
void Abort(const char *sc)
{
	perror(sc);
	exit(-1);
}



// Returns the number of bytes stored, excluding terminating zero
// double buffering
int ReadLine(FSPHANDLE h, char *buf, int size)
{
	LineBuffer *lineBuf = (LineBuffer *)GetExtPointer(h);
	if (lineBuf == NULL)
		return -EFAULT;

	int i = 0;
	char c = '\0';
	int n;

	while ((i < size - 1) && (c != '\n'))
	{
		if(lineBuf->firstOffset >= lineBuf->lastOffset)
		{
			if(lineBuf->lastOffset >= BUFFER_POOL_SIZE)
				lineBuf->firstOffset = lineBuf->lastOffset = 0;
			//
			n = ReadFrom(h, lineBuf->buf + lineBuf->lastOffset, BUFFER_POOL_SIZE - lineBuf->lastOffset, NULL);
			if(n < 0)
				return n;	// UNRESOLVED!? error handling
			// If nothing read, the line buffer could still be processed
			lineBuf->lastOffset += n;
		}
		//
		c = lineBuf->buf[lineBuf->firstOffset++];
		if (c == '\r')
		{
			c = lineBuf->buf[lineBuf->firstOffset];
			if(c == '\n')
				lineBuf->firstOffset++;
			else
				c = '\n';
		}
		buf[i] = c;
		i++;
	}
	buf[i] = '\0';
 
	return(i);
}



// Send a regular file to the client.
// built in rules: .htm, .html: 
// TODO! stat the file, and return the content accordingly
void SendRegFile(FSPHANDLE client, const char *filename)
{
	int numchars = 1;
	int fd;
	int n;

	char *buf = (char *)malloc(BUFFER_POOL_SIZE);
	buf[0] = 'A';
	buf[1] = '\0';
	while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
		numchars = ReadLine(client, buf, BUFFER_POOL_SIZE);

	n = _sopen_s(& fd, filename, _O_BINARY | _O_RDONLY, _SH_DENYWR, _S_IREAD);
	if (n != 0)
	{
		printf_s("_sopen_s('%s'...) return %d\n", filename, n);
		WriteErrStr(client, ERRSTR_NOT_FOUND);
		return;
	}

	const char *headers = HTTP_SUCCESS_HEADER SERVER_STRING
		"Content-Type: text/html\r\n"
		"\r\n";
	WriteTo(client, headers, strlen(headers), 0, NULL);

	// Output the content of the file
	if (buf == NULL)
	{
		printf_s("No memory");	// 500 error!?
		return;
	}

	n = _read(fd, buf, BUFFER_POOL_SIZE);
	while (n > 0)
	{
		WriteTo(client, buf, n, 0, NULL);
		n = _read(fd, buf, BUFFER_POOL_SIZE);
	}
	if (n < 0)
	{
		printf_s("Read error!");	// TODO? print the error number?
		return;
	}
	//
	free(buf);
	Commit(client, NULL);

	_close(fd);
}



static void FSPAPI onFurtherTunnelRequest(FSPHANDLE client, FSP_ServiceCode code, int value)
{
	LineBuffer *lineBuf = (LineBuffer *)GetExtPointer(client);

	printf_s("To further server tunnel request target at %s\n", lineBuf->buf);
	lineBuf->lastOffset += value;

	// TODO: parsing the line buffer, process further tunnel requests!
	ReadFrom(client, lineBuf->buf, BUFFER_POOL_SIZE, onFurtherTunnelRequest);
}



/**
  Future extensions:
	1.Cache and automatically compression (using lz4HC; automatically transport)
	  Use of program names for the identification of
	  encoding formats is not desirable and should be discouraged
	  for future encodings.Their use here is representative of
	  historical practice, not good design.
	2.Automatically utilizing content delivery network (alternate URL)
	  But
	3.Content transfer: application layer SHA256, or precomputed BLAKE2b checksum ?
	  For streamed content

  The DNS server list is built in

  */
 