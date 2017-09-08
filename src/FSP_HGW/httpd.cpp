/*
 * Simple HTTP 1.0 server over FSP version 0
 * Migrated by Jason Gao <jagao@outlook.com>
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
#include "defs.h"

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

struct LineBuffer
{
	int		firstOffset;
	int		lastOffset;
	char	buf[BUFFER_POOL_SIZE];
};

// assume that address space layout randomization keep the secret hard to find
static unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char *  bufPublicKey;

static FSPHANDLE hListener; 
static bool finished;
static char DEFAULT_ROOT[MAX_PATH];

void StartHTTPoverFSP();

static int	FSPAPI onAccepted(FSPHANDLE, PFSP_Context);
static void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value);
static void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value);

static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void MasterService(FSPHANDLE);

static void FSPAPI onFurtherTunnelRequest(FSPHANDLE, FSP_ServiceCode, int);

void	Abort(const char *);

void	ToServeSOCKS(int);

void	execute_cgi(FSPHANDLE, const char *, const char *, const char *);

int		ReadLine(FSPHANDLE, char *, int);
void	SendRegFile(FSPHANDLE, const char *);


inline void WriteErrStr(FSPHANDLE client, const char *buf)
{
	WriteTo(client, buf, strlen(buf) + 1, TO_END_TRANSACTION, NULL);
}


inline void FreeExtent(FSPHANDLE h)
{
	void *p;
	FSPControl(h, FSP_GET_SIGNATURE, (ulong_ptr) & p);
	if(p != NULL)
	{
		free(p);
		FSPControl(h, FSP_SET_SIGNATURE, 0);
	}
}


// [%s] ['-p' <port number>] | ['-d' <local web root>]
// Convention over configuration:
// By default it is a local SOCKS4a server that listen on the default port number 1080
// The port number could be configured on the command line only.
// If the command line specifies the port number, it could only be a local SOCKS4a server
// If the command line specifies the local web root, it is the remote end point of the tunnel
// The DNS server list is built in

int main(int argc, char *argv[])
{
	if(argc <= 1)
	{
		ToServeSOCKS(DEFAULT_SOCKS_PORT);
	}
	else if (strcmp(argv[1], "-p"))
	{
		int port = atoi(argv[2]);
		if (port == 0 || port > USHRT_MAX || argc > 3)
		{
			printf_s("Usage[as a SOCKS server]: %s -p <port number>\n", argv[0]);
			return -1;
		}

		ToServeSOCKS(port);
	}
	else if (strcmp(argv[1], "-d"))
	{
		if (argc > 3)
		{
			printf_s("Usage[as a SOCKS server]: %s -p <port number>\n", argv[0]);
			return -1;
		}
		//
		strcpy_s(DEFAULT_ROOT, sizeof(DEFAULT_ROOT), argv[2]);
		DEFAULT_ROOT[sizeof(DEFAULT_ROOT) - 1] = 0;
		//
		struct stat st;
		if (stat(DEFAULT_ROOT, &st) == -1 || (st.st_mode & S_IFMT) != S_IFDIR)
		{
			printf_s("Either the path is too long or the directory does not exist:\n\t%s\n", argv[2]);
			return -2;
		}
		//
		StartHTTPoverFSP();
	}
	else
	{
		printf_s("Usage: %s [-p <port number> | -d <web root directory>]\n", argv[0]);
		return -2;
	}

	printf("\n\nPress Enter to exit...");
	getchar();
	return(0);
}



void StartHTTPoverFSP()
{
	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;

	unsigned short mLen = (unsigned short)strlen(SERVER_STRING) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	memcpy(thisWelcome, SERVER_STRING, mLen);
	bufPublicKey = (unsigned char *)thisWelcome + mLen;
	mLen += CRYPTO_NACL_KEYBYTES;

	memset(&params, 0, sizeof(params));
	params.onAccepting = NULL;	// make it blocking
	params.onAccepted = onAccepted;
	params.onError = onNotice;
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
static void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, session was to shut down.\n", h);
	if(code != FSP_NotifyRecycled)
	{
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);
		return;
	}
	//
	return;
}


static int	FSPAPI onAccepted(FSPHANDLE client, PFSP_Context ctx)
{
	printf_s("\noTiny http 1.0\nAccepted: handle of FSP session is %p\n", client);

	void *bufPeerPublicKey = malloc(CRYPTO_NACL_KEYBYTES);
	if(bufPeerPublicKey == NULL)
		return -1;

	// TODO: check connection context
	FSPControl(client, FSP_SET_SIGNATURE, (ulong_ptr)bufPeerPublicKey);
	ReadFrom(client, bufPeerPublicKey, CRYPTO_NACL_KEYBYTES, onPublicKeyReceived);
	return 0;
}



// Given
//	FSPHANLDE	the handle of the connection to the client
// Do
//	Process the request
static void FSPAPI onPublicKeyReceived(FSPHANDLE client, FSP_ServiceCode c, int r)
{
	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	octet *bufPeerPublicKey;

	FSPControl(client, FSP_GET_SIGNATURE, (ulong_ptr) & bufPeerPublicKey);
	FSPControl(client, FSP_SET_SIGNATURE, NULL);

	if(r < 0)
	{
		free(bufPeerPublicKey);
		Dispose(client);
		return;
	}

#ifdef TRACE
	printf_s("\tTo install the negotiated shared key...\n");
#endif
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);
	free(bufPeerPublicKey);

	octet prfKey[32];
	sha256_hash(prfKey, bufSharedKey, CRYPTO_NACL_KEYBYTES);
	InstallSessionKey(client, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX);

	MasterService(client);
}



void MasterService(FSPHANDLE client)
{
	char buf[1024];
	char method[255];
	char url[255];
	char path[512];
	size_t i, j;
	struct stat st;
	int fcgi = 0;	// whether to pass the content via fast-cgi
	int tunnel = 0;
	char *query_string = NULL;

	int numchars = ReadLine(client, buf, sizeof(buf));
	for(i = 0, j = 0; !isspace(buf[j]) && (i < sizeof(method) - 1); i++, j++)
	{
		method[i] = buf[j];
	}
	method[i] = '\0';

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
		LineBuffer *lineBuf;
		FSPControl(client, FSP_GET_SIGNATURE, (ulong_ptr) & lineBuf);
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
	Shutdown(client, onFinished);
}



// Print out an error message with perror() (for system errors; based
// on value of errno, which indicates system call errors) and exit the
// program indicating an error.
void Abort(const char *sc)
{
	perror(sc);
	exit(-1);
}



/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
/**********************************************************************/
// 
// 
// Returns: the number of bytes stored (excluding nul)
int ReadLine(FSPHANDLE sock, char *buf, int size)
{
	LineBuffer *lineBuf;
	int i = 0;
	char c = '\0';
	int n;

	FSPControl(sock, FSP_GET_SIGNATURE, (ulong_ptr) & lineBuf);
	if(lineBuf == NULL)
	{
		lineBuf = (LineBuffer *)malloc(sizeof(LineBuffer));
		if(lineBuf == NULL)
		{
			printf_s("No enough memory");
			Dispose(sock);
			return -1;
		}
		//
		lineBuf->firstOffset = lineBuf->lastOffset = 0;
		FSPControl(sock, FSP_SET_SIGNATURE, (ulong_ptr)lineBuf);
	}
	// double buffering
	while ((i < size - 1) && (c != '\n'))
	{
		if(lineBuf->firstOffset >= lineBuf->lastOffset)
		{
			if(lineBuf->lastOffset >= BUFFER_POOL_SIZE)
				lineBuf->firstOffset = lineBuf->lastOffset = 0;
			//
			n = ReadFrom(sock, lineBuf->buf, BUFFER_POOL_SIZE - lineBuf->lastOffset, NULL);
			if(n == 0)
				return i;
			if(n < 0)
				return n;	// UNRESOLVED!? error handling
			lineBuf->lastOffset = n + lineBuf->firstOffset;
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

	const char *headers = "HTTP/1.0 200 OK\r\n"
		SERVER_STRING
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
	LineBuffer *lineBuf;
	FSPControl(client, FSP_GET_SIGNATURE, (ulong_ptr) & lineBuf);
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
*/
 