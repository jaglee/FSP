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

#ifdef WIN32
#include <WinSock2.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"
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

#define DEFAULT_FILE	"index.html"
#define	BUFFER_POOL_SIZE 65536
#define DEFAULT_SOCKS_PORT 1080

struct LineBuffer
{
	int		firstOffset;
	int		lastOffset;
	char	buf[BUFFER_POOL_SIZE];
};

// assume that address space layout randomization keep the secret hard to find
static unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char *  bufPublicKey;

static bool finished;
static char DEFAULT_ROOT[MAX_PATH];


void StartHTTPoverFSP();

int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
int	FSPAPI onAccepted(FSPHANDLE, PFSP_Context);
void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value);
void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value);


void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);

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
	params.onAccepting = onAccepting;
	params.onAccepted = onAccepted;
	params.onError = onNotice;
	params.welcome = thisWelcome;
	params.len = mLen;
	params.sendSize = MAX_FSP_SHM_SIZE;
	params.recvSize = 0;	// minimal receiving for download server

#ifdef _DEBUG
	TranslateFSPoverIPv4(&atAddress, 0, 80);	//INADDR_ANY
#else
	atAddress.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned
	atAddress.idHost = 0;
	atAddress.idALF = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 
#endif

	FSPHANDLE hFspListen = ListenAt(&atAddress, &params);

	while (!finished)
		_sleep(50);

	if (hFspListen != NULL)
		Dispose(hFspListen);

}


// The callback function to handle general notification of LLS. Parameters are self-describing.
void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	if(value < 0)
	{
		FreeExtent(h);
		finished = true;
		return;
	}
}



// The function called back when an FSP connection was released. Parameters are self-describing
void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, session was to shut down.\n", h);
	if(code != FSP_NotifyRecycled)
	{
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);
		return;
	}
	//
	finished = true;
	return;
}



// This function is for tracing purpose
int	FSPAPI onAccepting(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept handle of FSP session: %p\n", h);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	return 0;	// no opposition
}



int	FSPAPI onAccepted(FSPHANDLE client, PFSP_Context ctx)
{
	void *bufPeerPublicKey = malloc(CRYPTO_NACL_KEYBYTES);

	printf_s("\noTiny http 1.0 nAccepted: handle of FSP session is %p\n", client);
	// TODO: check connection context
	FSPControl(client, FSP_SET_SIGNATURE, (ulong_ptr)bufPeerPublicKey);
	ReadFrom(client, bufPeerPublicKey, CRYPTO_NACL_KEYBYTES, onPublicKeyReceived);
	return 0;
}



// Given
//	FSPHANLDE	the handle of the connection to the client
// Do
//	Process the request
void FSPAPI onPublicKeyReceived(FSPHANDLE client, FSP_ServiceCode c, int r)
{
	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	octet *bufPeerPublicKey;

	char buf[1024];
	int numchars;
	char method[255];
	char url[255];
	char path[512];
	size_t i, j;
	struct stat st;
	int fcgi = 0;	// whether to pass the content via fast-cgi
	char *query_string = NULL;

	FSPControl(client, FSP_GET_SIGNATURE, (ulong_ptr) & bufPeerPublicKey);

	if(r < 0)
	{
		FSPControl(client, FSP_SET_SIGNATURE, 0);
		free(bufPeerPublicKey);
		//
		Dispose(client);
		return;
	}

	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);

	printf_s("\tTo install the negotiated shared key...\n");
	InstallSessionKey(client, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX);

	//
	free(bufPeerPublicKey);

	numchars = ReadLine(client, buf, sizeof(buf));
	for(i = 0, j = 0; !isspace(buf[j]) && (i < sizeof(method) - 1); i++, j++)
	{
		method[i] = buf[j];
	}
	method[i] = '\0';

	if (_strcmpi(method, "GET") && _strcmpi(method, "POST"))
	{
		WriteErrStr(client, ERRSTR_UNIMPLEMENTED);
		return;
	}

	if (_strcmpi(method, "POST") == 0)
		fcgi = 1;

	i = 0;
	while (isspace(buf[j]) && (j < sizeof(buf)))
		j++;
	for(; !isspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)); i++, j++)
	{
		url[i] = buf[j];
	}
	url[i] = '\0';

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
	struct LineBuffer *lineBuf;
	int i = 0;
	char c = '\0';
	int n;

	FSPControl(sock, FSP_GET_SIGNATURE, (ulong_ptr) & lineBuf);
	if(lineBuf == NULL)
	{
		lineBuf = (struct LineBuffer *)malloc(sizeof(struct LineBuffer));
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

	while ((i < size - 1) && (c != '\n'))
	{
		if(lineBuf->firstOffset >= lineBuf->lastOffset)
		{
			n = ReadFrom(sock, lineBuf->buf, BUFFER_POOL_SIZE - lineBuf->firstOffset, NULL);
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
 