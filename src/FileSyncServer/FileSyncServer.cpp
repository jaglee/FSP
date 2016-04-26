#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>

#include "../FSP_API.h"

#define MAX_FILENAME_WITH_PATH_LEN	260

const char		*defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";

volatile bool	finished = false;
FSPHANDLE		hFspListen;

static char		fileName[MAX_FILENAME_WITH_PATH_LEN];
static int		fd;
static char		linebuf[80];

// assume that address space layout randomization keep the secret hard to find
static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];

static int	FSPAPI onAccepted(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void *, int32_t);

extern int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
extern void SendMemoryPattern();
extern void SendMemoryPatternEncyrpted();
extern void FSPAPI onResponseReceived(FSPHANDLE, FSP_ServiceCode, int);


void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: Fiber ID = %u, service code = %d, return %d\n", (uint32_t)(intptr_t)h, code, value);
	if(value < 0)
	{
		Dispose(h);
		finished = true;
		return;
	}
}



//
void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Fiber ID = %u, session was to shut down.\n", (uint32_t)(intptr_t)h);
	if(code != FSP_NotifyRecycled)
	{
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);
		return;
	}

	Dispose(h);
	finished = true;
	return;
}



//
void FSPAPI onClientClose(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Fiber ID = %u, the client shutdown the session.\n", (uint32_t)(intptr_t)h);
	if(code != FSP_NotifyToFinish)
	{
		printf_s("Should got TO_FINISH, but service code = %d, return %d\n", code, value);
		return;
	}

	Dispose(h);	// should be graceful 'close' socket
	finished = true;
	return;
}



void FSPAPI WaitConnection(const char *thisWelcome, unsigned short mLen, CallbackConnected onAccepted)
{
	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;
	memset(& params, 0, sizeof(params));
	params.beforeAccept = onAccepting;
	params.afterAccept = onAccepted;
	params.onError = onNotice;
	params.onFinish = onClientClose;
	params.welcome = thisWelcome;
	params.len = mLen;
	params.sendSize = MAX_FSP_SHM_SIZE;
	params.recvSize = 0;	// minimal receiving for download server

	//TranslateFSPoverIPv4(& atAddress, 0, 80);	//INADDR_ANY
	atAddress.u.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned 
	atAddress.idHost = 0;
	atAddress.idALF = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 

	hFspListen = ListenAt(& atAddress, & params);

	while(! finished)
		_sleep(1);	// yield CPU out for at least 1ms/one time slice

	//_sleep(300000);	// for debug purpose
	if(hFspListen != NULL)
		Dispose(hFspListen);
}



int main(int argc, char * argv[])
{
	errno_t	err = 0;

	if(argc != 1 && (argc != 2 || strlen(argv[1]) >= MAX_FILENAME_WITH_PATH_LEN))
	{
		printf_s("Usage: %s <filename>\n", argv[0]);
		err = -1;
		goto l_bailout;
	}

	if(argc == 1)
	{
		strcpy_s(fileName, sizeof(fileName), "$memory.^");
		SendMemoryPattern();
		goto l_bailout;
	}
	
	if(_stricmp(argv[1], "$memory.^") == 0)
	{
		strcpy_s(fileName, sizeof(fileName), argv[1]);
		SendMemoryPatternEncyrpted();
		goto l_bailout;
	}

	strcpy_s(fileName, sizeof(fileName), argv[1]);

	err = _sopen_s(& fd
		, fileName
		, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
		, _SH_DENYWR
		, 0);
	if(err != 0)
	{
		printf_s("Error number = %d: cannot open file %s\n", err, fileName);
		printf("\n\nPress Enter to exit...");
		err = -2;
		goto l_bailout;
	}

	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	unsigned char *bufPublicKey = (unsigned char *)thisWelcome + mLen;;
	memcpy(thisWelcome, defaultWelcome, mLen);	//+\000012345678901234567890123456789012
	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);
#ifndef NDEBUG
	printf("Public key generated: 0x");
	for(register int i = 0; i < CRYPTO_NACL_KEYBYTES; i++)
		printf_s("%X ", bufPublicKey[i]);
	printf("\n");
#endif
	WaitConnection(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES, onAccepted);

	if(fd != 0 && fd != -1)
		_close(fd);

l_bailout:
	printf("\n\nPress Enter to exit...");
	getchar();
	return err;
}


// This function is for tracing purpose
int	FSPAPI onAccepting(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept handle of FSP session: 0x%08X\n", h);
	printf_s("Interface: %d, session Id: %u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->u.subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	return 0;	// no opposition
}



static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: Fiber ID = %u\n", (uint32_t)(intptr_t)h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}



static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);
	printf_s("\tTo install the negotiated shared key...\n");
	InstallAuthenticKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX, END_OF_TRANSACTION); 

	printf_s("\tTo send filename to the remote end...\n");
	WriteTo(h, fileName, (int)strlen(fileName) + 1, END_OF_MESSAGE, onFileNameSent);
}



static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	// UNRESOLVED! Flushing WriteTo()?
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");
	//UNRESOLVED! spawn an implicit thread to receive remote feed-back

	// We insisted on sending even if only a small buffer of 1 octet is available
	r = GetSendBuffer(h, 1, toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		finished = true;
		Dispose(h);
		return;
	}

	// And we expected success acknowledgement
	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



static int FSPAPI toSendNextBlock(FSPHANDLE h, void * batchBuffer, int32_t capacity)
{
	if(capacity <= 0)
	{
		finished = true;
		return -1;
	}

	int bytesRead = _read(fd, batchBuffer, capacity);
	if(bytesRead < 0)
	{
		printf_s("Error when read the source file\n");
		finished = true;
		Dispose(h);
		return -1;
	}
	if(bytesRead == 0)
	{
		printf_s("The source file is empty.\n");
		finished = true;
		Dispose(h);
		return -1;
	}

	int r = _eof(fd);	// re-use the formal parameter. again, negative means error
	if(r < 0)
	{
		printf_s("Internal errror: cannot guess whether the file reaches the end?\n");
		finished = true;
		Dispose(h);
		return -1;
	}

	printf_s("To send %d bytes to the remote end\n", bytesRead);

	SendInline(h, batchBuffer, bytesRead, r ? END_OF_MESSAGE : NOT_END_ANYWAY);
	return (r ? -1 : 0);	// if EOF, tell DLL to terminate send
}


// non-static!
void FSPAPI onResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		printf_s("Wait response got error number %d. To abort.\n", r);
l_bailout:
		Dispose(h);
		finished = true;
		return;
	}

	printf_s("Response received: %s. To shutdown.\n", linebuf);
	if(Shutdown(h, onFinished) < 0)
	{
		printf_s("What? Cannot shutdown gracefully!\n");
		goto l_bailout;
	}
}
