/**
  Usage: <FileSyncServer> [pathname]
  Act as the prototyped file server for the Simple Artcrafted Web Site in the given work path
  If the pathname is a valid normal file, the file is transfered.
  If the pathname is ommitted, current work directory is transfered
**/
// If compiled in Debug mode with the '_DEBUG' macro predefined by default, it tests FSP over UDP/IPv4
// If compiled in Release mode, or anyway without the '_DEBUG' macro predefined, it tests FSP over IPv6
#include "stdafx.h"
#include "defs.h"

const char		*defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";
unsigned char	bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];

volatile bool	finished = false;
FSPHANDLE		hFspListen;
char			linebuf[80];
// assume that address space layout randomization keep the secret hard to find
unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];
unsigned char * bufPublicKey;

static TCHAR	fileName[MAX_PATH] = ".";
static int		fd;


// The callback function to handle general notification of LLS. Parameters are self-describing.
void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	if(value < 0)
	{
		r2Finish = finished = true;
		return;
	}
}



// The function called back when an FSP connection was released. Parameters are self-describing
static void FSPAPI onFinish(FSPHANDLE h, FSP_ServiceCode code, int)
{
	printf_s("Socket %p, session was to shut down, service code = %d.\n", h, code);
	finished = true;
	return;
}



// The actual top-level control function to accept the requests for new connections
// Given
//	const char *		The welcome message string. The message should only be encoded in multi-byte character set
//	unsigned short		The length of the welcome message string. Should be less than 968 for FSP over IPv6
//	CallbackConnected	The pointer of the callback function which manipulates the new incarnated connection
void FSPAPI WaitConnection(const char *thisWelcome, unsigned short mLen, CallbackConnected onAccepted)
{
	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;
	memset(& params, 0, sizeof(params));
	params.onAccepting = onAccepting;
	params.onAccepted = onAccepted;
	params.onError = onNotice;
	params.welcome = thisWelcome;
	params.len = mLen;
	params.sendSize = MAX_FSP_SHM_SIZE;
	params.recvSize = 0;	// minimal receiving for download server

#ifdef _DEBUG
	TranslateFSPoverIPv4(& atAddress, 0, htobe32(80));	//INADDR_ANY
#else
	atAddress.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned
	atAddress.idHost = 0;
	atAddress.idALF = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 
#endif

	hFspListen = ListenAt(& atAddress, & params);

	while(!r2Finish || !finished)
		Sleep(50);	// yield CPU out for about 1/20 second

	if(hFspListen != NULL)
		Dispose(hFspListen);
}



// It is assumed that text is in Multi-Byte Character Set
// Case 1: for test, send memory pattern without encryption
// Case 2: for test, send memory pattern with encryption, the length might be specified at command line
// Case 3: for test, send content of a given file to the remote end
// Case 4: the file server prototype of the Simple Artcrafted Web Site
int _tmain(int argc, TCHAR * argv[])
{
	errno_t	err = 0;

	if(argc != 1 && (argc != 2 || _tcslen(argv[1]) >= MAX_PATH))
	{
		_tprintf_s(_T("Usage: %s [<filename> [work directory]]\n"), argv[0]);
		return -1;
	}

	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	bufPublicKey = (unsigned char *)thisWelcome + mLen;;
	memcpy(thisWelcome, defaultWelcome, mLen);
	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

	if (argc >= 2)
		_tcscpy_s(fileName, MAX_PATH, argv[1]);

	err = _tsopen_s(& fd
		, fileName
		, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
		, _SH_DENYWR
		, 0);

	if(err == 0)
	{
		WaitConnection(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES, SendOneFile_onAccepted);
	}
	else if(err == EACCES)
	{
		if(! PrepareServiceSAWS(fileName))
			goto l_return;
		WaitConnection(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES, ServiceSAWS_onAccepted);
	}
	else
	{
		_tprintf_s(_T("Error number = %d: cannot open file %s\n"), err, fileName);
	}

l_return:
	if(fd != 0 && fd != -1)
		_close(fd);

	printf("\n\nPress Enter to exit...");
	_getts_s(fileName, MAX_PATH);
	return err;
}



// If the function pointer 'onAccepting' in a FSP_SocketParameter is not set
// the listener MUST accept the connection request in blocking mode
// This function is for tracing purpose
int	FSPAPI onAccepting(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept handle of FSP session: %p\n", h);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	printf_s("Remote address: 0x%X::%X::%X::%X\n"
		, be32toh(*(u_long*)& remoteAddr->subnet)
		, be32toh(*((u_long*)& remoteAddr->subnet + 1))
		, be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	return 0;	// no opposition
}



int FSPAPI SendOneFile_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nFileSyncServer onAccepted: handle of FSP session is %p\n", h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}



static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);

	printf_s("\tTo install the negotiated shared key...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	printf_s("\tTo send filename to the remote end...\n");
#ifdef _MBCS
	WriteTo(h, fileName, (int)strlen(fileName) + 1, TO_END_TRANSACTION, onFileNameSent);
#else
	octet buffer[sizeof(wchar_t) * MAX_PATH + 4];
	int len = WideStringToUTF8(buffer, sizeof(buffer), fileName);
	WriteTo(h, buffer, len, TO_END_TRANSACTION, onFileNameSent);
#endif
}



// We insisted on sending even if only a small buffer of 1 octet is available
// And we expected success acknowledgement
static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	// UNRESOLVED! Flushing WriteTo()?
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");
	//UNRESOLVED! spawn an implicit thread to receive remote feed-back

	r = GetSendBuffer(h, toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		Dispose(h);
		return;
	}

	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



// the iteration body that transfer to the remote end the segments of the file content one by one
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
		Dispose(h);
		return -1;
	}
	if(bytesRead == 0)
	{
		printf_s("The source file is empty.\n");
		Dispose(h);
		return -1;
	}

	int r = _eof(fd);	// re-use the formal parameter. again, negative means error
	if(r < 0)
	{
		printf_s("Internal errror: cannot guess whether the file reaches the end?\n");
		Dispose(h);
		return -1;
	}

	printf_s("To send %d bytes to the remote end\n", bytesRead);

	int err = SendInline(h, batchBuffer, bytesRead, r != 0, NULL);
	return (r ? -1 : err);	// if EOF, tell DLL to terminate send
}



// The shared call back function executed when the upper layer application has acknowledged
void FSPAPI onResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		printf_s("Wait response got error number %d. To abort.\n", r);
l_bailout:
		Dispose(h);
		return;
	}

	printf_s("Response received: %s. To shutdown.\n", linebuf);
	if (Shutdown(h, onFinish) < 0)
	{
		printf_s("What? Cannot shutdown gracefully!\n");
		goto l_bailout;
	}
}
