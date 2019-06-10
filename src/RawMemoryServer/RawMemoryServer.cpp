/**
  Usage 1, transfer non-encrypted memory patterns to the remote end on request: <FileSyncServer>
  Usage 2, transfer an encrypted memory pattern to the remot end: <FileSyncServer> $memory.^ [length-of-memory-pattern]
  Usage 3, transfer the name and content of a given file: <FileSyncServer> filename
  Usage 4, act as the prototyped file server for the Simple Artcrafted Web Site in the given work path: <FileSyncServer> pathname 
 **/
// If compiled in Debug mode with the '_DEBUG' macro predefined by default, it tests FSP over UDP/IPv4
// If compiled in Release mode, or anyway without the '_DEBUG' macro predefined, it tests FSP over IPv6
#include "stdafx.h"

const char		*defaultWelcome = "Memory pattern transfer to test purpose, based on Flexible Session Protocol, version 0.1";
unsigned char	bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];

volatile bool	finished = false;
FSPHANDLE		hFspListen;
char			linebuf[80];
// assume that address space layout randomization keep the secret hard to find
unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];
unsigned char * bufPublicKey;


extern int	FSPAPI WeakSecurity_onAccepted(FSPHANDLE, PFSP_Context);
extern int	FSPAPI SendMemory_onAccepted(FSPHANDLE, PFSP_Context);


static char* fileName = "$memory.^";
static uint8_t* bytesToSend;
static size_t	sizeOfBuffer;

static bool PrepareMemoryPattern(size_t);

static int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void*, int32_t);


// The callback function to handle general notification of LLS. Parameters are self-describing.
void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	if(value < 0)
	{
		finished = true;
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

	while(!finished)
		Sleep(50);	// yield CPU out for about 1/20 second

	if(hFspListen != NULL)
		Dispose(hFspListen);
}



// It is assumed that text is in Multi-Byte Character Set
// Case 1: for test, send memory pattern without encryption
// Case 2: for test, send memory pattern with encryption, the length might be specified at command line
int _tmain(int argc, TCHAR * argv[])
{
	errno_t	err = 0;

	if(argc != 1 && argc != 2)
	{
		_tprintf_s(_T("Usage: %s [length-of-memory-pattern to encrypted, >= 4]\n"), argv[0]);
		return -1;
	}

	if(argc == 1)
	{
		WaitConnection(defaultWelcome, (uint16_t)strlen(defaultWelcome) + 1, WeakSecurity_onAccepted);
		goto l_return;
	}
	
	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	bufPublicKey = (unsigned char *)thisWelcome + mLen;;
	memcpy(thisWelcome, defaultWelcome, mLen);
	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

	if(argc == 2)
	{
		size_t sizeOfBuffer = (size_t)_ttoi64(argv[2]);
		if(sizeOfBuffer < 4)
		{
			_tprintf_s(_T("Usage: %s <filename> [length-of-memory-pattern >= 4]\n"), argv[0]);
			err = -1;
			goto l_return;
		}
		//
		if(!PrepareMemoryPattern(sizeOfBuffer))
			goto l_return;
	}
	else if(! PrepareMemoryPattern(FSP_MAX_KEY_SIZE))	// Just send a key
	{
		goto l_return;
	}

	WaitConnection(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES, SendMemory_onAccepted);

l_return:
	printf("\n\nPress Enter to exit...");
	getchar();
	return err;
}



// If the function pointer 'onAccepting' in a FSP_SocketParameter is not set
// the listener MUST accept the connection request in blocking mode
// This function is for tracing purpose
static int	FSPAPI onAccepting(FSPHANDLE h, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	printf_s("\nTo accept handle of FSP session: %p\n", h);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	printf_s("Remote address: 0x%X::%X::%X::%X\n"
		, be32toh(*(u_long*)& remoteAddr->subnet)
		, be32toh(*((u_long*)& remoteAddr->subnet + 1))
		, be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));
	return 0;	// no opposition
}


static bool PrepareMemoryPattern(size_t sz1)
{
	bytesToSend = (uint8_t*)malloc(sizeOfBuffer = sz1);
	if (bytesToSend == NULL)
	{
		printf_s("Cannot allocate memory block size of %zu bytes\n", sizeOfBuffer);
		return false;
	}

	for (register int i = 0; (size_t)i < sizeOfBuffer / sizeof(uint32_t); i++)
	{
		*(uint32_t*)& bytesToSend[i * sizeof(uint32_t)] = htobe32(i);
	}

	return true;
}



int FSPAPI SendMemory_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nEncryptedMemory onAccepted: handle of FSP session %p\n", h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}


// On receive peer's public key establish the shared session key
// and write to the remote end the hard-coded special filename
// for memory pattern this is a 'virtual' filename
static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if (r < 0)
	{
		Dispose(h);
		return;
	}

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeerPublicKey, bufPrivateKey);

	printf_s("\nTo install the negotiated shared key instantly...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	printf_s("\tTo send filename to the remote end...\n");
	// multi-byte character set only:
	WriteTo(h, fileName, (int)strlen(fileName) + 1, TO_END_TRANSACTION, onFileNameSent);
}



// Besides, open another reverse-connection to send the signature
static void FSPAPI onFileNameSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if (r < 0)
	{
		Dispose(h);
		return;
	}

	printf("Filename has been sent to remote end,\n"
		"to get send buffer for reading file and sending inline...\n");

	// We insisted on sending even if only a small buffer of 1 octet is available
	r = GetSendBuffer(h, toSendNextBlock);
	if (r < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", r);
		Dispose(h);
		return;
	}

	printf_s("And we expected success acknowledgement\n");
}



// the iteration body that transfer to the remote end the segments of the memory block one by one
static int FSPAPI toSendNextBlock(FSPHANDLE h, void* batchBuffer, int32_t capacity)
{
	static int offset = 0;
	if (capacity < 0)
	{
		Dispose(h);
		return -ENOMEM;
	}

	int bytesRead = __min((int32_t)sizeOfBuffer - offset, capacity);
	if (bytesRead <= 0)
		return EOF;

	memcpy(batchBuffer, bytesToSend + offset, bytesRead);
	offset += bytesRead;

	// Would wait until acknowledgement is received. Shutdown is called in onResponseReceived
	bool r = (offset >= (int)sizeOfBuffer);
	int n = SendInline(h, batchBuffer, bytesRead, r, NULL);
	if (n < 0)
	{
		printf_s("SendInline return error#%d\n", n);
		Dispose(h);
		return n;
	}
	printf_s("%d bytes sent to the remote end. Totally %d bytes sent.\n", bytesRead, offset);
	if (r)
	{
		printf("All content has been sent. To wait acknowledgement and shutdown.\n");
		return EOF;
	}

	return n;	// non negative meaning no error and continue to process next block
}
