/**
  Usage: <FileSyncServer> [pathname]
  Act as the prototyped file server for the Simple Art-crafted Web Site in the given work path
  If the pathname is a valid normal file, the file is transfered.
  If the pathname is omitted, current work directory is transfered
**/
// If compiled in Debug mode with the '_DEBUG' macro predefined by default, it tests FSP over UDP/IPv4
// If compiled in Release mode, or anyway without the '_DEBUG' macro predefined, it tests FSP over IPv6
#include "stdafx.h"
#include "defs.h"

const char		*defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";

volatile bool	finished = false;

bool			toSendFile = false;
FSPHANDLE		hFspListen;

/**
 * Send a single file
 **/
static TCHAR	fileName[MAX_PATH] = ".";
static int		fd;
static int FSPAPI toSendNextBlock(FSPHANDLE, void*, int32_t);



int _tmain(int argc, TCHAR * argv[])
{
	errno_t	err = 0;

	if(argc != 1 && (argc != 2 || _tcslen(argv[1]) >= MAX_PATH))
	{
		_tprintf_s(_T("Usage: %s [<filename> | <work directory>]\n"), argv[0]);
		return -1;
	}

	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	char *thisWelcome = (char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	memcpy(thisWelcome, defaultWelcome, mLen);

	if (argc >= 2)
		_tcscpy_s(fileName, MAX_PATH, argv[1]);

	err = _tsopen_s(& fd
		, fileName
		, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
		, _SH_DENYWR
		, 0);
	if(err != 0 && err != EACCES)
	{
		_tprintf_s(_T("Error number = %d: cannot open file %s\n"), err, fileName);
		return -2;
	}
	if (err == EACCES && !PrepareServiceSAWS(fileName))
	{
		_tprintf_s(_T("Usage: %s [<filename> | <work directory>]\n"), argv[0]);
		return -3;
	}
	toSendFile = (err == 0);

	ActivateListening(thisWelcome, mLen + CRYPTO_NACL_KEYBYTES);

	while (!r2Finish || !finished)
		Sleep(50);	// yield CPU out for about 1/20 second

	if (hFspListen != NULL)
		Dispose(hFspListen);

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

	StartToSendSignature(h);
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
		printf_s("Internal error: cannot guess whether the file reaches the end?\n");
		Dispose(h);
		return -1;
	}

	printf_s("To send %d bytes to the remote end\n", bytesRead);

	int err = SendInline(h, batchBuffer, bytesRead, r != 0, NULL);
	if (r != 0)
		finished = true;
	return (r ? -1 : err);	// if EOF, tell DLL to terminate send
}



void StartToSendFile(FSPHANDLE h)
{
	printf_s("\tTo send filename to the remote end...\n");
#ifdef _MBCS
	WriteTo(h, fileName, (int)strlen(fileName) + 1, TO_END_TRANSACTION, onFileNameSent);
#else
	octet buffer[sizeof(wchar_t) * MAX_PATH + 4];
	int len = WideStringToUTF8(buffer, sizeof(buffer), fileName);
	WriteTo(h, buffer, len, TO_END_TRANSACTION, onFileNameSent);
#endif
}
