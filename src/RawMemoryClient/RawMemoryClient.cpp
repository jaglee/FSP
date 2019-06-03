/**
  Usage: <RawMemoryClient> [remote_fsp_url]    passively accept a memory file transfered by the remote server
 **/
#include "stdafx.h"
#include "tchar.h"

// If compiled in Debug mode with the '_DEBUG' macro predefined by default, it tests FSP over UDP/IPv4
// If compiled in Release mode, or anyway without the '_DEBUG' macro predefined, it tests FSP over IPv6
#ifdef _DEBUG
# define REMOTE_APPLAYER_NAME "localhost:80"
#else
# define REMOTE_APPLAYER_NAME "E000:AAAA::1"
#endif

int BeginReceiveMemoryPattern(FSPHANDLE, size_t);

int StartConnection(char *);
int CompareMemoryPattern(TCHAR*);

int32_t ticksToWait;

HANDLE	hFinished;
HANDLE	hFile;		// A shared file descriptor

static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];

static char fileName[sizeof(TCHAR) * MAX_PATH + 4];
static TCHAR finalFileName[MAX_PATH];

// The signal that the mainloop is finished
static bool finished;

// Forward declarations
static void FSPAPI onPublicKeySent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE, FSP_ServiceCode, int);
static bool FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, bool);
static void FSPAPI onAcknowledgeSent(FSPHANDLE, FSP_ServiceCode, int);


// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	finished = true;
	if (hFinished != NULL)
		SetEvent(hFinished);
	return;
}


// A clone of onError. For test of FSPControl FSP_SET_CALLBACK_ON_ERROR
static void FSPAPI onError2(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify2: socket %p, service code = %d, return %d\n", h, code, value);
	finished = true;
	return;
}



// the server would send the filename in the first message. the client should change the name
// in case it is in the same directory of the same machine 
int _tmain(int argc, TCHAR* argv[])
{
	int result = -1;
	if (argc > 3 || argc == 3 && (argv[2][0] != _T('.') || _tcslen(argv[2]) > 1))
	{
		_tprintf_s(_T("Usage: %s [<remote_fsp_url> [. ]]\n"), argv[0]);
		goto l_bailout;
	}

#ifdef _MBCS
	char* urlRemote = argc > 1 ? argv[1] : REMOTE_APPLAYER_NAME;
#else
	if (argc > 1)
	{
		_tprintf_s(_T("Presently this program does not accept wide-char parameter.\n");
		goto l_bailout;
	}
	char* urlRemote = REMOTE_APPLAYER_NAME;
#endif
	Sleep(2000);	// wait the server up when debug simultaneously

	result = StartConnection(urlRemote);
	if (result < 0)
		printf("Failed to initialize the connection in the very beginning\n");

l_bailout:
	printf("\n\nPress Enter to exit...");
	getchar();
	// handles are automatically closed on exit
	exit(result);
}



// On this client side we test blocking mode while on server side we test asynchronous mode
int StartConnection(char* urlRemote)
{
	static size_t	arrayTestSizes[] = { 511
		//, 512
		//, 513
		//, 1024
		//, 1536
		//, 2048
		//, 2560
		//, 3072
		//, 3584
		//, 4095
		//, 4096
		//, 4097
		//, 1000000	// 1MB
		, 10000000	// 10MB
		, 100000000	// 100MB
		, 1000000000// 1GB
	};
	static int		indexOfSizeArray;	// start from zero

	hFinished = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (hFinished == NULL)
		return -ENOMEM;	// no resource, actually

	FSP_SocketParameter parms;
	memset(&parms, 0, sizeof(parms));
	// parms.onAccepting = NULL;
	// parms.onAccepted = NULL;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE;
	parms.sendSize = 0;	// the underlying service would give the minimum, however

l_nextSize:
	// by default there is no reverse socket and wait for about 30 seconds to wait one.
#ifndef NDEBUG
	ticksToWait = 6000;
#else
	ticksToWait = 600;
#endif
	finished = false;

	FSPHANDLE h = Connect2(urlRemote, &parms);
	if (h == NULL)
		return -1;

	int32_t count;
	bool	flag;
	char* msg = (char*)TryRecvInline(h, &count, &flag);
	if (msg == NULL)
	{
		Dispose(h);
		return -1;
	}

	int32_t mLen = 0;
	if (count > 0)
	{
		mLen = (int32_t)strlen(msg);
		printf_s("%s\n", msg);
	}
	printf_s("\tWelcome message length: %d\n", mLen);
	mLen++;	// including the terminating zero
	if (count == 0 || mLen >= count)
	{
		printf_s("Security context is not fulfilled: the peer did not provide the public key.\n");
		printf_s("To read the memory pattern directly.\n");
		int r = BeginReceiveMemoryPattern(h, arrayTestSizes[indexOfSizeArray]);
		if (r < 0)
			return r;
		//
		WaitForSingleObject(hFinished, INFINITE);
		//
		HANDLE h = InterlockedExchangePointer((PVOID*)& hFile, NULL);
		if (h != NULL)
			CloseHandle(h);

		if (finished)
			return 0;
		//
		if (++indexOfSizeArray >= sizeof(arrayTestSizes) / sizeof(size_t))
			return 0;
		goto l_nextSize;
	}

	// On connected, send the public key to the remote end. We save the public key
	// temporarily on the stack because we're sure that there is at least one
	// buffer block available and the public key fits in one buffer block
	const octet* bufPeersKey = (const octet*)msg + mLen;
	octet bufPublicKey[CRYPTO_NACL_KEYBYTES];
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];

	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);
	CryptoNaClGetSharedSecret(bufSharedKey, bufPeersKey, bufPrivateKey);

	FSPControl(h, FSP_SET_CALLBACK_ON_ERROR, (ulong_ptr)onError2);
	printf_s("\nTo send the key material for shared key agreement...\n");
	WriteTo(h, bufPublicKey, CRYPTO_NACL_KEYBYTES, TO_END_TRANSACTION, onPublicKeySent);

	printf_s("\tTo install the shared key instantly...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	// Note that WriteTo is called asynchronously
	while (ticksToWait-- > 0 && !finished)
		Sleep(50);	// yield CPU out for about 1/20 second

	return (ticksToWait > 0 ? 0 : -ETIMEDOUT);
}




// On acknowledgement that the public key has been sent read the name of the file
// that the remote end is to send and is to be saved by the near end
static void FSPAPI onPublicKeySent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending public key: %d\n", r);
	if (r < 0)
	{
		Dispose(h);
		return;
	}

	printf_s("\nTo read filename...\t");
	if (ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
	{
		Dispose(h);
		return;
	}
}



// On receive the name of the remote file prepare to accept the content by receive 'inline'
// here 'inline' means ULA shares buffer memory with LLS
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE h, FSP_ServiceCode resultCode, int resultValue)
{
	if (resultCode != FSP_NotifyDataReady)
	{
		printf_s("\nUnknown result code %d returned by FSP LLS, returned = %d\n", resultCode, resultValue);
		Dispose(h);
		return;
	}

#ifdef _MBCS
	UTF8ToLocalMBCS(finalFileName, MAX_PATH, fileName);
#else
	UTF8ToWideChars(finalFileName, MAX_PATH, fileName, strlen(fileName) + 1);
#endif
	// try to create a new file of the same name. if failed on error file already exists, 
	// try to change the filename by append a 'C'[if it does not have suffix].
	// if the new filename exceed MAX_PATH, confuscate the last character
	_tprintf_s(_T("done.\nRemote filename: %s\n"), finalFileName);
	try
	{
		// TODO: exploit to GetDiskFreeSpace to take use of SECTOR size
		// _aligned_malloc
		// the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
		hFile = CreateFile(finalFileName
			, GENERIC_WRITE
			, 0	// shared none
			, NULL
			, CREATE_NEW
			, FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
			, NULL);
		// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
		if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
		{
			char linebuf[80];
			printf_s("Overwrite existent file? Y/n: ");
			gets_s(linebuf, sizeof(linebuf));
			int c = toupper(linebuf[0]);
			if (c != 'Y')
			{
				Dispose(h);
				return;
			}
			//
			hFile = CreateFile(finalFileName
				, GENERIC_WRITE
				, 0	// shared none
				, NULL
				, CREATE_ALWAYS
				, FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
				, NULL);
			// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
			if (hFile == INVALID_HANDLE_VALUE)
			{
				ReportLastError();	// "Cannot create the new file"
				Dispose(h);
				return;
			}
		}
		//
		printf_s("To read content with inline buffering...\n");
		RecvInline(h, onReceiveNextBlock);
	}
	catch (...)
	{
		Dispose(h);
	}
}



// The iteration body that accept continuous segments of the file content one by one
// The 'eot' (End of Transaction) flag is to indicate the end of the file
// A reverse application layer acknowledgement message is written back to the remote end
static bool FSPAPI onReceiveNextBlock(FSPHANDLE h, void* buf, int32_t len, bool eot)
{
	static DWORD totalWritten;
	if (buf == NULL)
	{
		printf("FSP Internal panic? Receive nothing when calling the CallbackPeeked? Error code = %d\n", len);
		Dispose(h);
		return false;
	}

	printf_s("%d bytes read, to write the buffer directly...\n", len);

	DWORD bytesWritten;
	if (!WriteFile(hFile, buf, len, &bytesWritten, NULL))
	{
		ReportLastError();
		Dispose(h);
		return false;
	}

	totalWritten += bytesWritten;
	printf_s("%d bytes written to local storage, totally %d bytes.\n", bytesWritten, totalWritten);
	if (eot)
	{
		printf_s("All data have been received, to acknowledge...\n");
		WriteTo(h, "0000", 4, TO_END_TRANSACTION, onAcknowledgeSent);
		return false;
	}

	return true;
}



// This time it is really shutdown
static void FSPAPI onAcknowledgeSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the acknowledgement: %d\n", r);
	if (r < 0)
	{
		Dispose(h);
		return;
	}

	// On server side we test asynchronous mode
	r = Shutdown(h, NULL);
	if (r < 0)
	{
		printf_s("Cannot shutdown gracefully in the final stage, error#: %d\n", r);
		Dispose(h);
	}

	finished = true;
	CompareMemoryPattern(finalFileName);
}



// A auxilary function
int ReportLastError()
{
	int	err = GetLastError();
	LPVOID lpMsgBuf;

	printf_s("Error code = %d\n", err);
	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)& lpMsgBuf,
		0,
		NULL))
	{
		printf_s("\tError: %s\n", (char*)lpMsgBuf);
		LocalFree(lpMsgBuf);
	}

	return err;
}