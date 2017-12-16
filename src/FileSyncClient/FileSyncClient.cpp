/**
  Usage 1, passively accept a file transfered the FileSyncServer <FileSyncClient> 
  Usage 2, check memory pattern of a file transfered and saved <FileSyncClient> $memory.^ 
 **/
#include "stdafx.h"
#include "tchar.h"

// If compiled in Debug mode with the '_DEBUG' macro predefined by default, it tests FSP over UDP/IPv4
// If compiled in Release mode, or anyway without the '_DEBUG' macro predefined, it tests FSP over IPv6
#ifdef _DEBUG
// # define REMOTE_APPLAYER_NAME "192.168.9.125:80"
# define REMOTE_APPLAYER_NAME "localhost:80"
// #define REMOTE_APPLAYER_NAME "lt-x61t:80"
// #define REMOTE_APPLAYER_NAME "lt-at4:80"
// #define REMOTE_APPLAYER_NAME "lt-ux31e:80"
#else
# define REMOTE_APPLAYER_NAME "E000:AAAA::1"
#endif

// the reverse socket, count to finish
extern int32_t ticksToWait;
extern bool r2finish;

// Branch controllers
extern int	CompareMemoryPattern(TCHAR *fileName);
extern int	ToAcceptPushedDirectory(char *);
extern int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);

static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];

static char fileName[sizeof(TCHAR) * MAX_PATH + 4];
static HANDLE hFile;

static bool finished;

// Forward declarations
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeySent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE, FSP_ServiceCode, int);
static bool FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, bool);
static void FSPAPI onAcknowledgeSent(FSPHANDLE, FSP_ServiceCode, int);


// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	r2finish = finished = true;
	return;
}


// A clone of onError. For test of FSPControl FSP_SET_CALLBACK_ON_ERROR
static void FSPAPI onError2(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify2: socket %p, service code = %d, return %d\n", h, code, value);
	r2finish = finished = true;
	return;
}



// the server would send the filename in the first message. the client should change the name
// in case it is in the same directory of the same machine 
int _tmain(int argc, TCHAR *argv[])
{
	int result = -1;
	if(argc > 2)
	{
		_tprintf_s(_T("Usage: %s [. | <filename>]\n"), argv[0]);
		goto l_bailout;
	}
	if(argc == 2 && (argv[1][0] != _T('.') || _tcslen(argv[1]) > 1))
	{
		result = CompareMemoryPattern(argv[1]);
		goto l_bailout;
	}

	Sleep(2000);	// wait the server up when debug simultaneously
	if(argc == 2)	//  && argv[1][0] isString "."
	{
		result = ToAcceptPushedDirectory(REMOTE_APPLAYER_NAME);
		goto l_bailout;
	}

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = onMultiplying;
	parms.onAccepted = onConnected;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.sendSize = 0;	// the underlying service would give the minimum, however
	if(Connect2(REMOTE_APPLAYER_NAME, & parms) == NULL)
	{
		printf("Failed to initialize the connection in the very beginning\n");
		goto l_bailout;
	}

	while(ticksToWait-- > 0 && !(finished && r2finish))
		Sleep(50);	// yield CPU out for about 1/20 second

	if(hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	//
	result = 0;
	//
l_bailout:
	printf("\n\nPress Enter to exit...");
	getchar();
	// Sleep(3000);	// so that the other thread may send RESET successfully
	exit(result);
}



// On connected, send the public key to the remote end. We save the public key
// temporarily on the stack because we're sure that there is at least one
// buffer block available and the public key fits in one buffer block 
static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	unsigned char bufPublicKey[CRYPTO_NACL_KEYBYTES];
	unsigned char bufPeersKey[CRYPTO_NACL_KEYBYTES];
	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];

	printf_s("\nHandle of FSP session: %p", h);
	if(h == NULL)
	{
		printf_s("\n\tConnection failed.\n");
		r2finish = finished = true;
		return -1;
	}

	int mLen = (int)strlen((const char *)ctx->welcome) + 1;
	printf_s("\tWelcome message length: %d\n", ctx->len);
	printf_s("%s\n", (char *)ctx->welcome);
	if(ctx->len <= 0 || mLen >= ctx->len)
	{
		printf_s("Security context is not fulfilled: the peer did not provide the public key.\n");
		printf_s("To read the filename directly...\t");
		if(ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
		{
			r2finish = finished = true;
			return -1;
		}
		return 0;
	}
	memcpy(bufPeersKey, (const char *)ctx->welcome + mLen, CRYPTO_NACL_KEYBYTES);

	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

	FSPControl(h, FSP_SET_CALLBACK_ON_ERROR, (ulong_ptr)onError2);

	printf_s("\nTo send the key material for shared key agreement...\n");
	WriteTo(h, bufPublicKey, CRYPTO_NACL_KEYBYTES, TO_END_TRANSACTION, onPublicKeySent);

	CryptoNaClGetSharedSecret(bufSharedKey, bufPeersKey, bufPrivateKey);

	printf_s("\tTo install the shared key instantly...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);

	return 0;
}



// On acknowledgement that the public key has been sent read the name of the file
// that the remote end is to send and is to be saved by the near end
static void FSPAPI onPublicKeySent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending public key: %d\n", r);
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	printf_s("\nTo read filename...\t");
	if(ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
	{
		Dispose(h);
		return;
	}
}



// On receive the name of the remote file prepare to accept the content by receive 'inline'
// here 'inline' means ULA shares buffer memory with LLS
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE h, FSP_ServiceCode resultCode, int resultValue)
{
	if(resultCode != FSP_NotifyDataReady)
	{
		printf_s("\nUnknown result code %d returned by FSP LLS, returned = %d\n", resultCode, resultValue);
		Dispose(h);
		return;
	}

	TCHAR finalFileName[MAX_PATH];
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
		if(hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
		{
			char linebuf[80];
			printf_s("Overwrite existent file? Y/n: ");
			gets_s(linebuf, sizeof(linebuf));
			int c = toupper(linebuf[0]);
			if(c != 'Y')
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
			if(hFile == INVALID_HANDLE_VALUE)
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
	catch(...)
	{
		Dispose(h);
	}
}



// The iteration body that accept continuous segments of the file content one by one
// The 'eot' (End of Transaction) flag is to indicate the end of the file
// A reverse application layer acknowledgement message is written back to the remote end
static bool FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	if(buf == NULL)
	{
		printf("FSP Internal panic? Receive nothing when calling the CallbackPeeked?\n");
		Dispose(h);
		return false;
	}

	printf_s("%d bytes read, to write the buffer directly...\n", len);

	DWORD bytesWritten;
	if(! WriteFile(hFile, buf, len, & bytesWritten, NULL))
	{
		ReportLastError();
		Dispose(h);
		return false;
	}

	printf_s("%d bytes written to local storage.\n", bytesWritten);
	if(eot)
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
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	// On server side we test asynchronous mode
	if(Shutdown(h, NULL) < 0)
	{
		printf_s("Cannot shutdown gracefully in the final stage.\n");
		Dispose(h);
	}

	finished = true;
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
		(LPTSTR) &lpMsgBuf,
		0,
		NULL )) 
	{
		printf_s("\tError: %s\n", (char *)lpMsgBuf);
		LocalFree( lpMsgBuf );
	}

	return err;
}
