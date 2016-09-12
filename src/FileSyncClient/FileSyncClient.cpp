// This is the main project file for VC++ application project 
// generated using an Application Wizard.

#include "stdafx.h"

//#define REMOTE_APPLAYER_NAME "localhost:80"
// #define REMOTE_APPLAYER_NAME "lt-x61t:80"
// #define REMOTE_APPLAYER_NAME "lt-at4:80"
// #define REMOTE_APPLAYER_NAME "lt-ux31e:80"
#define REMOTE_APPLAYER_NAME "E000:AAAA::1"
//#define REMOTE_APPLAYER_NAME "E000:BBBB::1"

static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char bufPublicKey[CRYPTO_NACL_KEYBYTES];

static HANDLE hFile;
static char fileName[MAX_PATH];
static bool finished;
// static bool toFinish;


static void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: Fiber ID = %u, service code = %d, return %d\n", (uint32_t)(intptr_t)h, code, value);
	if(value < 0)
	{
		Dispose(h);
		finished = true;
		return;
	}
}



static void FSPAPI onError2(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify2: fiber ID = %u, service code = %d, return %d\n", (uint32_t)(intptr_t)h, code, value);
	Dispose(h);
	finished = true;
	return;
}



//
static void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Fiber ID = 0x%X, session was to shut down.\n", (uint32_t)(intptr_t)h);
	if(code != FSP_NotifyRecycled)
	{
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);
		return;
	}

	Dispose(h);
	finished = true;
	return;
}



static int ReportLastError()
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
		printf("\tError: %s\n", lpMsgBuf);
		LocalFree( lpMsgBuf );
	}

	return err;
}



// the server would send the filename in the first message. the client should change the name
// in case it is in the same directory of the same machine 
int main(int argc, char *argv[])
{
	int result = 0;
	if(argc == 2)
	{
		result = CompareMemoryPattern(argv[1]);
		goto l_bailout;
	}

	Sleep(2000);	// wait the server up when debug simultaneously

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = onMultiplying;
	parms.onAccepted = onConnected;
	parms.onError = onNotice;
	parms.recvSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.sendSize = 0;	// the underlying service would give the minimum, however
	if(Connect2(REMOTE_APPLAYER_NAME, & parms) == NULL)
	{
		printf("Failed to initialize the connection in the very beginning\n");
		result = -1;
		goto l_bailout;
	}

	while(! finished)
		Sleep(1);	// yield CPU out for at least 1ms/one time slice

	if(hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

l_bailout:
	printf("\n\nPress Enter to exit...");
	getchar(); // Sleep(3000);	// so that the other thread may send RESET successfully
	exit(result);
}



static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: Fiber ID = 0x%X", (uint32_t)(intptr_t)h);
	if(h == NULL)
	{
		printf_s("\nConnection failure.\n");
		finished = true;
		return -1;
	}

	int mLen = strlen((const char *)ctx->welcome) + 1;
	printf_s("\tWelcome message length: %d\n", ctx->len);
	printf_s("%s\n", ctx->welcome);
	if(ctx->len <= 0 || mLen >= ctx->len)
	{
		printf_s("Security context is not fulfilled: the peer did not provide the public key.\n");
		printf_s("To read the filename directly...\t");
		if(ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
		{
			finished = true;
			return -1;
		}
		return 0;
	}

	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);

	unsigned char bufPeersKey[CRYPTO_NACL_KEYBYTES];
	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	memset(bufPeersKey, 0, CRYPTO_NACL_KEYBYTES);
	memcpy(bufPeersKey, (const char *)ctx->welcome + mLen, CRYPTO_NACL_KEYBYTES);

	CryptoNaClGetSharedSecret(bufSharedKey, bufPeersKey, bufPrivateKey);

	FSPControl(h, FSP_SET_CALLBACK_ON_ERROR, (ulong_ptr)onError2);

	printf_s("\nTo send the key material for shared key agreement...\n");
	WriteTo(h, bufPublicKey, CRYPTO_NACL_KEYBYTES, EOF, onPublicKeySent);

	printf_s("\tTo install the shared key instantly...\n");
	InstallAuthenticKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX, FSP_INSTALL_KEY_INSTANTLY);

	return 0;
}



static void FSPAPI onPublicKeySent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending public key: %d\n", r);
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	printf_s("\nTo read filename...\t");
	if(ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}
}



static void FSPAPI onReceiveFileNameReturn(FSPHANDLE h, FSP_ServiceCode resultCode, int resultValue)
{
	if(resultCode != FSP_NotifyDataReady)
	{
		printf("\nUnknown result code %d returned by FSP LLS, returned = %\n", resultCode, resultValue);
		finished = true;
		Dispose(h);
		return;
	}

	// try to create a new file of the same name. if failed on error file already exists, 
	// try to change the filename by append a 'C'[if it does not have suffix].
	// if the new filename exceed MAX_PATH, confuscate the last character
	printf_s("done.\nRemote filename: %s\n", fileName);
	try
	{
 		// TODO: exploit to GetDiskFreeSpace to take use of SECTOR size
		// _aligned_malloc
		// the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
		hFile = CreateFile(fileName
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
				finished = true;
				Dispose(h);
				return;
			}
			//
			hFile = CreateFile(fileName
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
				finished = true;
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
		// TODO...
		finished = true;
		Dispose(h);	// may raise second-chance exceptions?
	}
}



static int FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, bool toBeContinued)
{
	if(buf == NULL)
	{
		printf("FSP Internal panic? Receive nothing when calling the CallbackPeeked?\n");
		finished = true;
		Dispose(h);
		DebugBreak();
		return -1;
	}

	printf_s("%d bytes read, to write the buffer directly...\n", len);

	DWORD bytesWritten;
	if(! WriteFile(hFile, buf, len, & bytesWritten, NULL))
	{
		ReportLastError();
		finished = true;
		Dispose(h);
		DebugBreak();
		return -1;
	}

	printf_s("%d bytes written to local storage.\n", bytesWritten);
	// needn't UnlockPeeked as Shutdown would forcefully close the receive window
	// and return a non-zero would let the occupied receive buffer free
	if(! toBeContinued)
	{
		printf_s("All data have been received, to acknowledge...\n");
		// Respond with a code saying no error
		return WriteTo(h, "0000", 4, EOF, onAcknowledgeSent);
	}

	return 1;
}


// This time it is really shutdown
static void FSPAPI onAcknowledgeSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the acknowledgement: %d\n", r);
	if(r < 0)
	{
		finished = true;
		Dispose(h);
		return;
	}

	if(Shutdown(h, onFinished) < 0)
	{
		printf_s("Cannot shutdown gracefully in the final stage.\n");
		Dispose(h);
		finished = true;
	}
}