/**
  Usage: <FileSyncClient> [remote_fsp_url]    passively accept a file list sent by the FileSyncServer
  Or:  <FileSyncClient> - [remote_fsp_url]    passively accept a file sent by the FileSyncServer
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

// Branch controllers
int	ToAcceptPushedDirectory(char *);
int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);

// A shared global parameter to configure the time to wait the connection multiplication request is sent and acknowledged:
// by default there is no reverse socket and wait for about 30 seconds to wait one. see also main()
int32_t ticksToWait;
bool	finished;
bool	r2finish;	// whether the reverse channel is about to finish.
bool	toAcceptFile = false;

static HANDLE	hFile;
static char	fileName[sizeof(TCHAR) * MAX_PATH + 4];



// Forward declarations
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE, FSP_ServiceCode, int);
static bool FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, bool);


// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	Dispose(h);
	finalize();
	return;
}



// the server would send the filename in the first message. the client should change the name
// in case it is in the same directory of the same machine 
int _tmain(int argc, TCHAR *argv[])
{
	char *urlRemote = REMOTE_APPLAYER_NAME;
	int result = -1;
	if(argc > 3)
	{
l_usage:
		_tprintf_s(_T("Usage: %s [-] [<remote_fsp_url>]\n"), argv[0]);
		goto l_bailout;
	}


#ifdef _MBCS
	if (argc > 1)
	{
		toAcceptFile = (argv[1][0] == '-' && argv[1][1] == 0);
		if (!toAcceptFile && argc == 3)
			goto l_usage;
		if (argc == 3)
			urlRemote = argv[2];
		else if (!toAcceptFile)
			urlRemote = argv[1];
	}
#else
	if(argc > 1)
	{
		_tprintf_s(_T("Presently this program does not accept wide-char parameter.\n");
		goto l_bailout;
	}
#endif
	Sleep(2000);	// wait the server up when debug simultaneously
	result = ToAcceptPushedDirectory(urlRemote);

	if (result < 0)
		printf("Failed to initialize the connection in the very beginning\n");

l_bailout:
	printf("\n\nPress Enter to exit...");
	getchar();
	// handles are automatically closed on exit
	exit(result);
}



void StartAcceptFile(FSPHANDLE h)
{
	FSPControl(h, FSP_SET_CALLBACK_ON_REQUEST, (ULONG_PTR)onMultiplying);
	ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn);
}



// On receive the name of the remote file prepare to accept the content by receive 'inline'
// here 'inline' means ULA shares buffer memory with LLS
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE h, FSP_ServiceCode resultCode, int resultValue)
{
	if(resultCode != FSP_Receive || resultValue < 0)
	{
		printf_s("\nUnknown result code %d returned by FSP LLS, returned = %d\n", resultCode, resultValue);
		Dispose(h);
		finalize();
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
	// if the new filename exceed MAX_PATH, obfuscate the last character
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
				finalize();
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
				finalize();
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
		finalize();
	}
}



// The iteration body that accept continuous segments of the file content one by one
// The 'eot' (End of Transaction) flag is to indicate the end of the file
// A reverse application layer acknowledgement message is written back to the remote end
static bool FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	static DWORD totalWritten;
	if(buf == NULL)
	{
		printf("FSP Internal panic? Receive nothing when calling the CallbackPeeked? Error code = %d\n", len);
		Dispose(h);
		finalize();
		return false;
	}

	printf_s("%d bytes read, to write the buffer directly...\n", len);

	DWORD bytesWritten;
	if(! WriteFile(hFile, buf, len, & bytesWritten, NULL))
	{
		ReportLastError();
		Dispose(h);
		finalize();
		return false;
	}

	totalWritten += bytesWritten;
	printf_s("%d bytes written to local storage, totally %d bytes.\n", bytesWritten, totalWritten);
	if(eot)
	{
		printf_s("All data have been received.\n");
		finished = true;
		return false;
	}

	return true;
}




// A auxiliary function
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
