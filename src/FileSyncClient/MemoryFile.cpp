/**
 * Used to be a short module in FileSyncClient, now in FSP_FlowTest
 * which meant to check that the memory pattern saved in the designated file is right
 */
#include "stdafx.h"
#include "tchar.h"

const char * MEMORY_PATTERN_FILE_NAME = "$memory.^";
static DWORD totalWritten;


// The iteration body that accept continuous segments of the file content one by one
// The 'eot' (End of Transaction) flag is to indicate the end of the file
// A reverse application layer acknowledgement message is written back to the remote end
static bool FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
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
		printf_s("All data have been received, to shutdown...\n");
		Shutdown(h, NULL);
		//
		if (hFinished != NULL)
			SetEvent(hFinished);
		//
		return false;
	}

	return true;
}



// Return 0 or positive number if no error occurred
// return negative if it is the error number
int BeginReceiveMemoryPattern(FSPHANDLE h, size_t testSize)
{
	printf("To request %d otets from the remote end\n", (int32_t)testSize);
	hFile = CreateFile(MEMORY_PATTERN_FILE_NAME
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
			return -EPERM;	// end user did not permit
		}
		//
		hFile = CreateFile(MEMORY_PATTERN_FILE_NAME
			, GENERIC_WRITE
			, 0	// shared none
			, NULL
			, CREATE_ALWAYS
			, FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
			, NULL);
		// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
	}
	if (hFile == INVALID_HANDLE_VALUE)
	{
		ReportLastError();	// "Cannot create the new file"
		Dispose(h);
		return -ENODEV;
	}

	totalWritten = 0;
	WriteTo(h, &testSize, sizeof(size_t), TO_END_TRANSACTION, NULL);
	printf_s("To read content with inline buffering...\n");
	return RecvInline(h, onReceiveNextBlock);
}



// Limited to 128KB, word alignment of 4 octets
// "$memory.^";
int CompareMemoryPattern(TCHAR *fileName)
{
	static	uint8_t	buf[0x20000];	// 128KB

	int fd;
	errno_t	err = _tsopen_s(& fd
			, fileName
			, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
			, _SH_DENYWR
			, 0);
	if(err != 0)
	{
		_tprintf_s(_T("Error number = %d: cannot open file %s\n"), err, fileName);
		return -2;
	}

	_tprintf_s(_T("To check word pattern in %s\n"), fileName);

	int bytesRead = _read(fd, buf, sizeof(buf));
	_close(fd);
	if(bytesRead < 0)
		return bytesRead;
	if((bytesRead & (sizeof(uint32_t) - 1)) != 0)
		return -EDOM;

	for(register int i = 0; i < int(bytesRead / sizeof(uint32_t)); i++)
	{
		if(* (uint32_t *) & buf[i * sizeof(uint32_t)] != htobe32(i))
			__debugbreak();
	}

	_tprintf_s(_T("Word pattern in %s was checked.\n"), fileName);

	return 0;
}
