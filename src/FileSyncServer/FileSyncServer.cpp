#include <stdlib.h>
#include <iostream>
#include <io.h>
#include <errno.h>
#include <fcntl.h>

#include "../FSP_API.h"

#define MAX_FILENAME_WITH_PATH_LEN	260

volatile static bool finished = false;
static FSPHANDLE hFspListen;

static char		fileName[MAX_FILENAME_WITH_PATH_LEN];
static int		fd;


static void FSPAPI onReturn(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify 0x%08X service code = %d, returned %d\n", (uint32_t)(intptr_t)h, code, value);
	if(value < 0)
	{
		Dispose(h);
		finished = true;
		return;
	}
	if(code == FSP_NotifyFinish || code == FSP_NotifyRecycled)
	{
		printf_s("Session was shut down.\n");
		Dispose(h);
		finished = true;
		return;
	}
}



static int	FSPAPI onAccepted(FSPHANDLE h, PFSP_Context);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void *, int32_t);

/**
 *
 *
 */
int main(int argc, char * argv[])
{
	char * defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";
	errno_t	err;

	if(argc != 2 || strlen(argv[1]) >= MAX_FILENAME_WITH_PATH_LEN)
	{
		printf_s("Usage: %s <filename>\n", argv[0]);
		return -1;
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
		return -2;
	}

	//hFile = CreateFile(fileName
	//	, GENERIC_READ
	//	, FILE_SHARE_READ
	//	, NULL
	//	, OPEN_EXISTING
	//	, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN
	//	, NULL);	// the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
	//if(hFile == INVALID_HANDLE_VALUE)
	//{
	//	ReportLastError();
	//	printf_s("Cannot open file %s\n", fileName);
	//	DebugBreak();
	//	return -2;
	//}

	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;
	memset(& params, 0, sizeof(params));
	params.beforeAccept = NULL;
	params.afterAccept = onAccepted;
	params.onError = onReturn;
	params.welcome = defaultWelcome;
	params.len = (unsigned short)strlen(defaultWelcome) + 1;
	params.sendSize = MAX_FSP_SHM_SIZE;
	params.recvSize = 0;	// minimal receiving for download server

	TranslateFSPoverIPv4(& atAddress, 0, 80);	//INADDR_ANY
	// UNRESOLVE! Does PostAdjourn() losted? // TODO: CreateFWRules
	//atAddress.u.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned 
	//atAddress.idHost = 0;
	//atAddress.idALT = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 

	hFspListen = ListenAt(& atAddress, & params);

	while(! finished)
		_sleep(1);	// yield CPU out for at least 1ms/one time slice

	if(fd != 0 && fd != -1)
		_close(fd);

	//_sleep(300000);	// for debug purpose
	if(hFspListen != NULL)
		Dispose(hFspListen);

	getchar();
	return 0;
}



static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: 0x%08X\n", h);
	printf_s("\tTo send filename to the remote end...\n");
	// TODO: check connection context
	WriteTo(h, fileName, (int)strlen(fileName) + 1, END_OF_MESSAGE, onFileNameSent);
	return 0;
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
		"to get send buffer for reading and sending inline...\n");
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

	SendInline(h, batchBuffer, bytesRead, ! r);
	if(r)
	{
		printf("All content has been sent. To shutdown.\n");
		if(Shutdown(h) != 0)
		{
			Dispose(h);
			finished = true;
		}
		return -1;
	}

	return 0;
}