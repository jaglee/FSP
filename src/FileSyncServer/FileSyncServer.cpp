#include <stdlib.h>
#include <iostream>
#include <io.h>
#include <errno.h>
#include <fcntl.h>

#include "../FSP_API.h"

#define MAX_FILENAME_WITH_PATH_LEN	260
#define MIN_SEND_SEGMENT_SIZE	4096

volatile static bool finished = false;
static FSPHANDLE hFspListen;

static char		fileName[MAX_FILENAME_WITH_PATH_LEN];
static int		fd;
static void	*	batchBuffer;
static int		capacity;


static void FSPAPI onReturn(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify 0x%08X service code = %d, returned %d\n", h, code, value);
	if(value < 0)
	{
		Dispose(h);
		finished = true;
	}
	else if(code == FSP_NotifyReset || code == FSP_NotifyRecycled)
	{
		finished = true;
	}
}



static void FSPAPI onAccepted(FSPHANDLE h, PFSP_Context, PFSP_IN6_ADDR addrAccept);

static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI toSendNextBlock(FSPHANDLE, FSP_ServiceCode, int);

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
	hFspListen = ListenAt(& atAddress, & params);

	while(! finished)
		_sleep(1);	// yield CPU out for at least 1ms/one time slice

	if(fd != 0 && fd != -1)
		_close(fd);

	//_sleep(300000);	// for debug purpose
	if(hFspListen != NULL)
		Dispose(hFspListen);

	return 0;
}



static void FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx, PFSP_IN6_ADDR addrAccept)
{
	printf_s("\n**** Handle of FSP session: 0x%08X ****\nAccepted at ", h);
	printf_s("%X::%X::%X ::%X ::%X\n"
		, net16tohost(addrAccept->u.st.prefix)
		, net32tohost(addrAccept->u.st.ipv4)
		, net16tohost(addrAccept->u.st.port)
		, net32tohost(addrAccept->idHost)
		, net32tohost(addrAccept->idALT)
		);
	printf_s("\nTo send filename to the remote end...");
	// TODO: check connection context
	WriteTo(h, fileName, (int)strlen(fileName) + 1, onFileNameSent);
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

	printf("Filename has been sent to remote end, to get send buffer for reading and sending inline...\n");
	//UNRESOLVED! spawn an implicit thread to receive remote feed-back

	capacity = GetSendBuffer(h, & batchBuffer, MIN_SEND_SEGMENT_SIZE, toSendNextBlock);
	if(capacity < 0)
	{
		printf_s("Cannot get send buffer onFileNameSent, error code: %d\n", capacity);
		finished = true;
		Dispose(h);
		return;
	}
}



static void FSPAPI toSendNextBlock(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r <= 0)
	{
		finished = true;
		return;
	}
	capacity = r;

	int bytesRead = _read(fd, batchBuffer, capacity);
	if(bytesRead < 0)
	{
		printf_s("Error when read the source file\n");
		finished = true;
		Dispose(h);
		return;
	}
	if(bytesRead == 0)
	{
		printf_s("The source file is empty.\n");
		finished = true;
		Dispose(h);
		return;
	}

	r = _eof(fd);	// re-use the formal parameter. again, negative means error
	if(r < 0)
	{
		printf_s("Internal errror: cannot guess whether the file reaches the end?\n");
		finished = true;
		Dispose(h);
		return;
	}

	printf_s("To send %d bytes to the remote end\n", bytesRead);

	SendInline(h, batchBuffer, bytesRead, ! r);
	if(r)
	{
		printf("All content has been sent. To shutdown.\n");
		Shutdown(h);
		return;
	}

	printf_s("To get free block for further reading and send...\n");

	r = GetSendBuffer(h, & batchBuffer, 1, toSendNextBlock);
	if(r < 0)
	{
		printf_s("Cannot get send buffer toSendNextBlock, error code: %d\n", r);
		finished = true;
		Dispose(h);
		return;
	}
}
