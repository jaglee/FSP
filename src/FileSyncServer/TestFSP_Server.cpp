// This is the main project file for VC++ application project 
// generated using an Application Wizard.

#include "stdafx.h"

static CRITICAL_SECTION criticalSection;	// garden hFile
static TCHAR fileName[MAX_PATH];
static HANDLE hFile;
volatile static bool finished = false;
static FSPHANDLE hFSP;

int FSPAPI onReturn(FSP_ServiceCode code, int value)
{
	printf("Notify service code = %d, returned %d\n", code, value);
	return 0;
}

int FSPAPI onAccepted(FSPHANDLE h, PIN6_ADDR addrAccept);

int FSPAPI onFileNameSent(FSP_ServiceCode, int);

/**
 *
 *
 */
int _tmain(int argc, TCHAR * argv[])
{
	char * defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";
	IN6_ADDR atAddress;

	if(argc != 2 || _tcslen(argv[1]) >= MAX_PATH)
	{
		_tprintf("Usage: %s <filename>\n", argv[0]);
		return -1;
	}
	_tcscpy(fileName, argv[1]);

	hFile = CreateFile(fileName
		, GENERIC_READ
		, FILE_SHARE_READ
		, NULL
		, OPEN_EXISTING
		, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN
		, NULL);	// the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
	if(hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf("Cannot open file %s\n", fileName);
		return -2;
	}


	memset(& atAddress, 0, sizeof(atAddress));	// address any
	ListenAt(& atAddress
		, onAccepted
		, defaultWelcome, strlen(defaultWelcome)
		, onReturn);

	while(! finished)
		Sleep(1);	// yield CPU out for at least 1ms/one time slice

	EnterCriticalSection(& criticalSection);
	if(hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	LeaveCriticalSection(& criticalSection);

	return 0;
}



int FSPAPI onAccepted(FSPHANDLE h, PIN6_ADDR addrAccept)
{
	printf("\n**** Handle of FSP session: 0x%X ****\nAccepted at ", h);
	for(register int i = 0; i < 15; i++)
	{
		printf("%02X:", addrAccept->u.Byte[i]);
	}
	printf("%02X\n\n", addrAccept->u.Byte[15]);

	hFSP = h;
	SendCopy(h, fileName, sizeof(TCHAR) * _tcslen(fileName), onFileNameSent);
	//
	return 0;
}



int FSPAPI onFileNameSent(FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(hFSP);
		finished = true;
		return 0;
	}

	// TO DO: GetSendBuffer(), SendInline()...
	return 0;
}
