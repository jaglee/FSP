/*
 * Simple Artcrafted Web Site
 */
#include "stdafx.h"
#include "defs.h"

# define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, "ERROR REPORT")
# define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, (s1))
void TraceLastError(char * fileName, int lineNo, const char *funcName, const char *s1);


//
// by default return the file 'index.saws' under the given path
//
void PrepareServiceSAWS(const char * pathName)
{
	HANDLE h = CreateFile(pathName
		, GENERIC_READ
		, FILE_SHARE_READ
		, NULL
		, OPEN_EXISTING
		, FILE_FLAG_BACKUP_SEMANTICS  + FILE_FLAG_SEQUENTIAL_SCAN
		, NULL);
	if(h == INVALID_HANDLE_VALUE)
	{
		REPORT_ERRMSG_ON_TRACE(pathName);
		return;
	}
	//
	CloseHandle(h);
	//
	WIN32_FIND_DATA findFileData;
	char pattern[MAX_PATH];
	strcpy_s(pattern, pathName);
	strcat_s(pattern, "\\*");
	h = FindFirstFile(pattern, & findFileData); 
	if(h == INVALID_HANDLE_VALUE)
	{
		printf_s("Directory is empty: %s\n", pathName);
		return;
	}
	// Should filter out "." and ".."
	do
	{
		printf_s("File or directory: %s\n", findFileData.cFileName);
	} while(FindNextFile(h, & findFileData));
	//
	FindClose(h);
}



int FSPAPI ServiceSAWS_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nEncyrptedMemory onAccepted: handle of FSP session %p\n", h);
	// TODO: check connection context

	ReadFrom(h, bufPeerPublicKey, sizeof(bufPeerPublicKey), onPublicKeyReceived);
	return 0;
}



static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	//...
}

// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(char * fileName, int lineNo, const char *funcName, const char *s1)
{
	DWORD err = GetLastError();
	CHAR buffer[ERROR_SIZE];
	printf("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", fileName, lineNo, funcName, s1);

	buffer[0] = 0;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
		, NULL
		, err
		, LANG_USER_DEFAULT
		, (LPTSTR) & buffer
		, ERROR_SIZE
		, NULL);
	if(buffer[0] != 0)
		puts(buffer);
}
