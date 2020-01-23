// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <tchar.h>

// Forward declaration of an auxilary function
int ReportLastError();

extern HANDLE	hFinished;
extern HANDLE	hFile;
