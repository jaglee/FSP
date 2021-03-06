// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"

// Forward declaration of an auxilary function
int ReportLastError();

extern int32_t ticksToWait;
extern bool finished;
extern bool r2finish;
extern bool	toAcceptFile;

void		StartAcceptFile(FSPHANDLE);

// dispose/recycle resource
// TODO: further per-process clean-up works here!
static inline void finalize() { r2finish = finished = true; }
