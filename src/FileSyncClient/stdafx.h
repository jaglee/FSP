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

// Branch controllers
extern int CompareMemoryPattern(char	*fileName);

// Shared call-backs
extern int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);

// Per-file modules
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeySent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, bool);

//
static void FSPAPI onAcknowledgeSent(FSPHANDLE, FSP_ServiceCode, int);
