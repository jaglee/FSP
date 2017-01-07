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

#define MAX_FILENAME_WITH_PATH_LEN	260

#ifndef TEST_MEM_SIZE
# define TEST_MEM_SIZE	0x20000		// 128KB
#endif
//^Other typical choices: //	0x200 // 512B, only one block	// 0x200000 // 2MB		// 0x2000000 // 32MB

extern const char		*defaultWelcome;

extern volatile bool	toMultiply;
extern volatile bool	finished;
extern FSPHANDLE		hFspListen;
extern char				linebuf[80];
extern size_t			sizeOfBuffer;

// Branch controllers
extern void StartToSendSignature(FSPHANDLE h);
extern void SendMemoryPattern();
extern void SendMemoryPatternEncyrpted();

// Shared call-backs
extern void FSPAPI WaitConnection(const char *, unsigned short, CallbackConnected);
extern int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
extern void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onResponseReceived(FSPHANDLE, FSP_ServiceCode, int);

// Per-file modules
static int	FSPAPI onAccepted(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void *, int32_t);
