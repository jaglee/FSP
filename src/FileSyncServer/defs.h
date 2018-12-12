/**
 * Predefinitions of the callback functions in FileSyncServer.
 * Shared configurational globals are defined here as well
 */
#include <tchar.h>
#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

#ifndef TEST_MEM_SIZE
# define TEST_MEM_SIZE	0x20000		// 128KB
#endif
//^Other typical choices: //	0x200 // 512B, only one block	// 0x200000 // 2MB		// 0x2000000 // 32MB

extern const char		*defaultWelcome;
extern unsigned char	bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];
extern unsigned char	bufPrivateKey[CRYPTO_NACL_KEYBYTES];

extern volatile bool	toMultiply;
extern volatile bool	finished;
extern volatile	bool	r2Finish;

extern FSPHANDLE		hFspListen;
extern char				linebuf[80];

// Branch controllers
extern void StartToSendSignature(FSPHANDLE h);
extern void SendMemoryPattern();

extern int	FSPAPI ServiceSAWS_onAccepted(FSPHANDLE, PFSP_Context);
extern int	FSPAPI SendMemory_onAccepted(FSPHANDLE, PFSP_Context);
extern int	FSPAPI SendOneFile_onAccepted(FSPHANDLE, PFSP_Context);

// Branch auxilary functions
extern bool PrepareMemoryPattern(size_t);
extern bool	PrepareServiceSAWS(LPCTSTR);

// Shared call-backs
extern void FSPAPI WaitConnection(const char *, unsigned short, CallbackConnected);
extern int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
extern void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onResponseReceived(FSPHANDLE, FSP_ServiceCode, int);


// Per-file modules
static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void *, int32_t);
