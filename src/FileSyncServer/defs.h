/**
 * Predefinitions of the callback functions in FileSyncServer.
 * Shared configuration globals are defined here as well
 */
#include <tchar.h>
#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

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

extern int	FSPAPI ServiceSAWS_onAccepted(FSPHANDLE, PFSP_Context);
extern int	FSPAPI SendOneFile_onAccepted(FSPHANDLE, PFSP_Context);

// Branch auxiliary functions
extern bool	PrepareServiceSAWS(LPCTSTR);

// Shared call-backs

extern int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
extern void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value);
extern void FSPAPI onResponseReceived(FSPHANDLE, FSP_ServiceCode, int);


// Per-file modules
static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onFileNameSent(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI toSendNextBlock(FSPHANDLE, void *, int32_t);
