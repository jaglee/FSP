/**
 * Predefinitions of the callback functions in FileSyncServer.
 * Shared configuration globals are defined here as well
 */
#include <tchar.h>
#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

extern volatile bool	toMultiply;
extern volatile bool	finished;
extern volatile	bool	r2Finish;

extern bool				toSendFile;
extern FSPHANDLE		hFspListen;


// Branch controllers
extern void ActivateListening(const char*, unsigned short);
extern void StartToSendSignature(FSPHANDLE);
extern void StartToSendFile(FSPHANDLE);

// Branch auxiliary functions
extern bool	PrepareServiceSAWS(LPCTSTR);

// May be exploited to render rate limitation
extern int	FSPAPI onAccepting(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
