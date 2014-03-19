/*
 * DLL to service FSP upper layer application
 * the header file to have common system include file included
 * and declare functions scattered across variable source files
 *
    Copyright (c) 2012, Jason Gao
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT,INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
 */

#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <Windows.h>
#include <conio.h>
#include "rsa-gmp.hpp"


// excluded by WIN32_LEAN_AND_MEAN under VS2003??
#if (_MSC_VER < 1400)
// typedef VOID (NTAPI * WAITORTIMERCALLBACKFUNC) (PVOID, BOOLEAN );
typedef WAITORTIMERCALLBACKFUNC WAITORTIMERCALLBACK ;

extern "C"
DECLSPEC_IMPORT
BOOL
WINAPI
RegisterWaitForSingleObject(
  PHANDLE phNewWaitObject,
  HANDLE hObject,
  WAITORTIMERCALLBACK Callback,
  PVOID Context,
  ULONG dwMilliseconds,
  ULONG dwFlags
);

extern "C"
DECLSPEC_IMPORT
BOOL
WINAPI
UnregisterWaitEx(
    HANDLE WaitHandle,
    HANDLE CompletionEvent
    );
#endif


#define printf _cprintf

#include "../FSP.h"
#include "../FSP_Impl.h"
#include "../gcm-aes.h"

// prepare pre-defined macros before including FSP_API.h
// effectively avoid double-definition of API by customization
typedef CSocketItem * PSocketItem;
#define FSPHANDLE PSocketItem	// the pointer to some entry in the translate look-aside table

#define DllExport extern "C" __declspec(dllexport)
#define DllSpec DllExport

// DllSpec and FSPHANDLE must be defined properly before FSP_API,
// or else the includer is assumed as a caller, not an implementation
#include "../FSP_API.h"

// per-session connection limit. thereotically any connectable socket might be listener
#define MAX_CONNECTION_NUM	16	// 256	// must be some power value of 2

class CSocketItemDl: public CSocketItem
{
	RSA_GMP			keyTransferer;
	CSocketItemDl	*next;
	CSocketItemDl	*prev;
	// for sake of incarnating new accepted connection
	FSP_SocketParameter context;
	char			isFlushing;
	char			eomSending;
protected:
	ALIGN(8)		HANDLE theWaitObject;

	// when request of the initiator just received by the responder and it is to accept
	__declspec(property(get = GetOnRequested))	CallbackRequested fpRequested;
	CallbackRequested GetOnRequested() const { return context.beforeAccept; }

	__declspec(property(get = GetOnAccepted))		CallbackConnected fpAccepted;
	CallbackConnected GetOnAccepted() const { return context.afterAccept; }

	// when some exception occured, or the async-send/recv function returned
	__declspec(property(get = GetOnCallback))		NotifyOrReturn	fpCallback;
	NotifyOrReturn GetOnCallback() const { return context.callback; }

	// to support full-duplex send and receive does not share the same call back function
	NotifyOrReturn	fpSent;
	NotifyOrReturn	fpReceive;		// when data were received and it is to notify the upper layer
	// to support surveillance RecvInline() over ReadFrom() make CallbackPeeked an independent function
	CallbackPeeked	fpPeeked;

	bool			inUse;
	volatile char	mutex;	// Utilize _InterlockedCompareExchange8 to manage critical resource

	BYTE * volatile	pendingSendBuf;
	int				pendingSendSize;
	int				bytesBuffered;
	BYTE * volatile waitingRecvBuf;
	int				waitingRecvSize;
	int				bytesReceived;

	static VOID NTAPI WaitOrTimeOutCallBack(PVOID param, BOOLEAN isTimeout)
	{
		if(isTimeout)
		{
			TRACE_HERE("isTimeout == TRUE");
			return;
		}
		((CSocketItemDl *)param)->WaitEventToDispatch();
	}

	BOOL RegisterDrivingEvent()
	{
		return RegisterWaitForSingleObject(& theWaitObject
			, hEvent
			, WaitOrTimeOutCallBack
			, this
			, INFINITE
			, 0);
	}

	void WaitEventToDispatch();
	FSP_ServiceCode PopNotice() { return pControlBlock->PopNotice(); }

	// in Establish.cpp
	int LOCALAPI CopyKey(ALT_ID_T);
	void InitiateConnect();
	void ProcessBacklog();
	CSocketItemDl * LOCALAPI PrepareToAccept(BackLogItem &, CommandNewSession &);
	bool LOCALAPI ToWelcomeConnect(BackLogItem &);
	bool LOCALAPI ToWelcomeMultiply(BackLogItem &);
	//
	void OnGetFinish();
	void OnGetReset();
	//
	void ProcessPendingSend();
	void ProcessReceiveBuffer();
	//
	void ToConcludeAccept();
	void ToConcludeAdjourn();
	void ToConcludeConnect();
	//
	void HitResumableDisconnectedSessionCache();

	int LOCALAPI BufferData(int);
	int LOCALAPI DeliverData(void *, int);
	int FetchReceived();
	void FinalizeRead();

	friend struct CommandToLLS;
	friend class CSocketDLLTLB;

	friend FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR, PFSP_Context);
	friend FSPHANDLE FSPAPI Connect2(const char *, PFSP_Context);
	friend FSPHANDLE FSPAPI ConnectMU(FSPHANDLE, PFSP_Context);

public:
	enum FlushingFlag
	{
		NOT_FLUSHING = 0,
		ONLY_FLUSHING = 1,
		FLUSHING_SHUTDOWN = 2
	};

	CSocketItemDl() { }	// and lazily initialized
	~CSocketItemDl()
	{
		if(theWaitObject != NULL)
		// waits for all callback functions to complete before returning
		{
			UnregisterWaitEx(theWaitObject, INVALID_HANDLE_VALUE);
			theWaitObject = NULL;
		}
	}
	int LOCALAPI Initialize(PFSP_Context, char *);
	int Recycle();

	// Convert the relative address in the control block to the address in process space, unchecked
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		return pControlBlock->GetSendPtr(skb);
	}
	BYTE * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		return pControlBlock->GetRecvPtr(skb);
	}


	bool StateEqual(FSP_Session_State s) const { return pControlBlock->state == s; }
	void SetState(FSP_Session_State s) { pControlBlock->state = s; }
	// For _MSC_ only, as long is considered compatible with enum
	bool TestSetState(FSP_Session_State s0, FSP_Session_State s2)
	{
		return (_InterlockedCompareExchange((long *)& pControlBlock->state, s2, s0) == s0);
	}
	FSP_Session_State CompareSetState(FSP_Session_State s0, FSP_Session_State s2)
	{
		return (FSP_Session_State)_InterlockedCompareExchange((long *)& pControlBlock->state, s2, s0);
	}

	void SetMutexFree() { mutex = SHARED_FREE; }
	bool TestSetMutexBusy() 
	{
		return (_InterlockedCompareExchange8(& mutex, SHARED_BUSY, SHARED_FREE) == SHARED_FREE);
	}
	bool WaitSetMutex();
	bool IsInUse() const { return inUse; }

	void LOCALAPI InstallBootKey(const BYTE key[], size_t len) { keyTransferer.ImportPublicKey(key, len); }
	void LOCALAPI InstallSessionKey(BYTE sessionKey[])
	{
#ifndef NDEBUG
		pControlBlock->_mac_ctx_protect_prolog[0]
			= pControlBlock->_mac_ctx_protect_prolog[1]
			= pControlBlock->_mac_ctx_protect_epilog[0]
			= pControlBlock->_mac_ctx_protect_epilog[1]
			= MAC_CTX_PROTECT_SIGN;
#endif
		vmac_set_key(sessionKey, & pControlBlock->mac_ctx); 
	}
	void LOCALAPI InstallSessionKey(const BYTE * encrypted, int len)
	{
		keyTransferer.Decrypt(encrypted, len, pControlBlock->u.sessionKey);
#ifndef NDEBUG
		pControlBlock->_mac_ctx_protect_prolog[0]
			= pControlBlock->_mac_ctx_protect_prolog[1]
			= pControlBlock->_mac_ctx_protect_epilog[0]
			= pControlBlock->_mac_ctx_protect_epilog[1]
			= MAC_CTX_PROTECT_SIGN;
#endif
		vmac_set_key(pControlBlock->u.sessionKey, &pControlBlock->mac_ctx);
	}

	void SetPeerName(const char *cName, size_t len)
	{
		size_t n = min(len, sizeof(pControlBlock->peerAddr.name));
		memcpy(pControlBlock->peerAddr.name, cName, n);	// assume memory space has been zeroed
	}

	template<FSP_ServiceCode cmd> void InitCommand(CommandToLLS & objCommand)
	{
		objCommand.idSession = pairSessionID.source;
		objCommand.idProcess = ::idThisProcess;
		objCommand.opCode = cmd;
	}
	bool LOCALAPI Call(const CommandToLLS &, int);
	// TODO: for heavy-load network application, polling is not only more efficient but more responsive as well
	// Signal LLS that the send buffer is not null
	template<FSP_ServiceCode c> bool Call()
	{
		ALIGN(8) CommandToLLS cmd;
		InitCommand<c>(cmd);
		return Call(cmd, sizeof(cmd));
	}
	CSocketItemDl * LOCALAPI CallCreate(CommandNewSession &, FSP_ServiceCode);


	ControlBlock::PFSP_SocketBuf GetSendBuf() { return pControlBlock->GetSendBuf(); }
	ControlBlock::PFSP_SocketBuf PeekNextToSend() const { return pControlBlock->GetNextToSend(); }
	//
	int LOCALAPI AcquireSendBuf(void * &, int);
	int LOCALAPI PrepareToSend(void *, int, bool);
	int LOCALAPI SendStream(void *, int, char);
	bool TestSetSendReturn(NotifyOrReturn fp1) 
	{
		return InterlockedCompareExchangePointer((PVOID *) & fpSent, fp1, NULL) == NULL; 
	}
	NotifyOrReturn GetResetSendReturn()
	{
		return (NotifyOrReturn)InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);
	}


	int	LOCALAPI RecvInline(PVOID);
	int LOCALAPI ReadFrom(void *, int, PVOID);
	bool IsEndOfRecvMsg() const { return context.u.st.eom; }
	void SetEndOfRecvMsg(bool value = true) { context.u.st.eom = value ? 1 : 0; }
	bool IsRecvBufferEmpty()  { return pControlBlock->recvWindowFirstSN == pControlBlock->receiveMaxExpected; }

	int	Adjourn();
	char GetResetFlushing() { return _InterlockedExchange8(& isFlushing, 0);}
	void SetFlushing(char value = ONLY_FLUSHING) { isFlushing = value; }
	void RevertToResume() { isFlushing = 0; SetState(RESUMING); }

	int SelfNotify(FSP_ServiceCode c)
	{
		if(pControlBlock->PushNotice(c) < 0)
		{
			return -EBUSY;
		}
		else
		{
			::SetEvent(hEvent);
			return 0;
		}
	}
	void NotifyError(FSP_ServiceCode c, int e) { if(fpCallback != NULL) fpCallback(this, c, e); }

	// defined in DllEntry.cpp:
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context, CommandNewSession &);
};



class CSocketDLLTLB
{
	(CSocketItemDl *)pSockets[MAX_CONNECTION_NUM];
	CSocketItemDl *header;
	int sizeOfSet;
public:
	CSocketItemDl * AllocItem();
	void FreeItem(CSocketItemDl *r);
	void Compress();

	int Count() { return sizeOfSet; }
	// Application Layer Thread ID (ALT_ID) === sessionID
	CSocketItemDl * operator [] (ALT_ID_T sessionID);
	CSocketItemDl * operator [] (int i) { return pSockets[i]; }

	CSocketDLLTLB()
	{
		header = NULL;
		sizeOfSet = 0;
	}

	//~CSocketDLLTLB()
	//{
	//	CSocketItemDl *r = header;
	//	while(r != NULL)
	//	{
	//		header = r->next;
	//		delete r;
	//		r = header;
	//	}
	//}
};


// defined in DllEntry.cpp for shared across module files
extern int __lastFSPError;
extern HANDLE _mdService;
extern DWORD idThisProcess;

extern CSocketDLLTLB socketsTLB;
