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
	friend class	CSocketDLLTLB;
	friend struct	CommandToLLS;

	friend FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR, PFSP_Context);
	friend FSPHANDLE FSPAPI Connect2(const char *, PFSP_Context);
	friend FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, int8_t, NotifyOrReturn);
	friend FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE, PFSP_Context, int *, CallbackBufferReady);

	SRWLOCK			rtSRWLock;
	HANDLE			timer;
	//
	CSocketItemDl	*next;
	CSocketItemDl	*prev;
	// for sake of incarnating new accepted connection
	FSP_SocketParameter context;
	char			newTransaction;	// it may simultaneously start a transmit transaction and flush/commit it
	char			isFlushing;
	char			inUse;
	char			initiatingShutdown : 1;
	char			lowerLayerRecycled : 1;
	char			shouldChainTimeout : 1;
	char			endOfPeerMessage : 1;
	char			$reserved : 2;
	char			recvCompressed: 1;
	char			sendCompressing: 1;
protected:
	ALIGN(8)		HANDLE theWaitObject;

	NotifyOrReturn	fpRecycled;	// Callback for SHUT_DOWN

	// to support full-duplex send and receive does not share the same call back function
	NotifyOrReturn	fpReceived;
	// to support surveillance RecvInline() over ReadFrom() make CallbackPeeked an independent function
	CallbackPeeked	fpPeeked;
	CallbackBufferReady fpSent;

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
			((CSocketItemDl *)param)->TimeOut();
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

	bool LOCALAPI AddOneShotTimer(uint32_t);
	bool CancelTimer();
	void TimeOut();

	void WaitEventToDispatch();
	bool LockAndValidate();

	// in Establish.cpp
	void ProcessBacklog();

	CSocketItemDl * PrepareToAccept(BackLogItem &, CommandNewSession &);
	bool LOCALAPI ToWelcomeConnect(BackLogItem &);
	void ToConcludeConnect();
	ControlBlock::PFSP_SocketBuf LOCALAPI SetHeadPacketIfEmpty(FSPOperationCode c);

	// In Multiplex.cpp
	static CSocketItemDl * LOCALAPI CSocketItemDl::ToPrepareMultiply(CSocketItemDl *, PFSP_Context, CommandCloneSession &);
	void ToPrepareMultiply()
	{
		SetState(CLONING);
		SetNewTransaction();
	}
	void CompleteMultiply();
	bool LOCALAPI ToWelcomeMultiply(BackLogItem &);

	//
	void ProcessPendingSend();
	void ProcessReceiveBuffer();
	//
	void RespondToRecycle();

	int LOCALAPI BufferData(int);
	int LOCALAPI DeliverData(void *, int);
	int FetchReceived();
	void FinalizeRead();

public:
	CSocketItemDl() { InitializeSRWLock(& rtSRWLock); }	// and lazily initialized
	~CSocketItemDl() { Reinitialize(); }
	void Reinitialize()
	{
		register HANDLE h;
		CancelTimer();
		if((h = InterlockedExchangePointer((PVOID *) & theWaitObject, NULL)) != NULL)
			UnregisterWaitEx(theWaitObject, NULL);
		//^NULL: return immediately; INVALID_HANDLE_VALUE: waits for all callback functions to complete before returning
		//
		CSocketItem::Destroy();
		fpSent = NULL;
		fpPeeked = NULL;
		fpReceived = NULL;
		fpRecycled = NULL;
		InitializeSRWLock(& rtSRWLock); 
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

	FSP_Session_State GetState() const { return pControlBlock->state; }
	bool InState(FSP_Session_State s) const { return pControlBlock->state == s; }
	void SetState(FSP_Session_State s) { _InterlockedExchange8((char *) & pControlBlock->state, s); }
	// For _MSC_ only, as long is considered compatible with enum
	bool TestSetState(FSP_Session_State s0, FSP_Session_State s2)
	{
		return (_InterlockedCompareExchange((long *)& pControlBlock->state, s2, s0) == s0);
	}
	bool InIllegalState() const { return pControlBlock->state <= 0 || pControlBlock->state > LARGEST_FSP_STATE; }

	uint64_t GetULASignature() const { return context.signatureULA; }
	void SetSendCompressing(bool value) { sendCompressing = value ? 1 : 0; }
	bool WaitUseMutex();
#if defined(NDEBUG) || !defined(TRACE)
	void SetMutexFree() { ReleaseSRWLockExclusive(& rtSRWLock); }
#else
	void SetMutexFree();
#endif
	bool IsInUse() { return (_InterlockedXor8(& inUse, 0) != 0); }

	void SetPeerName(const char *cName, size_t len)
	{
		size_t n = min(len, sizeof(pControlBlock->peerAddr.name));
		memcpy(pControlBlock->peerAddr.name, cName, n);	// assume memory space has been zeroed
	}
	int ComparePeerName(const char *cName) { return _strnicmp(pControlBlock->peerAddr.name, cName, sizeof(pControlBlock->peerAddr.name)); }

	template<FSP_ServiceCode cmd> void InitCommand(CommandToLLS & objCommand)
	{
		objCommand.fiberID = fidPair.source;
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

	int LOCALAPI InstallKey(BYTE *, int, int32_t);

	int LOCALAPI AcquireSendBuf(int);
	int LOCALAPI SendInplace(void *, int, int8_t);

	ControlBlock::PFSP_SocketBuf GetSendBuf() { return pControlBlock->GetSendBuf(); }

	int LOCALAPI PrepareToSend(void *, int, bool);
	int LOCALAPI SendStream(void *, int, bool);
	bool TestSetSendReturn(PVOID fp1)
	{
		return InterlockedCompareExchangePointer((PVOID *) & fpSent, fp1, NULL) == NULL; 
	}
	int LOCALAPI CheckTransmitaction(bool);
	//
	int LOCALAPI FinalizeSend(int r)
	{
		SetMutexFree();
		// Prevent premature FSP_Send
		if (r < 0 || InState(CONNECT_AFFIRMING) || InState(CHALLENGING))
			return r;
		if (InState(CLONING))	// Just prebuffer.
			return r;
		//
		return (Call<FSP_Send>() ? r : -EIO);
	}

	int	LOCALAPI RecvInline(PVOID);
	int LOCALAPI ReadFrom(void *, int, PVOID);

	bool IsRecvBufferEmpty()  { return pControlBlock->CountReceived() <= 0; }

	int LOCALAPI Shutdown(NotifyOrReturn);

	void SetCallbackOnRequest(CallbackRequested fp1) { context.onAccepting = fp1; }
	void SetCallbackOnAccept(CallbackConnected fp1) { context.onAccepted = fp1; }

	void SetNewTransaction() { isFlushing = 0; newTransaction = 1; }
	
	int SelfNotify(FSP_ServiceCode c);
	void SetCallbackOnError(NotifyOrReturn fp1) { context.onError = fp1; }
	void NotifyError(FSP_ServiceCode c, int e = 0) { if (context.onError != NULL) context.onError(this, c, e); }

	// defined in DllEntry.cpp:
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context, CommandNewSession &);
};



class CSocketDLLTLB
{
	SRWLOCK	srwLock;
	int		countAllItems;
	int		sizeOfWorkSet;
	CSocketItemDl * pSockets[MAX_CONNECTION_NUM];
	CSocketItemDl * head;
	CSocketItemDl * tail;
public:
	CSocketItemDl * AllocItem();
	void FreeItem(CSocketItemDl *);
	bool ReuseItem(CSocketItemDl *);

	// Application Layer Fiber ID (ALFID) === fiberID
	CSocketItemDl * operator [] (ALFID_T fiberID);
	CSocketItemDl * operator [] (int i) { return pSockets[i]; }

	CSocketDLLTLB()
	{
		InitializeSRWLock(& srwLock);
		countAllItems = 0;
		sizeOfWorkSet = 0;
		head = tail = NULL;
	}

	~CSocketDLLTLB()
	{
		//
	}
};


// defined in DllEntry.cpp for shared across module files
extern int __lastFSPError;
extern HANDLE _mdService;
extern DWORD idThisProcess;

extern CSocketDLLTLB socketsTLB;
