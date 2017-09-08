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
#include "lz4.h"

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

// prepare pre-defined macros before including FSP_API.h
// effectively avoid double-definition of API by customization
typedef CSocketItem * PSocketItem;
#define FSPHANDLE PSocketItem	// the pointer to some entry in the translate look-aside table

#define DllExport extern "C" __declspec(dllexport)
#define DllSpec DllExport

// DllSpec and FSPHANDLE must be defined properly before FSP_API,
// or else the includer is assumed as a caller, not an implementation
#include "../FSP_API.h"

// per-session connection limit. theoretically any connectible socket might be listener
#define MAX_CONNECTION_NUM	16	// 256	// must be some power value of 2


// A internal class of CSocketItemDl, it should be
class CSocketItemDl;
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

	// Application Layer Fiber ID (ALFID) === fiberID
	CSocketItemDl * operator [] (ALFID_T fiberID);
	CSocketItemDl * operator [] (int i) { return pSockets[i]; }

	CSocketDLLTLB();
};



class CSocketItemDl: public CSocketItem
{
	friend class	CSocketDLLTLB;
	friend struct	CommandToLLS;

	friend FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR, PFSP_Context);
	friend FSPHANDLE FSPAPI Accept1(FSPHANDLE);
	friend FSPHANDLE FSPAPI Connect2(const char *, PFSP_Context);
	friend FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, int8_t, NotifyOrReturn);
	friend FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE, PFSP_Context, CallbackBufferReady);

	static	CSocketDLLTLB socketsTLB;
	static	DWORD	idThisProcess;

	SRWLOCK			rtSRWLock;
	HANDLE			timer;
	//
	CSocketItemDl	*next;
	CSocketItemDl	*prev;

	// optional on-the-wire compression/decompression
	// Forward declaration for compression-decompression
	struct SStreamState;
	struct SDecodeState;
	// 
	SStreamState	* pStreamState;
	SDecodeState	* pDecodeState;

	// for sake of incarnating new accepted connection
	FSP_SocketParameter context;

	char			isInCritical;	// to emulate the situation of NMI that free the socket before previous notice processed
	char			inUse;
	char			newTransaction;	// it may simultaneously start a transmit transaction and flush/commit it
	//
	char			initiatingShutdown : 1;
	char			isDisposing : 1;
	char			isFlushing : 1;
	char			lowerLayerRecycled : 1;
	char			peerCommitPending : 1;
	char			peerCommitted : 1;
protected:
	//
	ALIGN(8)		HANDLE theWaitObject;

	// On ACK_FLUSH Callback for FSPAPI COMMIT, and overloaded for SHUT_DOWN
	NotifyOrReturn	fpCommitted;
	// to support full-duplex send and receive does not share the same call back function
	NotifyOrReturn	fpReceived;
	// to support superior RecvInline() over ReadFrom() make CallbackPeeked an independent function
	CallbackPeeked	fpPeeked;
	CallbackBufferReady fpSent;

	LongRunCallback	longRunCallback;

	// For network streaming *Buf is not NULL
	BYTE *			pendingSendBuf;
	BYTE *			waitingRecvBuf;
	// the count of to send or to receive
	int32_t			pendingSendSize;
	int32_t			waitingRecvSize;
	// the count of sent or received
	int32_t			bytesBuffered;
	int32_t			bytesReceived;
	// For sake of scattered I/O and online compression, a block may include multiple message segment 
	int32_t			pendingStreamingSize;
	int32_t			offsetInLastRecvBlock;

	// Pair of functions meant to mimic hardware vector interrupt. It is yet OS-dependent, however
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
			, WT_EXECUTELONGFUNCTION);
	}

	bool LOCALAPI AddOneShotTimer(uint32_t);
	bool CancelTimer();
	void TimeOut();

	void WaitEventToDispatch();
	bool LockAndValidate();

	// in Establish.cpp
	CSocketItemDl *ProcessOneBackLog(BackLogItem *);
	void ProcessBacklogs();
	CSocketItemDl *Accept1();

	CSocketItemDl * PrepareToAccept(BackLogItem &, CommandNewSession &);
	bool LOCALAPI ToWelcomeConnect(BackLogItem &);
	void ToConcludeConnect();
	ControlBlock::PFSP_SocketBuf LOCALAPI SetHeadPacketIfEmpty(FSPOperationCode c);

	// In Multiplex.cpp
	static CSocketItemDl * LOCALAPI CSocketItemDl::ToPrepareMultiply(CSocketItemDl *, PFSP_Context, CommandCloneConnect &);
	FSPHANDLE CompleteMultiply(CommandCloneConnect &);
	bool LOCALAPI ToWelcomeMultiply(BackLogItem &);

	// In Send.cpp
	void ProcessPendingSend();
	int LOCALAPI BufferData(int);

	// In Receive.cpp
	void	ProcessReceiveBuffer();
	int32_t FetchReceived();

	// In IOControl.cpp
	bool AllocStreamState();
	bool AllocDecodeState();
	int	 Compress(void *, int &, const void *, int);
	int	 Decompress(void *, int &, const void *, int);
	bool HasPendingSend();
	bool FlushDecodeState();
	void FreeStreamState() { if(pStreamState != NULL) { free(pStreamState); pStreamState = NULL; } }

public:
	void Disable();
	void DisableAndFree()
	{
		FreeItem(this);
		Disable();
		SetMutexFree();
	}

	int LOCALAPI Initialize(PFSP_Context, char[MAX_NAME_LENGTH]);
	int Recycle(bool reportError = false);

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
	bool TestSetState(FSP_Session_State s0, FSP_Session_State s2)
	{
		return (_InterlockedCompareExchange8((char *) & pControlBlock->state, s2, s0) == s0);
	}
	bool InIllegalState() const { return pControlBlock->state <= 0 || pControlBlock->state > LARGEST_FSP_STATE; }

	uint64_t GetULASignature() const { return context.signatureULA; }
	void SetULASignature(uint64_t value) { context.signatureULA = value; }

	bool HasPeerCommitted() const { return peerCommitted != 0; }

	bool WaitUseMutex();
	void SetMutexFree() { ReleaseSRWLockExclusive(& rtSRWLock); }
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
		objCommand.idProcess = idThisProcess;
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

	int32_t LOCALAPI AcquireSendBuf();
	int32_t LOCALAPI SendInplace(void *, int32_t, bool);

	ControlBlock::PFSP_SocketBuf GetSendBuf() { return pControlBlock->GetSendBuf(); }

	int LOCALAPI PrepareToSend(void *, int32_t, bool);
	int LOCALAPI SendStream(const void *, int, bool, bool);
	bool TestSetSendReturn(PVOID fp1)
	{
		return InterlockedCompareExchangePointer((PVOID *) & fpSent, fp1, NULL) == NULL; 
	}
	int LOCALAPI CheckTransmitaction(bool);
	//
	int LOCALAPI FinalizeSend(int r)
	{
		// Prevent premature FSP_Send	// Just prebuffer.
		if (r < 0 || InState(CONNECT_AFFIRMING) || InState(CHALLENGING) || InState(CLONING))
		{
			SetMutexFree();
			return r;
		}
		//
		SetMutexFree();
		return (Call<FSP_Send>() ? r : -EIO);
	}

	int	LOCALAPI RecvInline(CallbackPeeked);
	int LOCALAPI ReadFrom(void *, int, NotifyOrReturn);
	int LOCALAPI MarkReceiveFinished(int n) { return pControlBlock->MarkReceivedFree(n); }

	bool HasDataToDeliver()  { return int32_t(pControlBlock->recvWindowExpectedSN - pControlBlock->recvWindowFirstSN) > 0; }
	bool HasFreeSendBuffer() { return (pControlBlock->CountSendBuffered() - pControlBlock->sendBufferBlockN < 0); }

	int LOCALAPI Shutdown(NotifyOrReturn);
	int LOCALAPI Commit(NotifyOrReturn);
	int Commit();

	void SetCallbackOnRequest(CallbackRequested fp1) { context.onAccepting = fp1; }
	void SetCallbackOnAccept(CallbackConnected fp1) { context.onAccepted = fp1; }
	void SetLongRunCallback(LongRunCallback fp1) { longRunCallback = fp1; }

	void SetNewTransaction() { isFlushing = 0; newTransaction = 1; }
	void SetEndTransaction() { isFlushing = 1; }

	int SelfNotify(FSP_ServiceCode c);
	void SetCallbackOnError(NotifyOrReturn fp1) { context.onError = fp1; }
	void NotifyError(FSP_ServiceCode c, int e = 0) { if (context.onError != NULL) context.onError(this, c, e); }

	// defined in DllEntry.cpp:
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context, CommandNewSession &);
	static DWORD GetProcessId() { return idThisProcess; }
	static DWORD SaveProcessId() { return (idThisProcess = GetCurrentProcessId()); }
	static void FreeItem(CSocketItemDl * p) { socketsTLB.FreeItem(p); }
};
