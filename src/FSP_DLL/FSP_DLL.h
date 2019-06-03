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

#include "../FSP_Impl.h"

// prepare predefined macros before including FSP_API.h
// effectively avoid double-definition of API by customization
typedef CSocketItem * PSocketItem;
#define FSPHANDLE PSocketItem	// the pointer to some entry in the translate look-aside table

#define DllExport extern "C" __declspec(dllexport)
#define DllSpec DllExport

// DllSpec and FSPHANDLE must be defined properly before FSP_API
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
	// Return the registered socket pointer mapped to the FSP handle
	static CSocketItemDl * HandleToRegisteredSocket(FSPHANDLE);
};



class CSocketItemDl : public CSocketItem
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

protected:
	// for sake of buffered, streamed I/O
	ControlBlock::PFSP_SocketBuf skbImcompleteToSend;

	char			inUse;
	char			locked;
	char			newTransaction;	// it may simultaneously start a transmit transaction and flush/commit it

	// Flags, in dictionary order
	char			initiatingShutdown : 1;
	char			lowerLayerRecycled : 1;
	char			peerCommitPending : 1;
	char			peerCommitted : 1;	// Only for conventional buffered, streamed read
	char			pendingEoT : 1;		// EoT flag is pending to be added on a packet

	HANDLE			pollingTimer;
	ALIGN(8)		HANDLE theWaitObject;

	// to support full-duplex send and receive does not share the same call back function
	NotifyOrReturn	fpReceived;
	CallbackPeeked	fpPeeked;
	CallbackBufferReady fpSent;
	//
	NotifyOrReturn	fpCommitted;
	NotifyOrReturn	fpFinished;		// NULL if synchronous shutdown, non-NULL if asynchronous

	// For network streaming *Buf is not NULL
	BYTE *			pendingSendBuf;
	BYTE *			waitingRecvBuf;
	// count of octets to send
	int32_t			pendingSendSize;
	// count of octets expected to receive maximumly
	int32_t			waitingRecvSize;
	// count of octets sent
	int32_t			bytesBuffered;
	// count of octets received
	int32_t			bytesReceived;
	// For sake of scattered I/O and online compression, a block may include multiple message segment 
	int32_t			pendingStreamingSize;
	int32_t			offsetInLastRecvBlock;

	int32_t			pendingPeekedBlocks;	// TryRecvInline called, number of the peeked buffers yet to be unlocked

	// Pair of functions meant to mimic hardware vector interrupt. It is yet OS-dependent, however
	static VOID NTAPI WaitOrTimeOutCallBack(PVOID param, BOOLEAN isTimeout)
	{
		if (isTimeout)
			((CSocketItemDl *)param)->TimeOut();
		else
			((CSocketItemDl *)param)->WaitEventToDispatch();
	}

	static VOID NTAPI PollingTimedoutCallBack(PVOID param, BOOLEAN) { ((CSocketItemDl *)param)->PollingTimedout(); }

	BOOL RegisterDrivingEvent()
	{
		return RegisterWaitForSingleObject(&theWaitObject
			, hEvent
			, WaitOrTimeOutCallBack
			, this
			, INFINITE
			, WT_EXECUTELONGFUNCTION);
	}

	bool LOCALAPI AddOneShotTimer(uint32_t);
	bool EnablePolling();
	bool CancelPolling();
	bool CancelTimeout();
	void TimeOut();
	void PollingTimedout();

	void WaitEventToDispatch();
	bool LockAndValidate();

	// in Establish.cpp
	CSocketItemDl *ProcessOneBackLog(BackLogItem *);
	void ProcessBacklogs();
	CSocketItemDl *Accept1();

	CSocketItemDl * PrepareToAccept(BackLogItem &, CommandNewSession &);
	bool LOCALAPI ToWelcomeConnect(BackLogItem &);
	void ToConcludeConnect();
	ControlBlock::PFSP_SocketBuf SetHeadPacketIfEmpty(FSPOperationCode);

	// In Multiplex.cpp
	static CSocketItemDl * LOCALAPI CSocketItemDl::ToPrepareMultiply(FSPHANDLE, PFSP_Context, CommandCloneConnect &);
	FSPHANDLE LOCALAPI WriteOnMultiplied(CommandCloneConnect &, PFSP_Context, int8_t, NotifyOrReturn);
	FSPHANDLE CompleteMultiply(CommandCloneConnect &);
	bool LOCALAPI ToWelcomeMultiply(BackLogItem &);

	// In Send.cpp
	void ProcessPendingSend();
	int LOCALAPI BufferData(int);

	bool HasFreeSendBuffer() { return (pControlBlock->CountSendBuffered() - pControlBlock->sendBufferBlockN < 0); }

	// In Receive.cpp
	void	ProcessReceiveBuffer();
	int32_t FetchReceived();

	// In IOControl.cpp
	bool AllocStreamState();
	bool AllocDecodeState();
	int	 Compress(void *, int &, const void *, int);
	int	 Decompress(void *, int &, const void *, int);
	bool HasInternalBufferedToSend();
	bool HasDataToCommit() { return (pendingSendSize > 0 || HasInternalBufferedToSend()); }
	bool FlushDecodeBuffer();
	void FreeStreamState() { if (pStreamState != NULL) { free(pStreamState); pStreamState = NULL; } }
	bool HasInternalBufferedToDeliver();
	bool HasDataToDeliver() { return (pControlBlock->CountDeliverable() > 0 || HasInternalBufferedToDeliver()); }

public:
	void Disable();
	void DisableAndNotify(FSP_ServiceCode c, int v)
	{
		NotifyOrReturn fp1 = context.onError;
		Disable();
		SetMutexFree();
		socketsTLB.FreeItem(this);
		if (fp1 != NULL)
			fp1(this, c, -v);
	}
	//^The error handler need not and should not do further clean-up work
	void FreeAndDisable()
	{
		socketsTLB.FreeItem(this);
		Disable();
	}

	int LOCALAPI Initialize(PFSP_Context, char[MAX_NAME_LENGTH]);
	int Dispose();
	int RecycLocked();

	// Convert the relative address in the control block to the address in process space, unchecked
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		return pControlBlock->GetSendPtr(skb);
	}
	BYTE * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		return pControlBlock->GetRecvPtr(skb);
	}

	ControlBlock::seq_t GetSendWindowFirstSN() { return (ControlBlock::seq_t)LCKREAD(pControlBlock->sendWindowFirstSN); }

	FSP_Session_State GetState() { return (FSP_Session_State)_InterlockedOr8((char *)& pControlBlock->state, 0); }
	bool InState(FSP_Session_State s) { return GetState() == s; }
	void SetState(FSP_Session_State s) { _InterlockedExchange8((char *)& pControlBlock->state, s); }

	// In ESTABLISHED or PEER_COMMIT state: does not make state transition on send
	// Send and Commit are separate atomic operations
	void MigrateToNewStateOnSend()
	{
		register FSP_Session_State s = pControlBlock->state;
		if (s == COMMITTED)
			SetState(ESTABLISHED);
		else if (s == CLOSABLE)
			SetState(PEER_COMMIT);
	}
	// Make state transition after and only after an EoT packet is to be sent
	void MigrateToNewStateOnCommit()
	{
		register FSP_Session_State s = pControlBlock->state;
		if (s == ESTABLISHED || s == COMMITTED)
			SetState(COMMITTING);
		else if (s == PEER_COMMIT || s == CLOSABLE)
			SetState(COMMITTING2);
		// else just clear the 'EoT is pending' flag
		SetEoTPending(false);
	}

	bool InIllegalState()
	{
		register FSP_Session_State s = (FSP_Session_State)_InterlockedOr8((char *)& pControlBlock->state, 0);
		return (s <= 0 || s > LARGEST_FSP_STATE);
	}

	uint64_t GetExtentOfULA() { return context.extentI64ULA; }
	void SetExtentOfULA(uint64_t value) { context.extentI64ULA = value; }

	bool HasPeerCommitted() { return peerCommitted != 0; }

	bool WaitUseMutex();
	void SetMutexFree() { _InterlockedExchange8(&locked, 0); }
	bool TryMutexLock() { return _InterlockedCompareExchange8(&locked, 1, 0) == 0; }

	bool IsInUse() { return (_InterlockedOr8(&inUse, 0) != 0) && (pControlBlock != NULL); }

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

#ifndef _NO_LLS_CALLABLE
	bool LOCALAPI Call(const CommandToLLS &, int);
#else
	bool Call(const CommandToLLS &, int) { return true; }
#endif

	// TODO: for heavy-load network application, polling is not only more efficient but more responsive as well
	// Signal LLS that the send buffer is not null
	template<FSP_ServiceCode c> bool Call()
	{
		ALIGN(8) CommandToLLS cmd;
		InitCommand<c>(cmd);
		return Call(cmd, sizeof(cmd));
	}
	CSocketItemDl * LOCALAPI CallCreate(CommandNewSession &, FSP_ServiceCode);
	void LOCALAPI RejectRequest(ALFID_T id1, uint32_t rc)
	{
		CommandRejectRequest objCommand(id1, rc);
		objCommand.idProcess = idThisProcess;
		Call(objCommand, sizeof(objCommand));
	}

	int LOCALAPI InstallRawKey(octet *, int32_t, uint64_t);

	void*	TryAcquireSendBuf(int32_t&);
	int32_t AcquireSendBuf();
	int32_t LOCALAPI SendInplace(void *, int32_t, bool);

	ControlBlock::PFSP_SocketBuf GetSendBuf() { return pControlBlock->GetSendBuf(); }

	int32_t LOCALAPI PrepareToSend(void *, int32_t, bool);
	int32_t LOCALAPI SendStream(const void *, int32_t, bool, bool);
	int Flush();

	bool AppendEoTPacket(FSPOperationCode op1)
	{
		ControlBlock::PFSP_SocketBuf p = pControlBlock->GetSendBuf();
		if (p == NULL)
			return false;
		p->opCode = op1;
		p->len = 0;
		p->SetFlag<TransactionEnded>();
		p->ReInitMarkComplete();
		MigrateToNewStateOnCommit();
		return true;
	}
	bool AppendEoTPacket() { return AppendEoTPacket(initiatingShutdown ? RELEASE : NULCOMMIT); }

	bool TestSetOnCommit(PVOID fp1)
	{
		return InterlockedCompareExchangePointer((PVOID *)& fpCommitted, fp1, NULL) == NULL;
	}
	//
	bool TestSetSendReturn(PVOID fp1)
	{
		return InterlockedCompareExchangePointer((PVOID *) & fpSent, fp1, NULL) == NULL; 
	}

	CSocketItemDl * WaitingConnectAck();
	//
	int BlockOnCommit();
	int Commit();
	int LockAndCommit(NotifyOrReturn);

	void* LOCALAPI TryRecvInline(int32_t&, bool&);
	int	LOCALAPI RecvInline(CallbackPeeked);
	int LOCALAPI ReadFrom(void *, int, NotifyOrReturn);
	int TryUnlockPeeked();

	int Shutdown();
	int Shutdown(NotifyOrReturn fp1) { fpFinished = fp1; return Shutdown(); }

	void SetCallbackOnRequest(CallbackRequested fp1) { context.onAccepting = fp1; }
	void SetCallbackOnAccept(CallbackConnected fp1) { context.onAccepted = fp1; }

	void SetNewTransaction() { newTransaction = 1; }
	void SetEoTPending(bool v = true) { pendingEoT = (v ? 1 : 0); }
	bool IsEoTPending() { return pendingEoT != 0; }

	int SelfNotify(FSP_ServiceCode c);
	void SetCallbackOnError(NotifyOrReturn fp1) { context.onError = fp1; }
	void NotifyError(FSP_ServiceCode c, int e = 0) { if (context.onError != NULL) context.onError(this, c, e); }

	// Defined in IOControl.cpp
	int GetProfilingCounts(PSocketProfile);


	// defined in DllEntry.cpp:
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context, CommandNewSession &);
	static DWORD GetProcessId() { return idThisProcess; }
	static DWORD SaveProcessId() { return (idThisProcess = GetCurrentProcessId()); }
};
