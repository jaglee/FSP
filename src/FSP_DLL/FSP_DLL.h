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

#include "lz4.h"
#include "../FSP_Impl.h"


#if defined(__WINDOWS__)
# include <conio.h>

// excluded by WIN32_LEAN_AND_MEAN under VS2003??
# if (_MSC_VER < 1400)
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
# endif

# define DllExport extern "C" __declspec(dllexport)
# define DllSpec DllExport

#elif defined(__linux__) || defined(__CYGWIN__)
# define DllExport
# define DllSpec DllExport
#endif



// prepare predefined macros before including FSP_API.h
// effectively avoid double-definition of API by customization
typedef CSocketItem * PSocketItem;
#define FSPHANDLE PSocketItem	// the pointer to some entry in the translate look-aside table

// DllSpec and FSPHANDLE must be defined properly before FSP_API
#include "../FSP_API.h"

#define MAX_CONNECTION_NUM	256	// must be some power value of 2


// A internal class of CSocketItemDl, it should be
class CSocketItemDl;
class CSocketDLLTLB: CSRWLock
{
	int		countAllItems;
	int		sizeOfWorkSet;
	CSocketItemDl * pSockets[MAX_CONNECTION_NUM];
	CSocketItemDl * head;
	CSocketItemDl * tail;
	void	Init();
public:
	CSocketItemDl * AllocItem();
	void FreeItem(CSocketItemDl *);

	// Application Layer Fiber ID (ALFID) === fiberID
	CSocketItemDl * operator [] (ALFID_T fiberID);
	CSocketItemDl * operator [] (int i) { return pSockets[i]; }

	CSocketDLLTLB()
	{
		InitMutex();
		Init();
		sizeOfWorkSet = 0;
		head = tail = NULL;
	}

	~CSocketDLLTLB();

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
	friend FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, unsigned, NotifyOrReturn);
	friend FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE, PFSP_Context, CallbackBufferReady);

	friend void UnitTestAllocAndFreeItem();

	static	CSocketDLLTLB socketsTLB;
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

#if defined(__WINDOWS__)
	static	DWORD	idThisProcess;
	ALIGN(8)		HANDLE theWaitObject;
	HANDLE			timer;

	void CopyFatMemPointo(CommandNewSession &cmd)
	{
		cmd.hMemoryMap = (uint64_t)hMemoryMap;
		cmd.dwMemorySize = dwMemorySize;
	}
	void EnableLLSInterrupt() { _bittestandreset(&pControlBlock->notices.vector, 0); }

	static VOID NTAPI WaitOrTimeOutCallBack(PVOID param, BOOLEAN isTimeout)
	{
		if (isTimeout)
			((CSocketItemDl *)param)->TimeOut();
		else
			((CSocketItemDl *)param)->WaitEventToDispatch();
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	static pid_t	idThisProcess;
	timer_t	pollingTimer;
	timer_t			timer;
	static void PollingNotices(union sigval v) { ((CSocketItemDl*)v.sival_ptr)->WaitEventToDispatch(); }
	static void TimeOutCallBack(union sigval v) { ((CSocketItemDl*)v.sival_ptr)->TimeOut(); }

	// See also InitLLSInterface()
	void CopyFatMemPointo(CommandNewSession &cmd)
	{
		cmd.GetShmNameFrom(this);
		cmd.dwMemorySize = dwMemorySize;
	}
	void EnableLLSInterrupt() { pControlBlock->notices.vector &= 0xFFFFFFFE; }
#endif

	// to support full-duplex send and receive does not share the same call back function
	NotifyOrReturn	fpReceived;
	CallbackPeeked	fpPeeked;
	CallbackBufferReady fpSent;
	//
	NotifyOrReturn	fpCommitted;
	NotifyOrReturn	fpFinished;		// NULL if synchronous shutdown, non-NULL if asynchronous

	// For network streaming *Buf is not NULL
	octet *			pendingSendBuf;
	octet *			waitingRecvBuf;
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

	bool LOCALAPI AddOneShotTimer(uint32_t);
	bool CancelTimeout();
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
	ControlBlock::PFSP_SocketBuf SetHeadPacketIfEmpty(FSPOperationCode);

	// In Multiplex.cpp
	static CSocketItemDl * LOCALAPI ToPrepareMultiply(FSPHANDLE, PFSP_Context, CommandCloneConnect &);
	FSPHANDLE LOCALAPI WriteOnMultiplied(CommandCloneConnect &, PFSP_Context, unsigned, NotifyOrReturn);
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
	void Free();
	void FreeAndNotify(FSP_ServiceCode c, int v)
	{
		NotifyOrReturn fp1 = context.onError;
		Free();
		if (fp1 != NULL)
			fp1(this, c, -v);
	}
	//^The error handler need not and should not do further clean-up work

	// TODO: evaluate configurable shared memory block size? // UNRESOLVED!? MTU?
	static int32_t AlignMemorySize(PFSP_Context psp1)
	{
		if (psp1->sendSize < 0 || psp1->recvSize < 0 || psp1->sendSize + psp1->recvSize > MAX_FSP_SHM_SIZE + MIN_RESERVED_BUF)
			return -ENOMEM;
		if (psp1->sendSize < MIN_RESERVED_BUF)
			psp1->sendSize = MIN_RESERVED_BUF;
		if (psp1->recvSize < MIN_RESERVED_BUF)
			psp1->recvSize = MIN_RESERVED_BUF;
		if (psp1->passive)
		{
			return ((sizeof(ControlBlock) + 7) >> 3 << 3)
				+ sizeof(LLSBackLog) + sizeof(BackLogItem) * (FSP_BACKLOG_SIZE - MIN_QUEUED_INTR);
		}
		else
		{
			int n = (psp1->sendSize - 1) / MAX_BLOCK_SIZE + (psp1->recvSize - 1) / MAX_BLOCK_SIZE + 2;
			// See also Init()
			return ((sizeof(ControlBlock) + 7) >> 3 << 3)
				+ n * (((sizeof(ControlBlock::FSP_SocketBuf) + 7) >> 3 << 3) + MAX_BLOCK_SIZE);
		}
	}
	bool InitLLSInterface(CommandNewSession&);
	void SetConnectContext(const PFSP_Context psp1)
	{
		if (psp1->passive)
			pControlBlock->Init(FSP_BACKLOG_SIZE);
		else
			pControlBlock->Init(psp1->sendSize, psp1->recvSize);
		//
		pControlBlock->tfrc = psp1->tfrc;
		pControlBlock->milky = psp1->milky;
		pControlBlock->noEncrypt = psp1->noEncrypt;
		//
		pControlBlock->notices.SetHead(FSP_IPC_CannotReach);
		//^only after the control block is successfully mapped into the memory space of LLS may it be cleared by LLS

		// could be exploited by ULA to make services distinguishable
		memcpy(&context, psp1, sizeof(FSP_SocketParameter));
		pendingSendBuf = (octet*)psp1->welcome;
		pendingSendSize = psp1->len;
	}

	int Dispose();
	int RecycLocked();

	// Convert the relative address in the control block to the address in process space, unchecked
	octet * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		return pControlBlock->GetSendPtr(skb);
	}
	octet * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb) const
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
	// Given
	//	int		the value meant to be returned
	// Do
	//	Process the receive buffer and send queue, then free the mutex and return the value
	// Remark
	//	ULA function may be called back on processing the receive buffer or send queue,
	//	and this function SHALL be called as the 'parameter' of the return statement
	//	Processing the receive buffer takes precedence because receiving is to free resource
	int  TailFreeMutexAndReturn(int r)
	{
		if (HasDataToDeliver() && (fpReceived != NULL || fpPeeked != NULL))
		{
			ProcessReceiveBuffer();
			if (!TryMutexLock())
				return r;
		}
		//
		if (HasFreeSendBuffer() && (fpSent != NULL || pendingSendBuf != NULL))
			ProcessPendingSend();
		else
			SetMutexFree();
		//
		return r;
	}
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
		initiatingShutdown = 1;
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
		return _InterlockedCompareExchangePointer((PVOID *)& fpCommitted, fp1, NULL) == NULL;
	}

	bool TestSetSendReturn(PVOID fp1)
	{
		return _InterlockedCompareExchangePointer((PVOID *) & fpSent, fp1, NULL) == NULL; 
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

	int SetOnRelease(PVOID fp1)
	{
		if (InState(NON_EXISTENT))
			return -EBADF;
		bool b = (_InterlockedCompareExchangePointer((PVOID*)& fpFinished, fp1, NULL) == NULL);
		if (b || InState(SHUT_REQUESTED) || InState(CLOSED))
			return EAGAIN;
		return 0;
	}

	int Shutdown();
	int Shutdown(NotifyOrReturn fp1) { fpFinished = fp1; return Shutdown(); }

	void SetCallbackOnRequest(CallbackRequested fp1) { context.onAccepting = fp1; }
	void SetCallbackOnAccept(CallbackConnected fp1) { context.onAccepted = fp1; }

	void SetNewTransaction() { newTransaction = 1; }
	void SetEoTPending(bool v = true) { pendingEoT = (v ? 1 : 0); }
	bool IsEoTPending() { return pendingEoT != 0; }

	void SetCallbackOnError(NotifyOrReturn fp1) { context.onError = fp1; }
	void NotifyError(FSP_ServiceCode c, int e = 0) { if (context.onError != NULL) context.onError(this, c, e); }

	// Defined in IOControl.cpp
	int GetProfilingCounts(PSocketProfile);
	PFSP_Context GetFSPContext() { return &this->context; }

	// defined in DllEntry.cpp:
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context, CommandNewSession &);
#if defined(__WINDOWS__)
	static void SaveProcessId() { idThisProcess = GetCurrentProcessId(); }
#elif defined(__linux__) || defined(__CYGWIN__)
	static void SaveProcessId() { idThisProcess = getpid(); }
#endif
};
