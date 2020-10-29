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

#ifndef MAX_CONNECTION_NUM	// must be some power value of 2
# define MAX_CONNECTION_NUM	256
#endif

#define MAX_WORKING_THREADS (MAX_CONNECTION_NUM*2)

struct CSocketItemDl;


// 'Slim' in the sense that there is no job queue
struct CSlimThreadPoolItem
{
	void (CSocketItemDl::* fpWork)();	// the function to do the real job
	pthread_t		hThread;
	CSocketItemDl * contextWorkingOn;	// NULL if the thread is idle
	//
	void			LoopWaitJob();
};



struct CSlimThreadPool
{
#ifndef _NO_LLS_CALLABLE
# define SLIM_THREAD_POOL_SIZE (MAX_CONNECTION_NUM * 2)
#else
# define SLIM_THREAD_POOL_SIZE 2
#endif
	CSlimThreadPoolItem items[SLIM_THREAD_POOL_SIZE];
	//
	bool NewThreadFor(CSlimThreadPoolItem *);
#if defined(__WINDOWS__)
	static DWORD WINAPI ThreadWorkBody(LPVOID param)
	{
		((CSlimThreadPoolItem*)param)->LoopWaitJob();
		return 0;
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	static void* ThreadWorkBody(void* param)
	{
		((CSlimThreadPoolItem*)param)->LoopWaitJob();
		return NULL;
	}
#endif

	bool ScheduleWork(CSocketItemDl *, void (CSocketItemDl::*)());
	CSlimThreadPool();
};



class CSocketDLLTLB: CSRWLock, public CSlimThreadPool
{
	int		countAllItems;
	int		sizeOfWorkSet;
	CSocketItemDl * pSockets[MAX_CONNECTION_NUM];
	CSocketItemDl * head;
	CSocketItemDl * tail;

	CSocketItemDl * headOfInUse;
	pthread_t		hThreadWait;
	void			WaitEventToDispatch();
	void	Init();

#if defined(__WINDOWS__)
	static DWORD WINAPI WaitNoticeCallBack(LPVOID param)
	{
		((CSocketDLLTLB *)param)->WaitEventToDispatch();
		return 0;
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	static void* NoticeHandler(void * param) { ((CSocketDLLTLB *)param)->WaitEventToDispatch(); return NULL; }
#endif

public:
	// IPC facility for working in tandem with LLS
	HPIPE_T			sdPipe;

	CSocketItemDl * AllocItem();
	void FreeItem(CSocketItemDl *);

	bool InitThread();

	CSocketDLLTLB()
	{
		InitMutex();
		Init();
		sizeOfWorkSet = 0;
		head = tail = NULL;
	}

	~CSocketDLLTLB();

	// Send message to the pairing socket TLB in LLS
	int		SendToPipe(const void*, int n = sizeof(UCommandToLLS));
	bool	GetNoticeFromPipe(SNotification *);

	// Return the registered socket pointer mapped to the FSP handle
	static CSocketItemDl * HandleToRegisteredSocket(FSPHANDLE);
};



// Forward declaration for compression-decompression
struct SStreamState;
struct SDecodeState;


// Data Layout for socket item in the library, had better dynamically linked
struct CSocketItemDl : CSocketItem
{
	static CSocketDLLTLB	socketsTLB;

	// for sake of incarnating new accepted connection
	FSP_SocketParameter context;

	// optional on-the-wire compression/decompression
	SStreamState	* pStreamState;
	SDecodeState	* pDecodeState;

	// for sake of buffered, streamed I/O
	ControlBlock::PFSP_SocketBuf skbImcompleteToSend;

	char			inUse;
	char			newTransaction;	// it may simultaneously start a transmit transaction and flush/commit it

	// Flags, in dictionary order
	char			initiatingShutdown : 1;
	char			peerCommitPending : 1;
	char			peerCommitted : 1;	// Only for conventional buffered, streamed read
	char			pendingEoT : 1;		// EoT flag is pending to be added on a packet
	char			toCancel : 1;		// cancel current operation
	char			toReleaseMemory : 1;

	FSP_ServiceCode commandLastIssued;

	int32_t			lockDepth;
	pthread_t		lockOwner;

	timer_t			timer;

	int64_t			timeOut_ns;
	timestamp_t		timeLastTriggered;

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

	void			ArrangeCallbackOnAccepted();
	void			ArrangeCallbackOnReceive();
	void			ArrangeCallbackOnSent();

#if defined(__WINDOWS__)
	static VOID NTAPI TimeOutCallBack(PVOID param, BOOLEAN isTimeout)
	{
		UNREFERENCED_PARAMETER(isTimeout);
		((CSocketItemDl*)param)->DoPolling();
	}

	void CopyFatMemPointo(CommandNewSession&);

	void RecycleSimply();

#elif defined(__linux__) || defined(__CYGWIN__)
	static void TimeOutHandler(union sigval v) { ((CSocketItemDl*)v.sival_ptr)->DoPolling(); }

	void CopyFatMemPointo(CommandNewSession&);

	void RecycleSimply()
	{
		timer_t h;
		if ((h = (timer_t)_InterlockedExchange(&timer, 0)) != 0)
		{
			timer_delete(h);
			socketsTLB.FreeItem(this);
		}
	}
#endif

	void CancelTimeout() { timeOut_ns = INT64_MAX; }
	bool IsTimedOut() { return ((int64_t(timeOut_ns - (NowUTC() - timeLastTriggered) * 1000)) < 0); }
	bool StartPolling();
	void DoPolling();

	void ProcessNoticeLocked(FSP_NoticeCode);

	void CallBackOnAccepted();
	void CallBackOnReceive();
	void CallBackOnBufferReady();

	// in Establish.cpp
	CSocketItemDl *ProcessOneBackLog(PItemBackLog);
	void ProcessBacklogs();
	CSocketItemDl *Accept1();

	CSocketItemDl * PrepareToAccept(SItemBackLog &);
	bool LOCALAPI ToWelcomeConnect(SItemBackLog &);
	void ToConcludeConnect();
	ControlBlock::PFSP_SocketBuf SetHeadPacketIfEmpty(FSPOperationCode);

	// In Multiplex.cpp
	FSPHANDLE LOCALAPI InitiateCloning(PFSP_Context);
	bool LOCALAPI ToWelcomeMultiply(SItemBackLog &);

	// In Send.cpp
	void ProcessPendingSend();
	int LOCALAPI BufferData(int);
	int PrepareSendBuffer(FSPOperationCode);

	bool HasFreeSendBuffer() { return (pControlBlock->CountSendBuffered() - pControlBlock->sendBufferBlockN < 0); }

	// In Receive.cpp
	void	ProcessReceiveBuffer();
	int32_t FetchReceived();

	// In Deflate.cpp
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
	void FreeWithReset()
	{
		if (pControlBlock != NULL)
			Call<FSP_Reset>();
		Free();
	}
	// Safely assume that ULA cleans socket created by Listen, Accept1, Connect2/3 and Multiply
	void ResetAndNotify(FSP_ServiceCode c, int v)
	{
		if (pControlBlock != NULL)
			Call<FSP_Reset>();
		inUse = 0;	// Make any function other than Dispose to fail
		NotifyError(c, -v);
	}

	// TODO: evaluate configurable shared memory block size? // UNRESOLVED!? MTU?
	static int32_t AlignMemorySize(PFSP_Context);

	bool InitSharedMemory();
	void SetConnectContext(const PFSP_Context);

	int Dispose();

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

	uint64_t GetExtentOfULA() { return context.extentI64ULA; }
	void SetExtentOfULA(uint64_t value) { context.extentI64ULA = value; }

	bool HasPeerCommitted() { return peerCommitted != 0; }

	bool WaitUseMutex();
	void SetMutexFree();
	bool TryMutexLock();
	int  TailFreeMutexAndReturn(int);
	bool IsInUse() { return (_InterlockedOr8(&inUse, 0) != 0) && (pControlBlock != NULL); }

	void SetPeerName(const char *cName, size_t len)
	{
		size_t n = min(len, sizeof(pControlBlock->peerAddr.name));
		memcpy(pControlBlock->peerAddr.name, cName, n);	// assume memory space has been zeroed
	}
	int ComparePeerName(const char *cName) { return _strnicmp(pControlBlock->peerAddr.name, cName, sizeof(pControlBlock->peerAddr.name)); }

#ifndef _NO_LLS_CALLABLE
	bool Call(const UCommandToLLS* pCmd)
	{
		commandLastIssued = pCmd->sharedInfo.opCode;
		return socketsTLB.SendToPipe((const void *)pCmd);
	}
#else
	bool Call(const UCommandToLLS *pCmd) { commandLastIssued = pCmd->sharedInfo.opCode; return true; }
#endif

	template<FSP_ServiceCode c> bool Call()
	{
		SCommandToLLS cmd;
		cmd.opCode = c;
		cmd.fiberID = fidPair.source;
		commandLastIssued = c;
		return (socketsTLB.SendToPipe(&cmd) > 0);
	}
	CSocketItemDl * CallCreate(FSP_ServiceCode);
	void LOCALAPI RejectRequest(ALFID_T, ALFID_T, uint32_t);

	int InstallRawKey(const octet *, int32_t, uint64_t);

	void*	TryAcquireSendBuf(int32_t&);
	int32_t AcquireSendBuf();
	int32_t LOCALAPI SendInplace(void *, int32_t, bool);

	ControlBlock::PFSP_SocketBuf GetSendBuf() { return pControlBlock->GetSendBuf(); }

	int32_t LOCALAPI PrepareToSend(void *, int32_t, bool);
	int32_t LOCALAPI SendStream(const void *, int32_t, bool, bool);
	int Flush();

	bool AppendEoTPacket()
	{
		ControlBlock::PFSP_SocketBuf p = pControlBlock->GetSendBuf();
		if (p == NULL)
			return false;
		p->opCode = (initiatingShutdown ? RELEASE : NULCOMMIT);
		p->len = 0;
		p->SetFlag<TransactionEnded>();
		p->ReInitMarkComplete();
		return true;
	}

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

	int SetOnConnected(CallbackConnected fp1)
	{
		if (InState(NON_EXISTENT))
			return -EBADF;
		context.onAccepted = fp1;
		return 0;
	}

	int SetOnError(NotifyOrReturn fp1)
	{
		if (InState(NON_EXISTENT))
			return -EBADF;
		context.onError = fp1;
		return 0;
	}

	int SetOnMultiplying(CallbackRequested fp1)
	{
		if (InState(NON_EXISTENT))
			return -EBADF;
		context.onAccepting = fp1;
		return 0;
	}

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
	static CSocketItemDl * LOCALAPI CreateControlBlock(const PFSP_IN6_ADDR, PFSP_Context);
};
