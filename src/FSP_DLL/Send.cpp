/*
 * DLL to service FSP upper layer application
 * Send/Write/Transmit functions
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
#include "FSP_DLL.h"
#include <time.h>


/* FSM:  State migration on sending. See also MigrateToNewStateOnSend. *\

{CHALLENGING, CLONING}
|<-->[API: Send{new data}]{just prebuffer}

{ACTIVE, PEER_COMMIT}
|<-->[API: Send{more data}][Send PURE_DATA]

ACTIVE
	|--[API: Send{flush}]-->COMMITTING{Urge COMMIT}

PEER_COMMIT
	|--[API: Send{flush}]-->COMMITTING2-->[Urge COMMIT]

COMMITTED
	|--[API: Send{more data}]-->ACTIVE-->[Send PERSIST]
	|--[API: Send{flush}]-->COMMITTING{Urge COMMIT}

CLOSABLE
	|--[API: Send{more data}]-->PEER_COMMIT-->[Send PERSIST]
	|--[API: Send{flush}]-->COMMITTING2-->[Urge COMMIT]

  */


// Given
//	FSPHANDLE			the socket handle
//	CallbackBufferReady	the pointer to the function called back when enough buffer available
// Return
//	size of free send buffer available immediately, might be 0 which is not an error
//	negative if exception has arisen
DllExport
int32_t FSPAPI GetSendBuffer(FSPHANDLE hFSPSocket, CallbackBufferReady fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	if (!p->TestSetSendReturn((PVOID)fp1))
		return -EBUSY;
	return p->AcquireSendBuf();
}



// Given
//	FSPHANDLE			the socket handle
//	placeholder of the pointer to the capacity available
// Return
//	NULL if no immediately available buffer
//	or the pointer to the free send buffer
// Remark
//	the capacity might be negative if error occurred, or 0 if no immediately available buffer
DllExport
void* FSPAPI TryGetSendBuffer(FSPHANDLE hFSPSocket, int32_t* pSize)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if (p == NULL)
	{
		*pSize = -EFAULT;
		return NULL;
	}
	
	if (!p->TestSetSendReturn(NULL))
	{
		*pSize = -EBUSY;
		return NULL;
	}

	return p->TryAcquireSendBuf(*pSize);
}



// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int32_t		the number of octets to send
//	bool		whether to terminate the transmit transaction
//	NotifyOnReturn	the pointer of the function to call back when the transmit transaction is terminated
// Return
//	zero or positive, number of payload octets in the send queue
//	negative if it is the error number
// Remark
//	SendInline is typically chained in tandem with GetSendBuffer
//	The buffer MUST begin from what the callback function of GetSendBuffer has returned and
//	may not exceed the capacity that the callback function of GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
DllExport
int32_t FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int32_t len, bool eotFlag, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	if(eotFlag && !p->TestSetOnCommit((PVOID)fp1))
		return -EBUSY;
	return p->SendInplace(buffer, len, eotFlag);
}



// Given
//	FSPHANDLE	the socket handle
//	const void *the buffer pointer
//	int32_t		the number of octets to send
//	unsigned	the send options
//	NotifyOrReturn	the callback function pointer
// Return
//	non-negative if it is the number of octets put into the queue immediately
//	-EBUSY if previous asynchronous Write operation has not completed
//	-EFAULT if some ridiculous exception has arisen
//	-EDEADLK if it cannot obtain mutual exclusive lock
//	-EADDRINUSE if previous blocking Write operation has not completed
//	-EIO if immediate sending operation failed
// Remark
//	Only all data have been buffered may be NotifyOrReturn called.
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until every octet in the given buffer has been passed to LLS. See also ReadFrom
DllExport
int32_t FSPAPI WriteTo(FSPHANDLE hFSPSocket, const void * buffer, int32_t len, unsigned flags, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	//
	bool eot = (flags & TO_END_TRANSACTION) != 0;
	if ((eot && !p->TestSetOnCommit((PVOID)fp1)) || (!eot && !p->TestSetSendReturn((PVOID)fp1)))
		return -EBUSY;
	return p->SendStream(buffer, len, eot, (flags & TO_COMPRESS_STREAM) != 0);
}



// Given
//	FSPHANDLE		the FSP socket
// Return
//	0 if no error
//	-EDEADLK if no mutual-exclusive lock available
//	-EIO if LLS is not available
// Remark
//	Unlike Commit, the last packet is not necessarily marked EoT
//	For compatibility with TCP byte-stream transmission
DllExport
int FSPAPI Flush(FSPHANDLE hFSPSocket)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	return p->Flush();
}



// Internal API for committing/flushing a transmit transaction
// Try to commit current transmit transaction
DllSpec
int FSPAPI Commit(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	return p->LockAndCommit(fp1);
}



// Given
//	int32_t&	[out] reference to the size of the send buffer obtained
// Return
//	NULL if no immediately available free send buffer
//	or the pointer to the send buffer obtained
void* CSocketItemDl::TryAcquireSendBuf(int32_t& size)
{
	if (!WaitUseMutex())
	{
		size = (IsInUse() ? -EDEADLK : -EINTR);
		return NULL;
	}

	if (pendingSendBuf != NULL)
	{
		SetMutexFree();
		size = -EBUSY;
		return NULL;
	}

	void* p = pControlBlock->InquireSendBuf(&pendingSendSize);
	size = pendingSendSize;
	SetMutexFree();
	return p;
}



// Return
//	Size of currently available free send buffer
int32_t CSocketItemDl::AcquireSendBuf()
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (pendingSendBuf != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	pControlBlock->InquireSendBuf(&pendingSendSize);

	return TailFreeMutexAndReturn(pendingSendSize);
}



// Given
//	void *		the buffer pointer
//	int32_t		the number of octets to send
//	bool		whether to terminate the transmit transaction
// Return
//	number of payload octets in the send queue
//	negative if it is the error number
// Remark
//	SendInplace works in tandem with AcquireSendBuf or TryAcquireSendBuf
int32_t LOCALAPI CSocketItemDl::SendInplace(void * buffer, int32_t len, bool eot)
{
	if (len <= 0)
		return -EINVAL;

	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (eot && (InState(COMMITTING) || InState(COMMITTING2)))
	{
		SetMutexFree();
		return -EBUSY;
	}

	int r = PrepareToSend(buffer, len, eot);
	return TailFreeMutexAndReturn(r < 0 ? r : bytesBuffered);
}



// Given
//	const void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
//	bool	whether to terminate the transmit transaction
// Return
//	number of octets put into the send queue
//	negative if it is the error number
// Remark
//	It is blocking if to commit the data but previous transaction commitment has not been acknowledged
int32_t LOCALAPI CSocketItemDl::SendStream(const void* buffer, int32_t len, bool eot, bool toCompress)
{
	int r;

	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	FSP_Session_State state1 = GetState();
	if (eot && (state1 == COMMITTING || state1 == COMMITTING2))
	{
		r = BlockOnCommit();
		if (r < 0)
		{
			SetMutexFree();
			return r;
		}
		SetEoTPending();
		newTransaction = 1;
	}
	else
	{
		SetEoTPending(eot);
		if (state1 == COMMITTED || state1 == CLOSABLE)
			newTransaction = 1;
	}

	if (_InterlockedCompareExchangePointer((PVOID*)&pendingSendBuf, (PVOID)buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}
	bytesBuffered = 0;

	if (toCompress && newTransaction && !AllocStreamState())
	{
		SetMutexFree();
		return -ENOMEM;
	}

	// By default it should be asynchronous:
	if (fpSent != NULL || fpCommitted != NULL)
		return TailFreeMutexAndReturn(BufferData(len));

	// If it is blocking, wait until every byte has been put into the queue
	while ((r = BufferData(len)) >= 0)
	{
		if (pendingSendSize <= 0)
			break;
		// Here wait LLS to free some send buffer block
		uint64_t t0 = GetTickCount64();
		do
		{
			SetMutexFree();
			Sleep(TIMER_SLICE_ms);
			if (GetTickCount64() - t0 > COMMITTING_TIMEOUT_ms)
				return -EBUSY;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : -EINTR);
		} while (!HasFreeSendBuffer());
		//
		len = pendingSendSize;
	}
	pendingSendBuf = NULL;

	return TailFreeMutexAndReturn(r < 0 ? r : bytesBuffered);
}



// [API:Commit]
//	{SHUT_REQUESTED, PRE_CLOSED, CLOSED}-->{warning}
//	{COMMITTED, CLOSABLE}-->{keep state}
//	ESTABLISHED-->COMMITTING
//	PEER_COMMIT-->COMMITTING2
//	{COMMITTING, COMMITTING2}-->{keep state}
//	{otherwise: failed}
int CSocketItemDl::LockAndCommit(NotifyOrReturn fp1)
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (!TestSetOnCommit((PVOID)fp1))
	{
#if defined(TRACE) && !defined(NDEBUG)
		printf_s("Commit: the socket is already in commit or graceful shutdown process.\n");
#endif
		SetMutexFree();
		return -EAGAIN;
	}

	if (pControlBlock->state > CLOSABLE)
	{
		SetMutexFree();
		return EAGAIN;	// Just a warning, and the callback function may or may not be called
	}

	if (InState(COMMITTED) || InState(CLOSABLE))
	{
#if defined(TRACE) && !defined(NDEBUG)
		if (HasDataToCommit() || IsEoTPending())
		{
			printf_s("Commit found protocol implementation error: \n"
				"in COMMITTED state there should have no data pended to send.\n");
		}
#endif
		fpCommitted = NULL;
		SetMutexFree();
		return 0;	// It is already in a state that the near end's last transmit transaction has been committed
	}

	return TailFreeMutexAndReturn(Commit());
}



// Remark
//	Side-effect: may modify pendingSendSize and pendingSendBuf if WriteTo() is pending
//	may call back fpSent or fpCommitted, and clear the function pointer
//	Here we have assumed that the underlying binary system does not change
//	execution order of accessing volatile variables
// Assume it has taken exclusive access of the socket
//	Also assume that this subroutine is either called by the polling timer, or
//	by the event handler on FSP_NotifyFlushed or FSP_NotifyBufferReady 
//	It is well known that fpSent is alias of CallbackBufferReady when to get send buffer
void CSocketItemDl::ProcessPendingSend()
{
l_recursion:
	// Conventional streaming mode takes precedence:
	if (pendingSendBuf != NULL || pStreamState != NULL)
	{
		if (HasDataToCommit())
		{
			BufferData(pendingSendSize);
			if (HasDataToCommit())
				return;
		}

		NotifyOrReturn fp2 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpSent, NULL);
		pendingSendBuf = NULL;
		if (fp2 != NULL)
		{
			fp2(this, FSP_Send, bytesBuffered);
			return;
		}
		// Or else fall through to check whether it has intent to commit the transmit transaction
	}

	// SendInplace does not rely on keeping 'pendingEoT' state internally, and such state takes precedence
	if (IsEoTPending())
	{
		if (!initiatingShutdown)
			MigrateToNewStateOnCommit();
		else if (GetState() == CLOSABLE)
			SetState(PRE_CLOSED);
		// The LLS does accept RELEASE packet in COMMITTING2 state
		AppendEoTPacket();
		return;
	}

	// Or else it's pending GetSendBuffer()
	CallbackBufferReady fp2 = (CallbackBufferReady)_InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);
	if (fp2 == NULL)
		return;	// As there's no thread waiting free send buffer

	ControlBlock::seq_t seqN = pControlBlock->sendBufferNextSN;
	int32_t m;
	octet *p = pControlBlock->InquireSendBuf(& m);
	if (p == NULL)
	{
		TestSetSendReturn((PVOID)fp2);
		BREAK_ON_DEBUG(); // race condition does exist, but shall be very rare!
		return;
	}

	// If ULA hinted that sending was not finished yet, continue to use the saved pointer
	// of the callback function. However, if it happens to be updated, prefer the new one
	bool b = (fp2(this, p, m) >= 0);
	if (!IsInUse())
		return;
	if (b)
		TestSetSendReturn((PVOID)fp2);

	// The callback function should consume at least one buffer block to avoid dead-loop
	if (b && (int32_t(pControlBlock->sendBufferNextSN - seqN) > 0) && HasFreeSendBuffer())
		goto l_recursion;

	return;
}


// Given
//	FSPOperationCode	The operation code of the first packet meant to put into the send buffer
// Return
//	number of packets that have been completed
//	negative return value is the error number
// Remark
//	Meant to start a new transmit transaction
int CSocketItemDl::PrepareSendBuffer(FSPOperationCode opCode)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	ControlBlock::PFSP_SocketBuf p;

	if (context.welcome == NULL)
	{
		skb->version = THIS_FSP_VERSION;
		skb->len = 0;
		skb->InitFlags<TransactionEnded>();
		// Mark the reserved head packet ready
		pControlBlock->sendBufferNextPos = 1;
		pControlBlock->sendBufferNextSN = GetSendWindowFirstSN() + 1;
		skb->opCode = opCode;
		skb->ReInitMarkComplete();
		return 1;
	}
	pendingSendBuf = (octet *)context.welcome;

	const octet cFlag = context.precompress ? (1 << Compressed) : 0;
	const int32_t capacity = pControlBlock->sendBufferBlockN;
	int32_t& m = pendingSendSize;
	int32_t count = 0;
	octet *tgtBuf;
	int k;
	do
	{
		p = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->flags = cFlag;
		tgtBuf = GetSendPtr(p);
		if (tgtBuf == NULL)
			return -EFAULT;

		k = min(m, MAX_BLOCK_SIZE);
		memcpy(tgtBuf, pendingSendBuf, k);
		p->len = k;
		p->ReInitMarkComplete();
		//
		bytesBuffered += k;
		m -= k;
		pendingSendBuf += k;
		//
		count++;
		pControlBlock->sendBufferNextSN++;
		pControlBlock->IncRoundSendBlockN(pControlBlock->sendBufferNextPos);
	} while (m > 0 && count < capacity);

	skb->opCode = opCode;
	if (m <= 0)
	{
		pendingSendBuf = NULL;
		p->SetFlag<TransactionEnded>();
	}

	return count;
}



// Given
//	int		number of octets in pendingSendBuf to put into the send queue
// Return
//	number of packets that have been completed
//	negative return value is the error number
// Remark
//	If len == 0, it meant to flush the compression buffer, if any
//	Side-effect:
//	set the value of pendingSendSize to number of octets yet to be buffered
//	set the value of pendingStreamingSize to number of compression result octets yet to be queued
// Compression on the wire is co-routing
int LOCALAPI CSocketItemDl::BufferData(int m)
{
	if (m < 0)
		return -EINVAL;
	if (m == 0 && !HasInternalBufferedToSend())
		return 0;
	ControlBlock::PFSP_SocketBuf p = skbImcompleteToSend;
	int count = 0;
	octet *tgtBuf;
	register int k;
	if (p != NULL)
	{
		if (p->len < 0 || p->len >= MAX_BLOCK_SIZE)
			return -EFAULT;
		//
		tgtBuf = GetSendPtr(p) + p->len;
	}
	else
	{
		p = GetSendBuf();
		if (p == NULL)
			return 0;
		//
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = 0;
		tgtBuf = GetSendPtr(p);
	}
	MigrateToNewStateOnSend();
	// p->buf was set when the send buffer control structure itself was initialized
	// flags are already initialized when GetSendBuf
	// only after every field, including flag, has been set may it be unlocked
	// otherwise WriteTo following may put further data into the last packet buffer
	ControlBlock::PFSP_SocketBuf skb0 = p;
	do
	{
		if (pStreamState == NULL)
		{
			k = min(m, MAX_BLOCK_SIZE - p->len);
			memcpy(tgtBuf, pendingSendBuf, k);
			p->len += k;
			bytesBuffered += k;
			//
			m -= k;
			pendingSendBuf += k;
		}
		else
		{
			k = MAX_BLOCK_SIZE - p->len;
			int m2 = Compress(tgtBuf, k, pendingSendBuf, m);
			if (m2 < 0)
				return m2;
			p->SetFlag<Compressed>();
			p->len += k;
			bytesBuffered += k;
			//
			m -= m2;
			pendingSendBuf += m2;
		}
		//
		if (p->len >= MAX_BLOCK_SIZE)
			count++;
		//
		if (m == 0)
		{
			tgtBuf += k;
			break;
		}
		//
		p = GetSendBuf();
		if (p == NULL)
			break;
		//
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = 0;
		tgtBuf = GetSendPtr(p);
	} while (true);

	pendingSendSize = m;
	//
	if(p == NULL)
	{
		skbImcompleteToSend = NULL;
		if(count > 0)
			goto l_finalize;
		return 0;
	}
	//
	k = MAX_BLOCK_SIZE - p->len;	// To compress internally buffered: it may be that k == 0
	if(pendingSendSize != 0 || !IsEoTPending())
	{
		skbImcompleteToSend = (k > 0 ? p : NULL);
		if(count > 0)
			goto l_finalize;
		return 0;
		//^As there is no packet physically put into the send queue do not migrate to new state.
	}
	// else if(pendingSendSize == 0 && IsEoTPending())
	skbImcompleteToSend = NULL;
	if (pStreamState == NULL)
	{
		p->SetFlag<TransactionEnded>();
		MigrateToNewStateOnCommit();
		if(k > 0)
			count++;
		goto l_finalize;
	}
	// pStreamState != NULL. To compress internal buffered
	if (k > 0)
	{
		Compress(tgtBuf, k, NULL, 0);
		p->len += k;
		count++;
		bytesBuffered += k;
	}
#ifndef NDEBUG
	if(count <= 0)
		printf_s("Erroneous implementation!? On-the-wire compression shall consume at least one block\n");
#endif
	while (HasInternalBufferedToSend())
	{
		p = GetSendBuf();
		if (p == NULL)
			goto l_finalize;	// Warning: not all data have been buffered		
		// To copy out internally compressed:
		k = MAX_BLOCK_SIZE;
		Compress(GetSendPtr(p), k, NULL, 0);
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->SetFlag<Compressed>();
		p->len = k;
		count++;
		bytesBuffered += k;
	}	// end if the internal buffer of on-the-wire compression is not empty
	p->SetFlag<TransactionEnded>();
	MigrateToNewStateOnCommit();
	FreeStreamState();
	//
l_finalize:
	p = skb0;
	if (_InterlockedCompareExchange8(&newTransaction, 0, 1) != 0)
		p->opCode = PERSIST;
	k = count;
	do
	{
		p->ReInitMarkComplete();
		if((++p - pControlBlock->HeadSend()) >= pControlBlock->sendBufferBlockN)
			p = pControlBlock->HeadSend();
	} while (--k > 0);
	//
	return count;
}



// Given
//	void *	the pointer to the in-place buffer to be marked in the send queue
//	int32_t	the size of the buffer in bytes
//	bool	whether to terminate the transmit transaction
// Return
//	number of blocks split
//	-EINVAL if the second or third parameter is illegal
//	-ENOMEM if size requested is larger than available
// Remark
//	Would automatically mark the previous last packet as completed
int32_t LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int32_t len, bool eot)
{
	if(len <= 0 || (len % MAX_BLOCK_SIZE != 0 && !eot))
	{
		bytesBuffered = 0;
		return -EINVAL;
	}

	// Automatically mark the last unsent packet as completed. See also BufferData()
	if(skbImcompleteToSend != NULL)
	{
		skbImcompleteToSend->ReInitMarkComplete();
		skbImcompleteToSend = NULL;
	}

	int32_t m;
#ifndef NDEBUG
	octet *bufToCheck = pControlBlock->InquireSendBuf(&m);
	if (bufToCheck != buf)
	{
		printf_s("The caller should not mess up the reserved the buffer space!\n");
		bufToCheck = pControlBlock->InquireSendBuf(&m);
	}
	if (m < len)
		return -ENOMEM;
#endif

	if (InState(COMMITTED) || InState(CLOSABLE))
		newTransaction = 1;
	MigrateToNewStateOnSend();

	register ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	// p now is the descriptor of the first available buffer block
	m = (len - 1) / MAX_BLOCK_SIZE;

	register ControlBlock::PFSP_SocketBuf p0 = p;
	for(register int j = 0; j < m; j++)
	{
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->ClearFlags();
		p->len = MAX_BLOCK_SIZE;
		p++;
	}
	//
	p->version = THIS_FSP_VERSION;
	p->opCode = PURE_DATA;
	if (eot)
	{
		p->InitFlags<TransactionEnded>();
		MigrateToNewStateOnCommit();
	}
	else
	{
		p->ClearFlags();
	}
	p->len = len - MAX_BLOCK_SIZE * m;
	bytesBuffered = len;

	p = p0;
	if (_InterlockedCompareExchange8(&newTransaction, 0, 1) != 0)
		p->opCode = PERSIST;
	// unlock them in a batch
	m++;
	for(register int j = 0; j < m; j++)
	{
		(p++)->ReInitMarkComplete();
	}

	// finally set the new tail of the send queue, and the let LLS detect the change
	pControlBlock->AddRoundSendBlockN(pControlBlock->sendBufferNextPos, m);
	_InterlockedExchangeAdd((PLONG)&pControlBlock->sendBufferNextSN, m);
	//^here memory barrier is necessary
	return m;
}



// Return
//	0 if no error
//	negative if error:
//	-EDEADLK if no mutex lock available
//	-EINTR if the connection is interrupted when waiting state migration
//	-EBUSY if can not reach target state in the limited time
// Remark
//	Assume it has obtain mutex lock on entry and it would keep the lock on success but free the lock on error
int CSocketItemDl::BlockOnCommit()
{
	int32_t k = pControlBlock->CountSentInFlight();
	uint64_t t0 = GetTickCount64();
	FSP_Session_State s;
	do
	{
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
		if (!WaitUseMutex())
			return (IsInUse() ? -EDEADLK : -EINTR);
		//
		if (pControlBlock->CountSentInFlight() < k)
		{
			k = pControlBlock->CountSentInFlight();
			t0 = GetTickCount64();
		}
		else if (GetTickCount64() - t0 > COMMITTING_TIMEOUT_ms)
		{
			SetMutexFree();
			return -EBUSY;
		}
		s = GetState();
	} while (s != COMMITTED && s < CLOSABLE && s != NON_EXISTENT);
	//
	return 0;
}



// Assume that it has obtained the mutex lock and the caller has set time-out clock
// Case 0, it is assumed that if it is already committed the routing is not called
// Remark
//	To make life easier, it is assumed that it needs no separate Commit after obtaining send buffer
//  And it does not manage to optimize for the corner case
//	that the last packet in the send queue could be marked EoT before being sent.
int CSocketItemDl::Commit()
{
#ifndef NDEBUG
	if (InState(COMMITTED) || InState(CLOSABLE))
	{
		printf_s("Should not call internal commit: protocol implementation error!\n");
		BREAK_ON_DEBUG();
		return -EDOM;
	}
#endif
	FSP_Session_State state1 = GetState();
	int r = 0;
	// Case 1, it is committing
	//	All blocks have been put into the send queue
	//	and the tail of the send queue has already been marked EOT
	if(state1 == COMMITTING || state1 == COMMITTING2)
		return (fpCommitted != NULL ? 0 : BlockOnCommit());

	SetEoTPending();

	// Case 2, there is set some block to be put into the send queue
	//	it is sending a stream and there are yet some data to be buffered
	if (HasDataToCommit())
	{
		// flush internal buffer for compression, if it is non-empty
		if (HasFreeSendBuffer())
			BufferData(pendingSendSize);
		// else Case 4.1, the send queue is full and there is some payload to wait free buffer
	}
	else if (skbImcompleteToSend != NULL)
	{
		// terminating the last packet of the stream
		skbImcompleteToSend->SetFlag<TransactionEnded>();
		skbImcompleteToSend->ReInitMarkComplete();
		skbImcompleteToSend = NULL;
		MigrateToNewStateOnCommit();
	}
	// Case 3, there is at least one idle slot to put an EoT packet
	else
	{
		MigrateToNewStateOnCommit();
		AppendEoTPacket();
	}
	// Case 4: just to wait some buffer ready. See also ProcessPendingSend

#ifdef _NO_LLS_CALLABLE
	return r;
#else
	return (fpCommitted != NULL || r < 0 ? r : BlockOnCommit());
#endif
}



// Urge LLS to send, even if the last packet is not fully loaded.
int CSocketItemDl::Flush()
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	register ControlBlock::PFSP_SocketBuf p
		= (ControlBlock::PFSP_SocketBuf)_InterlockedExchangePointer((PVOID *)&skbImcompleteToSend, NULL);

	if (p == NULL)
	{
		SetMutexFree();
		return 0;
	}

	p->ReInitMarkComplete();
	SetMutexFree();
	return 0;
}
