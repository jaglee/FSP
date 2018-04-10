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
		return -EFAULT;
	if (!p->TestSetSendReturn(fp1))
		return -EBUSY;
	return p->AcquireSendBuf();
}



// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int32_t		the number of octets to send
//	bool		whether to terminate the transmit transaction
// Return
//	positive if it is number of blocks scheduled to send
//	negative if it is the error number
// Remark
//	SendInline is typically chained in tandem with GetSendBuffer
//	The buffer MUST begin from what the callback function of GetSendBuffer has returned and
//	may not exceed the capacity that the callback function of GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int32_t len, bool eotFlag)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
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
//	-EFAULT if some ridiculous exception has arised
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
		return -EFAULT;
	if(!p->TestSetSendReturn(fp1))
		return -EBUSY;
	return p->SendStream(buffer, len, (flags & TO_END_TRANSACTION) != 0, (flags & TO_COMPRESS_STREAM) != 0);
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
		return -EFAULT;
	return p->Flush();
}



// [API:Commit]
//	{COMMITTED, CLOSABLE, PRE_CLOSED, CLOSED}-->{keep state}
//	ESTABLISHED-->COMMITTING
//	PEER_COMMIT-->COMMITTING2
//	{COMMITTING, COMMITTING2}-->{keep state}
//	{otherwise: failed}
DllSpec
int FSPAPI Commit(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	return p->LockAndCommit(fp1);
}



// Return
//	Size of currently available free send buffer
int32_t LOCALAPI CSocketItemDl::AcquireSendBuf()
{
	if (! WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if(pendingSendBuf != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	void *buf = pControlBlock->InquireSendBuf(& pendingSendSize);
	bool b = (chainingSend || buf == NULL);
	SetMutexFree();
	return ((b || SelfNotify(FSP_NotifyBufferReady) >= 0) ? pendingSendSize : -EFAULT);
}



// Given
//	void *		the buffer pointer
//	int32_t		the number of octets to send
//	bool		whether to terminate the transmit transaction
// Return
//	positive if it is number of blocks scheduled to send
//	negative if it is the error number
// Remark
//	SendInplace works in tandem with AcquireSendBuf
int LOCALAPI CSocketItemDl::SendInplace(void * buffer, int32_t len, bool eot)
{
#ifdef TRACE
	printf_s("SendInplace in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(len <= 0)
		return -EDOM;

	if(! WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (eot && (InState(COMMITTING) || InState(COMMITTING2)))
		return -EBUSY;

	AddPollingTimer(TIMER_SLICE_ms);
	CheckTransmitaction(eot);
	bytesBuffered = 0;
	return FinalizeSend(PrepareToSend(buffer, len));
}



// Given
//	const void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
//	bool	whether to terminate the transmit transaction
// Return
//	Number of bytes put on the send queue
//	negative on error
// Remark
//	It is blocking if to commit the data but previous transaction commitment has not been acknowledged
int32_t LOCALAPI CSocketItemDl::SendStream(const void * buffer, int32_t len, bool eot, bool toCompress)
{
#ifdef TRACE
	printf_s("SendStream in state %s[%d], toCompress is %d\n"
		, stateNames[GetState()], GetState(), toCompress);
#endif
	int r;

	if(! WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (eot && (InState(COMMITTING) || InState(COMMITTING2)))
	{
		uint64_t t0 = GetTickCount64();
		do
		{
			SetMutexFree();
			Sleep(TIMER_SLICE_ms);
			if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
				return -EBUSY;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : -EINTR);
		} while (InState(COMMITTING) || InState(COMMITTING2));
	}

	CheckTransmitaction(eot);

	if(InterlockedCompareExchangePointer((PVOID *) & pendingSendBuf, (PVOID)buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;  
	}
	bytesBuffered = 0;

	if(toCompress && newTransaction && ! AllocStreamState())
	{
		SetMutexFree();
		return -ENOMEM;  
	}

	// By default it should be asynchronous:
	if (fpSent != NULL)
	{
		AddPollingTimer(TIMER_SLICE_ms);
		return FinalizeSend(BufferData(len));	// pendingSendSize = len;
	}

	// If it is blocking, wait until every byte has been put into the queue
	while ((r = BufferData(len)) >= 0)
	{
		if (r > 0
		 && !InState(CONNECT_AFFIRMING) && !InState(CHALLENGING) && !InState(CLONING)
		 && !Call<FSP_Send>())
		{
			r = -EIO;
			break;
		}
		//
		if (pendingSendSize <= 0)
			break;
		// Here wait LLS to free some send buffer block
		uint64_t t0 = GetTickCount64();
		do
		{
			SetMutexFree();
			Sleep(TIMER_SLICE_ms);
			if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
				return -EBUSY;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : -EINTR);
		} while (!HasFreeSendBuffer());
		//
		len = pendingSendSize;
	}
	pendingSendBuf = NULL;
	SetMutexFree();
	//
	if (r < 0)
		return r;

	return bytesBuffered;
}



// Internal API for committing/flushing a transmit transaction
// Try to commit current transmit transaction
int CSocketItemDl::LockAndCommit(NotifyOrReturn fp1)
{
	if (InterlockedCompareExchangePointer((PVOID *)& fpCommitted, fp1, NULL) != NULL)
	{
#if defined(TRACE) && !defined(NDEBUG)
		printf_s("Commit: the socket is already in commit or graceful shutdown process.\n");
#endif
		SetMutexFree();
		return -EAGAIN;
	}

	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (HasDataToCommit())
		MigrateToNewStateOnSend();
	//^In case returning prematurely in COMMITTED or CLOSABLE state

	if (InState(COMMITTED) || InState(CLOSABLE) || InState(PRE_CLOSED) || InState(CLOSED))
	{
		SetMutexFree();	// So that SelfNotify may call back instantly
		SelfNotify(FSP_NotifyFlushed);
		return 0;	// It is already in a state that the near end's last transmit transactio has been committed
	}

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
	if (!AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for Commit");
		SetMutexFree();
		return -EFAULT;
	}

	return Commit();
}



// Remark
//	Side-effect: may modify pendingSendSize and pendingSendBuf if WriteTo() is pending
//	may call back fpSent and clear the function pointer
//	Here we have assumed that the underlying binary system does not change
//	execution order of accessing volatile variables
// Assume it has taken exclusive access of the socket
// When FSP_NotifyFlushed was triggered the sender queue MUST be empty,
// When FSP_NotifyBufferReady was triggered the header packet of the sender queue SHALL be acknowledged
void CSocketItemDl::ProcessPendingSend()
{
#ifdef TRACE
	printf_s("Fiber#%u process pending send in %s\n", fidPair.source, stateNames[pControlBlock->state]);
#endif
	toIgnoreNextPoll = 1;
	// Set fpSent to NULL BEFORE calling back so that chained send may set new value
	CallbackBufferReady fp2 = (CallbackBufferReady)InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);
	if(pendingSendBuf != NULL || pStreamState != NULL)
	{
		if (HasDataToCommit())
		{
			int r = BufferData(pendingSendSize);
			if(r > 0)
				Call<FSP_Send>();
			//
			if(HasDataToCommit())
			{
				SetMutexFree();
				return;
			}
		}

		pendingSendBuf = NULL;
		SetMutexFree();
		//
		if(fp2 != NULL)
			((NotifyOrReturn)fp2)(this, FSP_Send, bytesBuffered);
		return;
	}

	// Or else it's pending GetSendBuffer()
	if(fp2 == NULL)
	{
		SetMutexFree();
		return;	// As there's no thread is waiting free send buffer
	}

	int32_t k = pControlBlock->CountSendBuffered();
	int32_t m;
	void *p = pControlBlock->InquireSendBuf(& m);
	if(p == NULL)
	{
		TestSetSendReturn(fp2);
		SetMutexFree();
		// BREAK_ON_DEBUG(); // race condition does exist, but shall be very rare!
		return;
	}
	chainingSend = 1;
	SetMutexFree();
	// If ULA hinted that sending was not finished yet, continue to use the saved pointer
	// of the callback function. However, if it happens to be updated, prefer the new one
	bool b = (fp2(this, p, m) >= 0);
	if(! WaitUseMutex())
		return;	// It could be disposed in the callback function.
	if (b)
		TestSetSendReturn(fp2);
	chainingSend = 0;
	// The callback function should consume at least one buffer block to avoid dead-loop
	b = b && (pControlBlock->CountSendBuffered() > k) && HasFreeSendBuffer();
	SetMutexFree();
	if(b)
		SelfNotify(FSP_NotifyBufferReady);
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
		return -EDOM;
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
			p->len += k;
			bytesBuffered += k;
			//
			m -= m2;
			pendingSendBuf += m2;
			p->SetFlag<Compressed>();
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
		skb0->Unlock();
		return 0;
	}
	//
	k = MAX_BLOCK_SIZE - p->len;	// To compress internally buffered: it may be that k == 0
	if(pendingSendSize != 0 || !committing)
	{
		skbImcompleteToSend = (k > 0 ? p : NULL);
		if(count > 0)
			goto l_finalize;
		// assert(p == skb0);
		p->Unlock();
		return 0;
	}
	// pendingSendSize == 0 && committing:
	skbImcompleteToSend = NULL;
	if (pStreamState == NULL)
	{
		p->SetFlag<TransactionEnded>();
		if(k > 0)
			count++;
		goto l_finalize;
	}
	// pStreamState != NULL, ie. To compress internal buffered
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
		p->len = k;
		p->SetFlag<Compressed>();
		count++;
		bytesBuffered += k;
	}	// end if the internal buffer of on-the-wire compression is not empty
	p->SetFlag<TransactionEnded>();
	FreeStreamState();
	//
l_finalize:
	if (_InterlockedCompareExchange8(&newTransaction, 0, 1) != 0)
	{
		p = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
#ifndef NDEBUG
		if (p != skb0)
			printf_s("Erroneous implementation!? May not start a new transaction\n");
		if (p->GetFlag<IS_SENT>())
			printf_s("Erroneous implementation!? Packet to start a new transaction locked but sent?\n");
#endif
		p->opCode = PERSIST;
		p->SetFlag<IS_COMPLETED>();	// Might be redundant, but it doesn't matter!
	}
	//
	MigrateToNewStateOnSend();
	//
	k = count;
	p = skb0;
	do
	{
		p->SetFlag<IS_COMPLETED>();
		p->Unlock();
#ifndef NDEBUG
		if (p->len < MAX_BLOCK_SIZE && !p->GetFlag<TransactionEnded>())
			printf_s("Erroneous implementation!? Length of a non-terminating packet is %d\n", p->len);
#endif
		if((++p - pControlBlock->HeadSend()) >= pControlBlock->sendBufferBlockN)
			p = pControlBlock->HeadSend();
	} while (--k > 0);
	//
	return count;
}



// Given
//	void *	the pointer to the in-place buffer to be marked in the send queue
//	int32_t	the size of the buffer in bytes
// Return
//	number of blocks split
//	-EFAULT if the first parameter is illegal
//	-ENOMEM if too larger size requested
//	-EDOM if the second or third parameter is illegal
// Remark
//	Would automatically mark the previous last packet as completed
int32_t LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int32_t len)
{
	if(len <= 0 || len % MAX_BLOCK_SIZE != 0 && !committing)
		return -EDOM;

	// Automatically mark the last unsent packet as completed. See also BufferData()
	if(skbImcompleteToSend != NULL)
	{
		skbImcompleteToSend->SetFlag<IS_COMPLETED>();
		skbImcompleteToSend->Unlock();
		skbImcompleteToSend = NULL;
	}

	int32_t m;
#ifndef NDEBUG
	void *bufToCheck = pControlBlock->InquireSendBuf(&m);
	if (bufToCheck != buf)
	{
		printf_s("The caller should not mess up the reserved the buffer space!\n");
		bufToCheck = pControlBlock->InquireSendBuf(&m);
	}
	if (m < len)
		return -ENOMEM;
#endif

	register ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	// p now is the descriptor of the first available buffer block
	m = (len - 1) / MAX_BLOCK_SIZE;

	register ControlBlock::PFSP_SocketBuf p0 = p;
	for(register int j = 0; j < m; j++)
	{
		p->InitFlags();	// and locked
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = MAX_BLOCK_SIZE;
		p->SetFlag<IS_COMPLETED>();
		p++;
	}
	//
	p->InitFlags();	// and locked
	p->version = THIS_FSP_VERSION;
	p->len = len - MAX_BLOCK_SIZE * m;
	p->opCode = PURE_DATA;
	p->SetFlag<TransactionEnded>(committing != 0);
	p->SetFlag<IS_COMPLETED>();
	//
	m++;
	pControlBlock->sendBufferNextPos += m;
	pControlBlock->RoundSendBufferNextPos();
	pControlBlock->sendBufferNextSN += m;

	MigrateToNewStateOnSend();

	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
		p0->opCode = PERSIST;
	// unlock them in a batch
	p = p0;
	for(register int j = 0; j < m; j++)
	{
		(p++)->Unlock();
	}

	return m;
}



// Remark
//	if(InState(CLONING) || InState(CONNECT_AFFIRMING) || InState(CHALLENGING))
//		return (NO_ERROR);	// Just prebuffer, data could be sent without state migration
//	// otherwise silently ignore
//	Because there may be race condition between LLS and DLL
//	we have to defer state transition until all packet has been put into the send queue
void CSocketItemDl::MigrateToNewStateOnSend()
{
	if(InState(ESTABLISHED))
	{
		if(committing)
		{
#ifdef TRACE
			printf_s("\nData requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
			SetState(COMMITTING);
		}
	}
	else if(InState(PEER_COMMIT))
	{
		if(committing)
		{
#ifdef TRACE
			printf_s("\nData requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
			SetState(COMMITTING2);
		}
	}
	else if (InState(COMMITTED))
	{
#ifdef TRACE
		printf_s("\nData requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		SetState(committing ? COMMITTING : ESTABLISHED);
	}
	else if (InState(CLOSABLE))
	{
#ifdef TRACE
		printf_s("\nData requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		SetState(committing ? COMMITTING2 : PEER_COMMIT);
	}
}



// Assume that it has obtained the mutex lock
// It is somewhat a little tricky to commit a transmit tranaction:
// Case 1, it is in sending a stream or obtaining send buffer, and there are yet some data to be buffered
// Case 2, the send queue is empty at all
// Case 3, there is set some block to be sent in the send queue
// Case 4, all blocks have been sent and the tail of the send queue has already been marked EOT
// Case 5, all blocks have been sent and the tail of the send queue could not set with EOT flag
// Remark
//	It is possible that a rogue ULA managed to call FSP_Send more frequently than fair share
//	However the LLS would prevent abnormally frequent FSP_Commit from abusing
int CSocketItemDl::Commit()
{
	committing = 1;

	// The last resort: flush sending stream if it has not yet been committed
	// Assume the caller has set time-out clock
	while (InState(COMMITTING) || InState(COMMITTING2))
	{
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
		if (!WaitUseMutex())
			return (IsInUse() ? -EDEADLK : 0);
	}

	if (!TestSetState(ESTABLISHED, COMMITTING) && !TestSetState(PEER_COMMIT, COMMITTING2))
	{
		RecycLocked();
		return -EDOM;
	}

	// flush internal buffer for compression, if it is non-empty
	bool yetSomeDataToBuffer = HasDataToCommit();
	if (yetSomeDataToBuffer && HasFreeSendBuffer())
	{
		BufferData(pendingSendSize);
		yetSomeDataToBuffer = HasDataToCommit();
		if (yetSomeDataToBuffer)
			Call<FSP_Send>();	// Or else FSP_Commit would trigger sending the queue
	}
	if (!yetSomeDataToBuffer && skbImcompleteToSend != NULL)
	{
		skbImcompleteToSend->SetFlag<TransactionEnded>();
		skbImcompleteToSend->Unlock();	// further processing is done on FSP_Commit
		skbImcompleteToSend = NULL;
	}

#ifndef _NO_LLS_CALLABLE
	// Case 1 is handled in DLL while case 2~5 are handled in LLS
	if (fpCommitted != NULL)
	{
		int r = yetSomeDataToBuffer ? 0 : (Call<FSP_Commit>() ? 0 : -EIO);
		SetMutexFree();
		return r;
	}

	// Or else it is in blocking mode:
	// Assume the caller has set time-out clock
	do
	{
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
		if (!WaitUseMutex())
			return (IsInUse() ? -EDEADLK : 0);
	} while (!InState(COMMITTED) && !InState(CLOSABLE) && !InState(CLOSED) && !InState(NON_EXISTENT));
#endif
	return 0;
}



// Urge LLS to send, even if the last packet is not fullly loaded.
int CSocketItemDl::Flush()
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	register ControlBlock::PFSP_SocketBuf p = skbImcompleteToSend;

	if (p == NULL)
	{
		SetMutexFree();
		return 0;
	}

	p->SetFlag<IS_COMPLETED>();
	skbImcompleteToSend = NULL;

	int r = Call<FSP_Send>() ? 0 : -EIO;
	SetMutexFree();
	return r;
}
