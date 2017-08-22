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
//	int					buffer size requested
//	CallbackBufferReady	the pointer to the function called back when enough buffer available
// Return
//	size of free send buffer available immediately, might be 0 which is not an error
//	negative if exception has arisen
DllExport
int FSPAPI GetSendBuffer(FSPHANDLE hFSPSocket, int m, CallbackBufferReady fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		// Invalid FSP handle: for sake of pre-buffering only in a limited number of states sending is prohibited
		if (p->InIllegalState() || p->InState(LISTENING) || p->InState(PRE_CLOSED) || p->InState(CLOSED))
			return -EBADF;
		if (!p->TestSetSendReturn(fp1))
			return -EBUSY;
		return p->AcquireSendBuf(m);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	bool		whether to terminate the transmit transaction
// Return
//	number of octets really scheduled to send
// Remark
//	SendInline is typically chained in tandem with GetSendBuffer
//	The buffer MUST begin from what the callback function of GetSendBuffer has returned and
//	may not exceed the capacity that the callback function of GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int len, bool eotFlag)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->SendInplace(buffer, len, eotFlag);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Given
//	FSPHANDLE	the socket handle
//	const void *the buffer pointer
//	int			the number of octets to send
//	int8_t		the send options
//	NotifyOrReturn	the callback function pointer
// Return
//	non-negative if it is the number of octets put into the queue immediately. might be 0 of course.
//	-EBUSY if previous asynchronous Write operation has not completed
//	-EFAULT if some ridiculous exception has arised
//	-EDEADLK if it cannot obtain mutual exclusive lock
//	-EBADF if the socket is in unknown state
//	-EADDRINUSE if previous blocking Write operation has not completed
//	-EIO if immediate sending operation failed
// Remark
//	Only all data have been buffered may be NotifyOrReturn called.
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until every octet in the given buffer has been passed to LLS. See also ReadFrom
DllExport
int FSPAPI WriteTo(FSPHANDLE hFSPSocket, const void * buffer, int len, int8_t flags, NotifyOrReturn fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(!p->TestSetSendReturn(fp1))
			return -EBUSY;
		//
		return p->SendStream(buffer, len, (flags & TO_END_TRANSACTION) != 0, (flags & TO_COMPRESS_STREAM) != 0);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Return
//	Size of currently available free send buffer
int LOCALAPI CSocketItemDl::AcquireSendBuf(int n)
{
	if (n <= 0)
		return -EDOM;
	if (! WaitUseMutex())
		return -EDEADLK;

	if(pendingSendBuf != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	pendingSendSize = n;
	n = 1;
	void *buf = pControlBlock->InquireSendBuf(& n);
	SetMutexFree();
	if(buf != NULL)
	{
		int r = SelfNotify(FSP_NotifyBufferReady);
		if(r < 0)
			return -EFAULT;
	}

	return n;
}



// Given
//	void *		the buffer pointer
//	int			the number of octets to send
//	bool		whether to terminate the transmit transaction
// Return
//	number of octets really scheduled to send
// Remark
//	SendInplace works in tandem with AcquireSendBuf
//	This is a prototype and thus simultaneous send and receive is not considered
int LOCALAPI CSocketItemDl::SendInplace(void * buffer, int len, bool eot)
{
#ifdef TRACE
	printf_s("SendInplace in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(! WaitUseMutex())
		return -EDEADLK;
	//
	int r = CheckTransmitaction(eot);
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}
	//
	bytesBuffered = 0;
	return FinalizeSend(PrepareToSend(buffer, len, eot));
}



// Given
//	const void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
//	bool	whether to terminate the transmit transaction
// Return
//	Number of bytes put on the send queue
//	negative on error
// Remark
//	This is a prototype and thus simultaneous send and receive is not considered
int LOCALAPI CSocketItemDl::SendStream(const void * buffer, int len, bool eot, bool toCompress)
{
#ifdef TRACE
	printf_s("SendStream in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(! WaitUseMutex())
		return -EDEADLK;

	int r = CheckTransmitaction(eot);
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}

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
		return FinalizeSend(BufferData(len));	// pendingSendSize = len;

	// If it is blocking, wait until every byte has been put into the queue
	uint64_t t0 = GetTickCount64();
	while ((r = BufferData(len)) >= 0)
	{
		if (!InState(CONNECT_AFFIRMING) && !InState(CHALLENGING) && !InState(CLONING)
		 && !Call<FSP_Send>())
		{
			r = -EIO;
			break;
		}
		//
		if (!HasPendingSend())
			break;
		// Here wait LLS to free some send buffer block
		do
		{
			SetMutexFree();
			Sleep(50);
			if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
				return -EDEADLK;
			if (!WaitUseMutex())
				return -EDEADLK;
		} while (!HasFreeSendBuffer());
		//
		len = pendingSendSize;
	}
	pendingSendBuf = NULL;
	SetMutexFree();
	//
	if (r < 0)
		return r;
	//
	return bytesBuffered;
}



/**
	An ACK_CONNECT_REQ packet itself make a singular transmit transaction.
	A PERSIST or MULTIPLY packet always starts a transmit transaction.
	A PERSIST or MULTIPLY packet with 'To Be Continued' flag cleared terminates the transmit transaction as well.
 */
// Return
//	1 if revert to ACTIVE or PEER_COMMIT state
//	0 if no state reversion
//	-EBADF if the operation is prohibited because the control block is in irreversible state
//	-EBUSY if the control block is busy in committing a message
// Remark
//	You may not send further packet when a transmit transaction commitment is pending
//	It MIGHT change state in the ESTABLISHED state
//	It may change indication 'isFlushing' as well
//	See also FinalizeSend()
int LOCALAPI CSocketItemDl::CheckTransmitaction(bool eotFlag)
{
	if(InState(COMMITTING) || InState(COMMITTING2))
		return -EBUSY;

	if(eotFlag)
		SetEndTransaction();

	if(InState(CLONING) || InState(CONNECT_AFFIRMING) || InState(CHALLENGING))
		return 0;	// Just prebuffer, data could be sent without state migration

	if(InState(ESTABLISHED))
	{
		if(isFlushing)
			SetState(COMMITTING);
		return 0;
	}

	if(InState(PEER_COMMIT))
	{
		if(isFlushing)
			SetState(COMMITTING2);
		return 0;
	}

	if (InState(COMMITTED))
	{
#ifdef TRACE
		printf_s("Data requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		if(isFlushing)
		{
			SetState(COMMITTING);
		}
		else
		{
			SetState(ESTABLISHED);
			newTransaction = 1;	// isFlushing = 0; // SetNewTransaction();
		}
		return 1;
	}

	if (InState(CLOSABLE))
	{
#ifdef TRACE
		printf_s("\nData requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		if(isFlushing)
		{
			SetState(COMMITTING2);
		}
		else
		{
			SetState(PEER_COMMIT);
			newTransaction = 1;	// isFlushing = 0; // SetNewTransaction();
		}
		return 1;
	}

	return -EBADF;
}



// Remark
//	Side-effect: may modify pendingSendSize and pendingSendBuf if WriteTo() is pending
//	may call back fpSent and clear the function pointer
//	Here we have assumed that the underlying binary system does not change
//	execution order of accessing volatile variables
void CSocketItemDl::ProcessPendingSend()
{
#ifdef TRACE
	printf_s("Fiber#%u process pending send in %s\n", fidPair.source, stateNames[pControlBlock->state]);
#endif
	// Assume it has taken exclusive access of the socket
	// Set fpSent to NULL BEFORE calling back so that chained send may set new value
	CallbackBufferReady fp2 = (CallbackBufferReady)InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);

	// pending GetSendBuffere()
	if (pendingSendBuf == NULL)
	{
		if(fp2 == NULL)
		{
			SetMutexFree();
			return;	// As there's no thread is waiting free send buffer
		}
		//
		if(pendingSendSize <= 0)
		{
			SetMutexFree();
#ifdef _DEBUG
			printf_s("Waiting for a null buffer? It should not have happened!\n");
#endif
			fp2(this, NULL, 0);
			return;
		}
		//
		int m = 1;				// minimum block works perfect
		void * p = pControlBlock->InquireSendBuf(& m);
		SetMutexFree();
		// If FSP_NotifyBufferReady caught but even a minimal buffer block is unavailable,
		// it must be in chaotic memory situation. However, race condition does exist.
		if(p == NULL)
		{
			TestSetSendReturn(fp2);
			BREAK_ON_DEBUG();
			if(HasFreeSendBuffer())
				SelfNotify(FSP_NotifyBufferReady);
			return;
		}
		// If ULA hinted that sending was not finished yet,
		// continue to use the saved pointer of the callback function
		bool r = (pendingSendSize - m > 0);
		if (fp2(this, p, m) >= 0 || r)
		{
			pendingSendSize = (pendingSendSize - m > 0 ? pendingSendSize - m : 0);
			TestSetSendReturn(fp2);
			if(HasFreeSendBuffer())	// In case of round-robin
				SelfNotify(FSP_NotifyBufferReady);
		}
		//
		return;
	}

	// Now pendingSendBuf != NULL, pending WriteTo(), or pending Commit()
	if (HasPendingSend())
	{
		BufferData(pendingSendSize);
		Call<FSP_Send>();
		if(HasPendingSend())
		{
			SetMutexFree();
			return;
		}
		//
#ifdef _DEBUG
		if (fpSent == NULL)
			printf_s("\nInternal panic! Lost way to report WriteTo result\n");
#endif
	}

	void *p = InterlockedExchangePointer((PVOID *)& pendingSendBuf, NULL);	// So that WriteTo() chaining is possible, see also BufferData()
	SetMutexFree();
	//
	if(p != NULL && fp2 != NULL)
		((NotifyOrReturn)fp2)(this, FSP_Send, bytesBuffered);
	// Or else SendInplace silently finished.
}



// Given
//	int		number of octets in pendingSendBuf to put into the send queue
// Return
//	number of bytes buffered in the send queue
// Remark
//	If len == 0, it meant to flush the compression buffer, if any
//	Side-effect:
//	set the value of pendingSendSize to number of octets yet to be buffered
//	set the value of pendingStreamingSize to number of compression result octets yet to be queued
// Compression on the wire is co-routing
int LOCALAPI CSocketItemDl::BufferData(int len)
{
	int m = len;
	if (m < 0)
		return -EDOM;
	if (m == 0 && pStreamState == NULL)
		return 0;

	ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	if(p != NULL && !p->GetFlag<IS_COMPLETED>())
	{
		if (p->len < 0 || p->len >= MAX_BLOCK_SIZE)
			return -EFAULT;
		//
		octet *tgtBuf = GetSendPtr(p) + p->len;
		//
		if(pStreamState == NULL)
		{
			int k = min(m, MAX_BLOCK_SIZE - p->len);
			memcpy(tgtBuf, pendingSendBuf, k);
			m -= k;
			p->len += k;
			bytesBuffered += k;
			pendingSendBuf += k;
		}
		else
		{
			int k = MAX_BLOCK_SIZE - p->len;
			int m2 = Compress(tgtBuf, k, pendingSendBuf, m);
			if(m2 < 0)
				return m2;
			m -= m2;
			p->len += k;
			bytesBuffered += k;
			pendingSendBuf += m2;
		}
		//
		if(p->len >= MAX_BLOCK_SIZE)
			p->SetFlag<IS_COMPLETED>();
		else
			goto l_finish;	// assert: m == 0
		//
		if (m == 0)
			goto l_finish;	// it is full, and it happens to be the last packet in this batch
		//
		p->Unlock();
	}
	else if(p != NULL)	// && p->GetFlag<IS_COMPLETED>()
	{
		p->Unlock();
	}

	p = GetSendBuf();
	// p->buf was set when the send buffer control structure itself was initialized
	// flags are already initialized when GetSendBuf
	while(p != NULL)
	{
		octet *tgtBuf = GetSendPtr(p);
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		if(pStreamState == NULL)
		{
			p->len = min(m, MAX_BLOCK_SIZE);
			memcpy(tgtBuf, pendingSendBuf, p->len);
			m -= p->len;
			bytesBuffered += p->len;
			pendingSendBuf += p->len;
		}
		else
		{
			int k = MAX_BLOCK_SIZE;
			int m2 = Compress(tgtBuf, k, pendingSendBuf, m);
			if(m2 < 0)
				return m2;
			m -= m2;
			p->len = k;
			bytesBuffered += k;
			pendingSendBuf += m2;
			p->SetFlag<Compressed>();
			// assert: if k == 0 then n == 0
		}
		if(p->len >= MAX_BLOCK_SIZE)
			p->SetFlag<IS_COMPLETED>();
		//
		if (m <= 0)
			break;
		//
		p->Unlock();
		p = GetSendBuf();
	}

l_finish:
	// It somewhat overlaps with checking isFlushing, i.e. there is some redundancy, but it keeps code simple
	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
	{
		ControlBlock::PFSP_SocketBuf skb0 = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
#ifdef TRACE
		if(skb0->GetFlag<IS_SENT>())
			printf_s("Erroneous implementation!? May not start a new transaction");
#endif
		skb0->opCode = PERSIST;
	}

	pendingSendSize = m;
	//
	if(p == NULL)
		return (len - m);
	//
	if(pendingSendSize != 0 || !isFlushing)
	{
		p->Unlock();
		return (len - m);
	}
	// only after every field, including flag, has been set may it be unlocked
	// otherwise WriteTo following may put further data into the last packet buffer
	if(pStreamState == NULL)
	{
		p->SetFlag<TransactionEnded>();
		p->SetFlag<IS_COMPLETED>();
		p->Unlock();
		return (len - m);
	}

	int k = MAX_BLOCK_SIZE - p->len;	// To compress internally buffered: it may be that k == 0
	Compress(GetSendPtr(p) + p->len, k, NULL, 0);
	p->len += k;
	p->SetFlag<IS_COMPLETED>();
	bytesBuffered += k;
	while(pendingStreamingSize > 0)
	{
		p->Unlock();	// only after every field, including flag, has been set may it be unlocked
		p = GetSendBuf();
		if(p == NULL)
			return (len - m);	// Warning: not all data have been buffered
		//
		k = MAX_BLOCK_SIZE;			// To copy out internally compressed:
		Compress(GetSendPtr(p), k, NULL, 0);
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = k;
		p->SetFlag<Compressed>();
		p->SetFlag<IS_COMPLETED>();
		bytesBuffered += k;
	}	// end if the internal buffer of on-the-wire compression is not empty
	//
	p->SetFlag<TransactionEnded>();
	p->Unlock();
	FreeStreamState();
	return (len - m);
}



// Given
//	void *	the pointer to the in-place buffer to be marked in the send queue
//	int		the size of the buffer in bytes
//	bool	whether to terminate the transmit transaction
// Return
//	number of blocks split
//	-EFAULT if the first parameter is illegal
//	-ENOMEM if too larger size requested
//	-EDOM if the second or third parameter is illegal
// Remark
//	Would automatically mark the previous last packet as completed
int LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int len, bool eotFlag)
{
	if(len <= 0 || len % MAX_BLOCK_SIZE != 0 && ! eotFlag)
		return -EDOM;

	// Automatically mark the last unsent packet as completed. See also BufferData()
	register ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	if(p != NULL)
	{
		p->SetFlag<IS_COMPLETED>();
		//^it might be redundant, but do little harm
		p->Unlock();
	}

	int m = len;
	if(pControlBlock->InquireSendBuf(& m) != buf)	// 'm' is an in-out parameter
		return -EFAULT;
	if(m < len)
		return -ENOMEM;

	p = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
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
	p->SetFlag<IS_COMPLETED>();
	p->SetFlag<TransactionEnded>(eotFlag);
	//
	pControlBlock->sendBufferNextPos += m + 1;
	pControlBlock->RoundSendBufferNextPos();
	pControlBlock->sendBufferNextSN += m + 1;

	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
		p0->opCode = PERSIST;
	// unlock them in a batch
	p = p0;
	for(register int j = 0; j <= m; j++)
	{
		(p++)->Unlock();
	}

	return (m + 1);
}
