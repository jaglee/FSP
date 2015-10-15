/*
 * DLL to service FSP upper layer application
 * part of the SessionCtrl class, Send and Flush
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
//	FSPHANDLE	the socket handle
//	NotifyOrReturn	the pointer to the function called back when enough buffer available
// Return
//	Size of free send bufffe in bytes, 0 if no free, negative if error
DllExport
int FSPAPI GetSendBuffer(FSPHANDLE hFSPSocket, int m, CallbackBufferReady fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		// Invalid FSP handle: for sake of prebuffering only in a limited number of states sending is prehibited
		if (p->InState(NON_EXISTENT) || p->InState(LISTENING) || p->InState(PRE_CLOSED) || p->InState(CLOSED))
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
//	FlagEndOfMessage
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int len, FlagEndOfMessage eomFlag)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->SendInplace(buffer, len, eomFlag);
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
//	FlagEndOfMessage
//	NotifyOrReturn	the callback function pointer
// Return
//	0 if no immediate error, negative if it failed, or positive it was warned (I/O pending)
// Remark
//	Return value passed in NotifyOrReturn is the number of octets really scheduled to send
//	which may be less or greater than requested because of compression and/or encryption
//	Only all data have been buffered may be NotifyOrReturn called.
//	Choice of the flag:
//		0: not finshed more data to follow
//		1: it is the trail of the containing message
//		2: it is the last message of the session of the particular transmit direction
DllExport
int FSPAPI WriteTo(FSPHANDLE hFSPSocket, void * buffer, int len, FlagEndOfMessage flag, NotifyOrReturn fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(fp1 == NULL)
			return -EDOM;
		//
		if(!p->TestSetSendReturn(fp1))
			return -EBUSY;
		//
		int r = p->SendStream(buffer, len, flag);
		return (r < len ? E2BIG : 0);	// Error too BIG is a warning here, however
	}
	catch(...)
	{
		return -EFAULT;
	}
}




// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the callback function
// Return
//	EGAIN if the session is already in committed state
//	-EBADF if the connection is not in valid context
//	-EDOM if the connection is not in proper state
//	-EIO if the COMMIT packet cannot be sent
//	0 if no immediate error
// Remark
//	the callback function may return delayed error such as Commit rejected the remote end
//	The connection would remain in the COMMITTED, CLOSABLE or CLOSED state,
//	or be set to the COMMITTING or COMMITTING2 state immediately.
DllSpec
int FSPAPI Commit(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	TRACE_HERE("called");

	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if (p == NULL || p->IsIllegalState())
			return -EBADF;
		//
		if(p->InState(COMMITTED) || p->InState(CLOSABLE) || p->InState(PRE_CLOSED) || p->InState(CLOSED))
			return EAGAIN;	// warning that the socket has already been committed
		//
		if(! p->SetFlushing(fp1))
			return -EDOM;
		//
		return p->Commit();
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
		return -EINTR;

	if(pendingSendBuf != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	pendingSendSize = n;

	void *buf = pControlBlock->InquireSendBuf(n);
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
//	FlagEndOfMessage
// Return
//	number of octets really scheduled to send
// Remark
//	SendInplace works in tandem with AcquireSendBuf
//	This is a prototype and thus simultaneous send and receive is not considered
int LOCALAPI CSocketItemDl::SendInplace(void * buffer, int len, FlagEndOfMessage eomFlag)
{
#ifdef TRACE
	printf_s("SendInplace in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(! WaitUseMutex())
		return -EINTR;
	//
	int r = CheckedRevertToResume(eomFlag);
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}
	//
	return FinalizeSend(PrepareToSend(buffer, len, eomFlag));
}


// Given
//	void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
//	FlagEndOfMessage
// Return
//	Number of bytes put on the send queue
//	negative on error
// Remark
//	This is a prototype and thus simultaneous send and receive is not considered
int LOCALAPI CSocketItemDl::SendStream(void * buffer, int len, FlagEndOfMessage flag)
{
#ifdef TRACE
	printf_s("SendStream in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(! WaitUseMutex())
		return -EINTR;

	int r = CheckedRevertToResume(flag);
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}

	if(InterlockedCompareExchangePointer((PVOID *) & pendingSendBuf, buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EDEADLK;	//  EADDRINUSE
	}
	bytesBuffered = 0;
	eomSending = flag;

	return FinalizeSend(BufferData(len));	// pendingSendSize = len;
}



//[API: Commit]
//	{ACTIVE, RESUMING}-->COMMITTING-->[Urge COMMIT]
//	PEER_COMMIT-->COMMITTING2-->[Urge COMMIT]{restart keep-alive}
// Return
//	-EDOM if in erraneous state
//	-EINTR if cannot gain the exclusive lock
//	0 if no error
// Remark
//	Automatically terminate previous message, if any when called
int CSocketItemDl::Commit()
{
	//if(_InterlockedCompareExchange8(& eomSending, END_OF_SESSION, END_OF_MESSAGE) != END_OF_MESSAGE)
	//	return -EDOM;
	// UNRESOLVED! Is COMMIT a MUST?
	if(! WaitUseMutex())
	{
		TRACE_HERE("deadlock encountered? timed-out management?");
		return -EINTR;
	}

	if (InState(ESTABLISHED) || InState(RESUMING))
	{
		SetState(COMMITTING);
	}
	else if (InState(PEER_COMMIT))
	{
		SetState(COMMITTING2);
	}
	else if (!InState(COMMITTING) && !InState(COMMITTING2))
	{
		SetMutexFree();
		return -EDOM;
	}

	// If the last packet happened to have been sent by @LLS::EmitQ append a COMMIT and FSP_Urge would activate @LLS::EmitQ again 
	int r = pControlBlock->ReplaceSendQueueTailToCommit();
	if(r < 0)	// EmitQ() is busy and we count on it
		pControlBlock->shouldAppendCommit = 1;

	SetMutexFree();
	return (r == 0 ? (Call<FSP_Urge>() ? 0 : -EIO) : 0);
}



//[API: Send]
//	{ACTIVE, PEER_COMMIT}<-->[Send PURE_DATA]
//	{COMMITTED, CLOSABLE}-->RESUMING-->[Send RESUME]{enable retry}
//	{CONNECT_AFFIRMING, CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE}<-->{just prebuffer}
// Return
//	1 if revert to RESUMING state
//	0 if no state change
//	-EBADF if the operation is prohibited because the control block is in unrevertible state
//	-EBUSY if the control block is busy in committing a message
// UNRESOLVED! But if PERSIST hasn't been received before COMMIT is sent?
int LOCALAPI CSocketItemDl::CheckedRevertToResume(FlagEndOfMessage eomFlag)
{
	if(InState(CONNECT_AFFIRMING) || InState(CHALLENGING) || InState(CLONING) || InState(QUASI_ACTIVE) || InState(RESUMING))
		return  0;	// In these states data could be sent without state migration
	// TODO: But if to COMMIT a transaction in these states?

	if(InState(ESTABLISHED))
	{
		if(eomFlag == END_OF_TRANSACTION)
		{
			SetState(COMMITTING);
			SetFlushing(true);
		}
		return 0;
	}

	if(InState(PEER_COMMIT))
	{
		if(eomFlag == END_OF_TRANSACTION)
		{
			SetState(COMMITTING2);
			SetFlushing(true);
		}
		return 0;
	}

	if(InState(COMMITTING) || InState(COMMITTING2))
		return -EBUSY;

	if (InState(COMMITTED) && eomFlag == END_OF_TRANSACTION)
	{
		SetState(COMMITTING);
		SetFlushing(true);
		return 0;
	}

	if (InState(CLOSABLE) && eomFlag == END_OF_TRANSACTION)
	{
		SetState(COMMITTING2);
		SetFlushing(true);
		return 0;
	}

	// if (InState(NON_EXISTENT) || InState(LISTENING) || InState(CONNECT_BOOTSTRAP) || InState(PRE_CLOSED) || InState(CLOSED))
	if (!InState(COMMITTED) && !InState(CLOSABLE))
		return -EBADF;

#ifdef TRACE
	printf_s("Data requested to be sent in %s state. Migrate to RESUMING state\n", stateNames[GetState()]);
#endif
	pControlBlock->shouldAppendCommit = 0;	// just ignore it if the COMMIT packet has already been put into the send queue
	isFlushing = REVERT_TO_RESUME;
	SetState(RESUMING);
	return 1;
}




// Remark
//	Side-effect: may modify pendingSendSize and pendingSendBuf if WriteTo() is pending
//	may call back fpSent and clear the function pointer
//	Here we have assumed that the underlying binary system does not change
//	execution order of accessing volatile variables
void CSocketItemDl::ProcessPendingSend()
{
#ifdef TRACE_PACKET
	printf_s("Process pending send in state %s\n", stateNames[pControlBlock->state]);
#endif
	if(! WaitUseMutex())
	{
		TRACE_HERE("deadlock encountered!?");
		return;
	}
	// Assume it has taken exclusive access of the socket
	// WriteTo takes precedence over SendInline. In the contrast to RecvInline takes precedence over ReadFrom
	if(pendingSendBuf != NULL && pendingSendSize > 0)
	{
		BufferData(pendingSendSize);
		Call<FSP_Send>();
		if(pendingSendSize > 0)	// should be the norm
		{
			SetMutexFree();
			return;
		}
#if defined(_DEBUG)
		if (fpSent == NULL)
			TRACE_HERE("Internal panic!Lost way to report WriteTo result");
#endif
	}

	// Set fpSent to NULL BEFORE calling back so that chained send may set new value
	CallbackBufferReady fp2 = (CallbackBufferReady)InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);
	if (fp2 == NULL)
	{
		SetMutexFree();
		return;
	}

	if(pendingSendSize <= 0)	// pending WriteTo()
	{
		pendingSendBuf = NULL;	// So that WriteTo() chaining is possible, see also BufferData()
		SetMutexFree();
		((NotifyOrReturn)fp2)(this, FSP_Send, bytesBuffered);
		return;
	}
	//	if(pendingSendSize > 0)	// while pendingSendBuf == NULL
	int m = pendingSendSize;	// the size of the requested buffer
	int r = 0;
	void * p = pControlBlock->InquireSendBuf(m);
	if (m >= pendingSendSize)
	{
		SetMutexFree();
		r = fp2(this, p, m);
	}
	else if (pControlBlock->CountSendBuffered() == 0)
	{
		int n = pControlBlock->ResetSendWindow();
		SetMutexFree();
		r = fp2(this, pControlBlock->GetSendPtr(pControlBlock->HeadSend()), MAX_BLOCK_SIZE * n);
	}
	else
	{
		SetMutexFree();
	}
	// ULA hints that sent was not finished sent yet. Continue to use the saved function pointer as the callback handle
	if (r == 0)
		TestSetSendReturn(fp2);
}


// Given
//	int &	[_In_] length of data in pendingSendBuf to send [_Out_] length of data scheduled to send
// Return
//	number of bytes buffered in the send queue
// TODO: encryption and/or compression
int LOCALAPI CSocketItemDl::BufferData(int len)
{
	ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	// UNRESOLVED!milky-payload: apply FIFD instead of FIFO
	int m = len;
	if (m <= 0)
		return -EDOM;
	//
	// pack the byte stream, TODO: compression
	if(p != NULL && !p->GetFlag<IS_COMPLETED>())
	{
#ifdef TRACE
		printf_s("BufferData: assert(p->GetFlag<TO_BE_CONTINUED>() && p->len < MAX_BLOCK_SIZE || p->opCode == PERSIST && p->len == 0)");
#endif
#ifndef NDEBUG
		if (p->len < 0 || p->len >= MAX_BLOCK_SIZE)
		{
			printf_s("Internal panic! Length of an incomplete packet is %d, while requested BUfferData len is %d?\n", p->len, m);
			return 0;
		}
#endif
		int k = min(m, MAX_BLOCK_SIZE - p->len);
		memcpy(GetSendPtr(p) + p->len, pendingSendBuf, k);
		m -= k;
		p->len += k;
		pendingSendBuf += k;
		if(p->len >= MAX_BLOCK_SIZE)
		{
			p->SetFlag<IS_COMPLETED>();
			p->Unlock();
		}
		//
		if (m == 0)
		{
			p->Unlock();// it should be redundant but do little harm
			goto l_finish;
		}
	}
	else if(p != NULL)	// && p->GetFlag<IS_COMPLETED>()
	{
		p->Unlock();
	}

	ControlBlock::PFSP_SocketBuf p0 = p = GetSendBuf();
	// p->buf was set when the send buffer control structure itself was initialized
	// flags are already initialized when GetSendBuf
	while(p != NULL)
	{
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = min(m, MAX_BLOCK_SIZE);
		m -= p->len;
		memcpy(GetSendPtr(p), pendingSendBuf, p->len);
		// TODO: Compress
		// TODO: Encrypt
		bytesBuffered += p->len;

		p->SetFlag<TO_BE_CONTINUED>();
		if(p->len >= MAX_BLOCK_SIZE)
		{
			p->SetFlag<IS_COMPLETED>();
			p->Unlock();
		}
		if (m <= 0)
			break;
		//
		pendingSendBuf += MAX_BLOCK_SIZE;
		p = GetSendBuf();
	}

	p = p0;
	//
l_finish:
	if(_InterlockedCompareExchange8(& isFlushing, 0, REVERT_TO_RESUME) == REVERT_TO_RESUME)
		p->opCode = RESUME;
	//
	pendingSendSize = m;
	// 	Depending on eomSending flag and the state set the last packet
	if (pendingSendSize == 0)
	{
		if (eomSending == FlagEndOfMessage::END_OF_MESSAGE)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
			p->Unlock();
		}
		else if (eomSending == FlagEndOfMessage::END_OF_TRANSACTION)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
			p->opCode = COMMIT;
			p->Unlock();
		}
		// otherwise WriteTo following may put further data into the last packet buffer
	}
	//
	return (len - m);
}



// Given
//	void *	the pointer to the in-place buffer to be marked in the send queue
//	int		the size of the buffer in bytes
//	FlagEndOfMessage
// Return
//	number of blocks split
//	-EFAULT if the first parameter is illegal
//	-ENOMEM if too larger size requested
//	-EDOM if the second or third parameter is illegal
// Remark
//	Would automatically mark the previous last packet as completed
int LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int len, FlagEndOfMessage eomFlag)
{
	if(len <= 0 || len % MAX_BLOCK_SIZE != 0 && eomFlag == NOT_END_ANYWAY)
		return -EDOM;

	// Automatically mark the last unsent packet as completed. See also BufferData()
	ControlBlock::PFSP_SocketBuf skb0 = pControlBlock->LockLastBufferedSend();
	if (skb0 != NULL)
	{
#ifdef TRACE
		printf_s("SendInline automatically closes previous packet sent by WriteTo() or implicit welcome\n");
#endif
		skb0->SetFlag<IS_COMPLETED>();	// TO_BE_CONTINUED, if any, is kept, however
		//^it might be redundant, but do little harm
		skb0->Unlock();
	}

	register int m = len;
	if(pControlBlock->InquireSendBuf(m) != buf)	// 'm' is an in-out parameter
		return -EFAULT;
	if(m < len)
		return -ENOMEM;
	// assert(pControlBlock->sendBufferNextPos == ((BYTE *)buf - (BYTE *)this - pControlBlock->sendBuffer) / MAX_BLOCK_SIZE);

	skb0 = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	register ControlBlock::PFSP_SocketBuf p = skb0;
	// p now is the descriptor of the first available buffer block
	m = (len - 1) / MAX_BLOCK_SIZE;
	for(int j = 0; j < m; j++)
	{
		p->InitFlags();	// and locked
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = MAX_BLOCK_SIZE;
		p->SetFlag<TO_BE_CONTINUED>();
		p->SetFlag<IS_COMPLETED>();
		p->Unlock();	// so it could be send
		p++;
	}
	//
	eomSending = eomFlag;
	p->InitFlags();	// and locked
	p->version = THIS_FSP_VERSION;
	p->len = len - MAX_BLOCK_SIZE * m;
	p->opCode = (eomFlag == END_OF_TRANSACTION ? COMMIT : PURE_DATA);
	p->SetFlag<TO_BE_CONTINUED>(eomFlag == NOT_END_ANYWAY);
	p->SetFlag<IS_COMPLETED>();
	p->Unlock();
	//
	pControlBlock->sendBufferNextPos += m + 1;
	pControlBlock->sendBufferNextSN += m + 1;
	pControlBlock->RoundSendBufferNextPos();

	if(_InterlockedCompareExchange8(& isFlushing, 0, REVERT_TO_RESUME) == REVERT_TO_RESUME && skb0->opCode != COMMIT)
		skb0->opCode = RESUME;

	return (m + 1);
}
