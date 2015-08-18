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
//	bool		whether it is to be continued
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int len, bool toBeContinued)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->SendInplace(buffer, len, toBeContinued);
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
//	short		the flags to indicate whether it is transactional
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
int FSPAPI WriteTo(FSPHANDLE hFSPSocket, void * buffer, int len, char flag, NotifyOrReturn fp1)
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
	if(pendingSendBuf != NULL)
		return -EBUSY;
	if (n <= 0)
		return -EDOM;
	pendingSendSize = n;

	void *buf = pControlBlock->InquireSendBuf(n);

	if(buf != NULL && SelfNotify(FSP_NotifyBufferReady) < 0)
	{
		TRACE_HERE("cannot generate the soft interrupt?");
		return -EFAULT;
	}

	return n;
}


//[API: Send]
//	{ACTIVE, PEER_COMMIT}<-->[Send PURE_DATA]
//	{COMMITTING, COMMITTING2, COMMITTED}-->RESUMING-->[Send RESUME]
//	CLOSABLE-->RESUMING-->[Send RESUME]{enable retry}
//	{CONNECT_AFFIRMING, CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE}<-->{just prebuffer}
// Given
//	void *		the buffer pointer
//	int			the number of octets to send
//	bool		whether it is to be continued
// Return
//	number of octets really scheduled to send
// Remark
//	SendInplace works in tandem with AcquireSendBuf
int LOCALAPI CSocketItemDl::SendInplace(void * buffer, int len, bool toBeContinued)
{
#ifdef TRACE
	printf_s("SendInplace in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if (!WaitSetMutex())
		return -EINTR;	// UNRESOLVED!Simultaneous one send and one receive shall be allowed!
	//
	int r = CheckedRevertToResume();
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}
	//
	return FinalizeSend(PrepareToSend(buffer, len, toBeContinued));
}


//[API: Send]
//	{ACTIVE, PEER_COMMIT}<-->[Send PURE_DATA]
//	{COMMITTING, COMMITTING2, COMMITTED}-->RESUMING-->[Send RESUME]
//	CLOSABLE-->RESUMING-->[Send RESUME]{enable retry}
//	{CONNECT_AFFIRMING, CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE}<-->{just prebuffer}
// Given
//	void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
// Return
//	Number of bytes put on the send queue
//	negative on error
// TODO: buffer data for transactional transfer
int LOCALAPI CSocketItemDl::SendStream(void * buffer, int len, char flag)
{
#ifdef TRACE
	printf_s("SendStream in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(!WaitSetMutex())
		return -EINTR;	// UNRESOLVED!Simultaneous one send and one receive shall be allowed!

	int r = CheckedRevertToResume();
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
//	-EINTR if cannot gain the exclusive lock
//	-EDOM if in erraneous state
//	-ETIMEDOUT if blocked due to lack of buffer 
// Remark
//	It might be blocking to wait the send buffer slot to buffer the COMMIT packet
int CSocketItemDl::Commit()
{
	eomSending = EndOfMessageFlag::END_OF_SESSION;
	//
	if(! WaitSetMutex())
		return -EINTR;

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

	if(AppendCommit() == NULL)
	{
		SetMutexFree();
		return -ETIMEDOUT;
	}

	SetMutexFree();
	return (Call<FSP_Urge>() ? 0 : -EIO);
}



// Append the COMMIT packet to the end of the message in the send queue.
ControlBlock::PFSP_SocketBuf CSocketItemDl::AppendCommit()
{
	//
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->LockLastBufferedSend();
	if(skb != NULL)
	{
		if(skb->opCode == PURE_DATA || skb->opCode == PERSIST)
		{
			skb->SetFlag<TO_BE_CONTINUED>(false);
		}
		else if(skb->opCode != COMMIT)
		{
			skb->Unlock();
			skb = NULL;
		}
	}
	// allocate new slot to hold the COMMIT packet
	if(skb == NULL)
	{
		time_t t0 = time(NULL);
		while((skb = pControlBlock->GetSendBuf()) == NULL)
		{
			SetMutexFree();
			Sleep(1);
			if(time(NULL) - t0 > TRASIENT_STATE_TIMEOUT_ms)
				return NULL;
			if(! WaitSetMutex())
				return NULL;
		}
		skb->len = 0;
	}
	// UNRESOLVED! The IS_COMPLETED flag of COMMIT is reused for accumulative acknowledgment?
	skb->opCode = COMMIT;
	skb->SetFlag<IS_COMPLETED>();
	//
	skb->Unlock();
	return skb;
}




// Return
//	-ENOENT	if no buffer entry for the COMMIT packet (fatal error!)
//	0		if no error
// Remark
//	It is non-blocking unlike AppendCommit()
int CSocketItemDl::CommitSendQueue()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->LockLastBufferedSend();
	if(skb != NULL)
	{
		// skb->SetFlag<TO_BE_CONTINUED>(false); skb->SetFlag<IS_COMPLETED>();
		if(skb->opCode == COMMIT)
		{			
			skb->Unlock();
			return 0;
		}

		if(skb->opCode != PURE_DATA && skb->opCode != PERSIST)
		{
			skb->Unlock();
			skb = NULL;
		}
		// or else the packet is to be replaced and terminating
	}

	if(skb == NULL)
	{
		if((skb = pControlBlock->GetSendBuf()) == NULL)
			return -ENOENT;
		//
		skb->len = 0;
	}
	//
	skb->SetFlag<TO_BE_CONTINUED>(false);
	skb->SetFlag<IS_COMPLETED>();
	skb->opCode = COMMIT;
	//
	skb->Unlock();
	return 0;
}



// Return
//	1 if revert to RESUMING state
//	0 if no state change
//	-EBADF if the operation is prohibited because the control block is in unrevertible state
//	-EBUSY if the control block is busy in committing a message
int CSocketItemDl::CheckedRevertToResume()
{
	if(InState(CONNECT_AFFIRMING) || InState(CHALLENGING) || InState(CLONING) || InState(QUASI_ACTIVE)
	|| InState(RESUMING) || InState(ESTABLISHED) || InState(PEER_COMMIT))
	// In these states data could be sent without state migration
	{
		return 0;
	}

	if(InState(COMMITTING) || InState(COMMITTING2))
		return -EBUSY;

	// if (InState(NON_EXISTENT) || InState(LISTENING) || InState(CONNECT_BOOTSTRAP) || InState(PRE_CLOSED) || InState(CLOSED))
	if (!InState(COMMITTED) && !InState(CLOSABLE))
		return -EBADF;

#ifdef TRACE
	printf_s("Data requested to be sent in %s state. Migrate to RESUMING state\n", stateNames[GetState()]);
#endif
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

	//	SetMutexFree() is splitted because of calling back
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
	// pack the byte stream, TODO: encryption and compression
	if(p != NULL && !p->GetFlag<IS_COMPLETED>())
	{
#ifdef TRACE
		printf_s("BufferData: assert(p->GetFlag<TO_BE_CONTINUED>() && p->len < MAX_BLOCK_SIZE || p->opCode == PERSIST && p->len == 0)");
#endif
#ifndef NDEBUG
		if (p->len < 0 || p->len >= MAX_BLOCK_SIZE)
		{
			printf_s("Internal panic!Length of an incomplete packet is %d, while requested BUfferData len is %d?\n", p->len, m);
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

	if(_InterlockedCompareExchange8(& isFlushing, 0, REVERT_TO_RESUME) == REVERT_TO_RESUME)
		p0->opCode = RESUME;

l_finish:
	pendingSendSize = m;
	// 	Depending on eomSending flag and the state set the last packet
	if (pendingSendSize == 0)
	{
		if (eomSending == EndOfMessageFlag::END_OF_MESSAGE)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
			p->Unlock();
		}
		else if (eomSending == EndOfMessageFlag::END_OF_SESSION)
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
//	bool	whether there would be further data in the message
// Return
//	number of blocks split
//	-EFAULT if the first parameter is illegal
//	-ENOMEM if too larger size requested
//	-EDOM if the second or third parameter is illegal
// Remark
//	Would automatically mark the previous last packet as completed
int LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int len, bool toBeContinued)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->LockLastBufferedSend();
	// Automatically mark the previous last packet as completed. See also BufferData()
	if (skb != NULL)
	{
#ifdef TRACE
		printf_s("SendInline automatically closed previous message sent by WriteTo() or implicit welcome\n");
#endif
		skb->SetFlag<TO_BE_CONTINUED>(false);
		skb->SetFlag<IS_COMPLETED>();
		skb->Unlock();
		//^it might be redundant, but did little harm
	}

	skb = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	int r = pControlBlock->MarkSendQueue(buf, len, toBeContinued);
	if (r < 0)
	{
#ifdef TRACE
		printf_s("\nMarkSendQueue 0x%08X, len = %d, toBeContinued = %d, returned %d\n", (LONG)buf, len, (int)toBeContinued, r);
#endif
		return r;
	}

	if(_InterlockedCompareExchange8(& isFlushing, 0, REVERT_TO_RESUME) == REVERT_TO_RESUME)
		skb->opCode = RESUME;

	return r;
}
