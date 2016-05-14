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
	int r = CheckCommitOrRevert(eomFlag);
	if (r < 0)
	{
		SetMutexFree();
		return -EBADF;
	}
	//
	bytesBuffered = 0;
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

	int r = CheckCommitOrRevert(flag);
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

	return FinalizeSend(BufferData(len));	// pendingSendSize = len;
}



//[API: Send]
//	CLONING<-->[Send PERSIST]{enable retry}
//	ACTIVE<-->[Send{more data}]
//	ACTIVE-->[Send flush]-->COMMITTING
//	PEER_COMMIT<-->[Send{more data}]
//	PEER_COMMIT-->[Send{flush}]-->COMMITTING2{enable retry}
//	COMMITTED-->ACTIVE-->[Send PERSIST]
//	COMMITTED-->[Send{flush}]-->COMMITTING
//	CLOSABLE-->PEER_COMMIT-->[Send PERSIST]{enable retry}
//	CLOSABLE-->[Send{flush}]-->COMMITTING2{enable retry}
// Return
//	1 if revert to ACTIVE or PEER_COMMIT state
//	0 if no state change
//	-EBADF if the operation is prohibited because the control block is in unrevertible state
//	-EBUSY if the control block is busy in committing a message
// Remark
//	You may not send further packet when a transmit transaction commitment is pending
//	It MIGHT change state in the ESTABLISHED state
//	It may change indication 'isFlushing' as well
//	See also FinalizeSend()
int LOCALAPI CSocketItemDl::CheckCommitOrRevert(FlagEndOfMessage flag)
{
	if(pControlBlock->hasPendingKey != 0)
		flag = END_OF_TRANSACTION;
	//
	if (isFlushing == 0 && flag == END_OF_MESSAGE)
		isFlushing = END_MESSAGE_ONLY;
	else if (flag == END_OF_TRANSACTION && isFlushing != FLUSHING_SHUTDOWN)
		isFlushing = FLUSHING_COMMIT;

	if(InState(CLONING) || InState(CONNECT_AFFIRMING) || InState(CHALLENGING))
		return 0;	// Just prebuffer, data could be sent without state migration

	if (shouldAppendCommit != 0)
		return -EBUSY;

	if(InState(ESTABLISHED))
	{
		if(isFlushing > 0)
			SetState(COMMITTING);
		return 0;
	}

	if(InState(PEER_COMMIT))
	{
		if(isFlushing > 0)
			SetState(COMMITTING2);
		return 0;
	}

	if(InState(COMMITTING) || InState(COMMITTING2))
		return -EBUSY;

	if (InState(COMMITTED))
	{
#ifdef TRACE
		printf_s("Data requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		if(isFlushing > 0)
		{
			SetState(COMMITTING);
		}
		else
		{
			SetState(ESTABLISHED);
			SetNewTransaction();
		}
		return 1;
	}

	if (InState(CLOSABLE))
	{
#ifdef TRACE
		printf_s("Data requested to be sent in %s state. Migrated\n", stateNames[GetState()]);
#endif
		if(isFlushing > 0)
		{
			SetState(COMMITTING2);
		}
		else
		{
			SetState(PEER_COMMIT);
			SetNewTransaction();
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
// UNRESOLVED!
//	No matter what happpend if shouldAppendCommit a new COMMIT packet shall be appended and sent!
void CSocketItemDl::ProcessPendingSend()
{
#ifdef TRACE
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
		//
#if defined(_DEBUG)
		if (fpSent == NULL)
			TRACE_HERE("Internal panic! Lost way to report WriteTo result");
#endif
	}

	// Set fpSent to NULL BEFORE calling back so that chained send may set new value
	CallbackBufferReady fp2 = (CallbackBufferReady)InterlockedExchangePointer((PVOID volatile *)& fpSent, NULL);

	if (pendingSendSize > 0)	// while pendingSendBuf == NULL: pending GetSendBuffere()
	{
		int m = pendingSendSize;	// the size of the requested buffer
		void * p = pControlBlock->InquireSendBuf(m);
		SetMutexFree();
		//
		// If ULA hinted that sending was not finished yet, continue to use the saved pointer of the callback function
		if (m < pendingSendSize || fp2 != NULL && fp2(this, p, m) == 0)
			TestSetSendReturn(fp2);
		//
		return;
	}

	// pending WriteTo(), or pending Commit()
	pendingSendBuf = NULL;	// So that WriteTo() chaining is possible, see also BufferData()
	//
	if (shouldAppendCommit != 0)
	{
		int r = pControlBlock->ReplaceSendQueueTailToCommit();
		if (r >= 0)
		{
			shouldAppendCommit = 0;
			if (r == 1)	// should be the norm
				Call<FSP_Send>();
		}
	}
	//
	SetMutexFree();
	if (fp2 != NULL)
		((NotifyOrReturn)fp2)(this, FSP_Send, bytesBuffered);
}



// Given
//	int &	[_In_] length of data in pendingSendBuf to send [_Out_] length of data scheduled to send
// Return
//	number of bytes buffered in the send queue
// TODO: encryption and/or compression
int LOCALAPI CSocketItemDl::BufferData(int len)
{
	ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	// UNRESOLVED! milky-payload: apply FIFD instead of FIFO
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
			p->SetFlag<IS_COMPLETED>();
		//
		p->Unlock();
		//
		if (m == 0)
			goto l_finish;
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
			p->SetFlag<IS_COMPLETED>();
		//
		p->Unlock();
		if (m <= 0)
			break;
		//
		pendingSendBuf += MAX_BLOCK_SIZE;
		p = GetSendBuf();
	}

l_finish:
	// assert:
	// It somewhat overlaps with checking isFlushing, i.e. there is some redundancy, but it keeps code simple
	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
	{
		ControlBlock::PFSP_SocketBuf skb0 = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
#ifdef TRACE
		if(skb0->GetFlag<IS_SENT>())
			printf_s("Erraneous implementation!? Maynot start a new transaction");
#endif
		skb0->opCode = PERSIST;
	}

	pendingSendSize = m;
	//
	if(p == NULL)
	{
#ifdef TRACE
		printf_s("No enough send buffer to send the message in a batch. %d bytes left.\n", pendingSendSize);
#endif
		return (len - m);
	}
	//
	if (pendingSendSize == 0)
	{
		if (isFlushing == FlushingFlag::END_MESSAGE_ONLY)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
		}
		else if (isFlushing > 0)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->opCode = COMMIT;
			p->SetFlag<IS_COMPLETED>();
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
	register ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	if(p != NULL)
	{
#ifdef TRACE
		printf_s("SendInline automatically closes previous packet sent by WriteTo() or implicit welcome\n");
#endif
		p->SetFlag<IS_COMPLETED>();	// TO_BE_CONTINUED, if any, is kept, however
		//^it might be redundant, but do little harm
		p->Unlock();
	}

	register int m = len;
	if(pControlBlock->InquireSendBuf(m) != buf)	// 'm' is an in-out parameter
		return -EFAULT;
	if(m < len)
		return -ENOMEM;

	ControlBlock::PFSP_SocketBuf skb0 = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
	p = skb0;
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
	p->InitFlags();	// and locked
	p->version = THIS_FSP_VERSION;
	p->len = len - MAX_BLOCK_SIZE * m;
	p->opCode = (eomFlag == END_OF_TRANSACTION ? COMMIT : PURE_DATA);
	p->SetFlag<TO_BE_CONTINUED>(eomFlag == NOT_END_ANYWAY);
	p->SetFlag<IS_COMPLETED>();
	p->Unlock();
	//
	pControlBlock->sendBufferNextPos += m + 1;
	pControlBlock->RoundSendBufferNextPos();
	pControlBlock->sendBufferNextSN += m + 1;

	// Slightly differ from BufferData on when to set COMMIT or PERSIST
	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
	{
#ifdef TRACE
		if(skb0->GetFlag<IS_SENT>())
			printf_s("Erraneous implementation!? Maynot start a new transaction");
#endif
		if(skb0->opCode != COMMIT)
			skb0->opCode = PERSIST;
	}

	return (m + 1);
}
