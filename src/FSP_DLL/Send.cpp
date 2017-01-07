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
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int len, int8_t eotFlag)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->SendInplace(buffer, len, eotFlag != 0);
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
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
//	NotifyOrReturn	the callback function pointer
// Return
//	0 if no immediate error, negative if it failed, or positive it was warned (I/O pending)
// Remark
//	Only all data have been buffered may be NotifyOrReturn called.
//	Choice of the flag:
//		0: not finshed more data to follow
//		1: it is the trail of the containing message
//		2: it is the last message of the session of the particular transmit direction
DllExport
int FSPAPI WriteTo(FSPHANDLE hFSPSocket, void * buffer, int len, int8_t flag, NotifyOrReturn fp1)
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
		int r = p->SendStream(buffer, len, flag != 0);
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
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
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
		return -EINTR;
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
//	void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
//	bool	whether terminate the transaction
// Return
//	Number of bytes put on the send queue
//	negative on error
// Remark
//	This is a prototype and thus simultaneous send and receive is not considered
int LOCALAPI CSocketItemDl::SendStream(void * buffer, int len, bool flag)
{
#ifdef TRACE
	printf_s("SendStream in state %s[%d]\n", stateNames[GetState()], GetState());
#endif
	if(! WaitUseMutex())
		return -EINTR;

	int r = CheckTransmitaction(flag);
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



/**
	An ACK_CONNECT_REQ packet itself make a singular transmit transaction.
	A PERSIST or MULTIPLY packet always starts a transmit transaction.
	A PERSIST or MULTIPLY packet with 'To Be Continued' flag cleared terminates the transmit transaction as well.
 */
// Return
//	1 if revert to ACTIVE or PEER_COMMIT state
//	0 if no state revertion
//	-EBADF if the operation is prohibited because the control block is in unrevertible state
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
		isFlushing = 1;
	// else keep the isFlushing flag

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
			printf_s("\nInternal panic! Lost way to report WriteTo result\n");
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
		bool r = (fp2 != NULL && fp2(this, p, m) >= 0);
		if (m < pendingSendSize || r)
		{
			TestSetSendReturn(fp2);
			if(HasFreeSendBuffer())	// In case of round-robin
				SelfNotify(FSP_NotifyBufferReady);
		}
		//
		return;
	}

	// pending WriteTo(), or pending Commit()
	pendingSendBuf = NULL;	// So that WriteTo() chaining is possible, see also BufferData()
	//
	SetMutexFree();
	if (fp2 != NULL)
		((NotifyOrReturn)fp2)(this, FSP_Send, bytesBuffered);
}



// Given
//	int &	[_In_] length of data in pendingSendBuf to send [_Out_] length of data scheduled to send
// Return
//	number of bytes buffered in the send queue
int LOCALAPI CSocketItemDl::BufferData(int len)
{
	ControlBlock::PFSP_SocketBuf p = pControlBlock->LockLastBufferedSend();
	// UNRESOLVED! milky-payload: apply FIFD instead of FIFO
	int m = len;
	if (m <= 0)
		return -EDOM;
	//
	if(p != NULL && !p->GetFlag<IS_COMPLETED>())
	{
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
		bytesBuffered += p->len;

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
	if (pendingSendSize == 0 && isFlushing)
	{
		p->SetFlag<END_OF_TRANSACTION>();
		p->SetFlag<IS_COMPLETED>();
	}
	// otherwise WriteTo following may put further data into the last packet buffer
	return (len - m);
}



// Given
//	void *	the pointer to the in-place buffer to be marked in the send queue
//	int		the size of the buffer in bytes
//	bool	whether terminate the transaction
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
#ifdef TRACE
		printf_s("SendInline automatically closes previous packet sent by WriteTo() or implicit welcome\n");
#endif
		p->SetFlag<IS_COMPLETED>();
		//^it might be redundant, but do little harm
		p->Unlock();
	}

	register int m = len;
	if(pControlBlock->InquireSendBuf(m) != buf)	// 'm' is an in-out parameter
		return -EFAULT;
	if(m < len)
		return -ENOMEM;

	p = pControlBlock->HeadSend() + pControlBlock->sendBufferNextPos;
	// p now is the descriptor of the first available buffer block
	m = (len - 1) / MAX_BLOCK_SIZE;
	register ControlBlock::PFSP_SocketBuf p0 = p;
	for(int j = 0; j < m; j++)
	{
		p->InitFlags();	// and locked
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = MAX_BLOCK_SIZE;
		p->SetFlag<IS_COMPLETED>();
		if(p != p0)			// keep p0 locked until the tail pointer is adjusted
			p->Unlock();	// to keep the co-routine EmitQ of LLS from flounder
		p++;
	}
	//
	p->InitFlags();	// and locked
	p->version = THIS_FSP_VERSION;
	p->len = len - MAX_BLOCK_SIZE * m;
	p->opCode = PURE_DATA;
	p->SetFlag<END_OF_TRANSACTION>(eotFlag);
	p->SetFlag<IS_COMPLETED>();
	//
	pControlBlock->sendBufferNextPos += m + 1;
	pControlBlock->RoundSendBufferNextPos();
	pControlBlock->sendBufferNextSN += m + 1;
	// Slightly differ from BufferData; Unlock the start packet only when 
	if(_InterlockedCompareExchange8(& newTransaction, 0, 1) != 0)
		p0->opCode = PERSIST;
	//
	p->Unlock();	// delay unlock p in case p == p0
	p0->Unlock();	// might be redundant, but it doesn't matter

	return (m + 1);
}
