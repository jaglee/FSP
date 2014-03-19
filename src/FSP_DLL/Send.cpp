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

// Given
//	FSPHANDLE	the socket handle
//	void **		the place holder for the available buffer
//	int			the requested capacity of the buffer
//	NotifyOrReturn	the pointer to the function called back when enough buffer available
// Return
//	Size of free send bufffe in bytes, 0 if no free, negative if error
DllExport
int FSPAPI GetSendBuffer(FSPHANDLE hFSPSocket, void *(*pBuf), int m, NotifyOrReturn fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(m <= 0)
			return -EDOM;
		if(! p->StateEqual(ESTABLISHED) && ! p->StateEqual(PAUSING) && ! p->StateEqual(RESUMING))
			return -EBADF;	// invalid FSP handle	//! p->StateEqual(CHALLENGING)
		if(! p->TestSetSendReturn(fp1))
			return -EBUSY;
		return p->AcquireSendBuf(*pBuf, m);
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
//  PAUSING--[API:Send{new data}]-->[Snd RESTORE]-->RESUMING
DllExport
int FSPAPI SendInline(FSPHANDLE hFSPSocket, void * buffer, int len, bool toBeContinued)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(! p->WaitSetMutex())
			return -EINTR;	// UNRESOLVED! Simultaneous one send and one receive shall be allowed!
		if(p->StateEqual(PAUSING))
		{
			TRACE_HERE("Data requested to be sent in PAUSING state. Migrate to RESUMING state");
			p->RevertToResume();
		}	// See also TryClose()
		else if(! p->StateEqual(ESTABLISHED) && ! p->StateEqual(RESUMING))
		{
			// QUASI_ACTIVE and CLONING are excluded. This is a rate-control policy.
			p->SetMutexFree();
			return -EPERM;
		}
		int r = p->PrepareToSend(buffer, len, toBeContinued);
		p->SetMutexFree();
		if(r < 0)
			return r;
		//
		return (p->Call<FSP_Send>() ? r : -EIO);
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
		if(! p->TestSetSendReturn(fp1))
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
//	void * &	the placeholder of the returned buffer
//	int			the requested capacity
// Return
//	Size of currently available free send buffer
int LOCALAPI CSocketItemDl::AcquireSendBuf(void * & buf, int n)
{
	if(pendingSendBuf != NULL)
	{
		buf = NULL;
		return -EBUSY;
	}
	pendingSendSize = n;
	buf = pControlBlock->InquireSendBuf(n);
	if(n >= pendingSendSize && SelfNotify(FSP_NotifyBufferReady) < 0)
	{
		TRACE_HERE("cannot generate the soft interrupt?");
		return -EFAULT;
	}
	return n;
}



// Given
//	void * 	the pointer to the source data buffer
//	int		the size of the source data in bytes
// Return
//	Number of bytes put on the send queue
//	negative on error
// TODO: buffer data for transactional transfer
//[API: Send]
//ACTIVE<-->[Snd PURE_DATA{might be changed to KEEP_ALIVE on flight}]
//PAUSING-->[Snd RESTORE]-->RESUMING
//CLOSABLE-->[Snd RESTORE]-->RESUMING
//RESUMING<-->{Buffer PURE_DATA}
int LOCALAPI CSocketItemDl::SendStream(void * buffer, int len, char flag)
{
	if(! WaitSetMutex())
		return -EINTR;	// UNRESOLVED! Simultaneous one send and one receive shall be allowed!

	if(StateEqual(PAUSING))
	{
		TRACE_HERE("Data requested to be sent in PAUSING state. Migrate to RESUMING state");
		RevertToResume();
	}
	else if(! StateEqual(ESTABLISHED) && ! StateEqual(RESUMING))
	{
		TRACE_HERE("Can only send in the ESTABLISHED or RESUMING state.\n"
			"QUASI_ACTIVE and CLONING are excluded. This is a rate-control policy");
		SetMutexFree();
		return -EPERM;
	}

	if(InterlockedCompareExchangePointer((PVOID *) & pendingSendBuf, buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EDEADLK;	//  EADDRINUSE
	}
	bytesBuffered = 0;
	eomSending = flag;

	int r = BufferData(len);	// pendingSendSize = len;
	SetMutexFree();
	// Unlike in SendInline here ULA is triggered as soon as LLS have scheduled to send
	return (Call<FSP_Send>() ? r : -EIO);
}



// Remark
//	Side-effect: may modify pendingSendSize and pendingSendBuf if WriteTo() is pending
//	May call back fpSent and clear the function pointer if GetSendBuf() is pending,
//	while size of available send buffer is given as the parameter of the call back function
//	here we have assumed that the underlying binary system does not change execution order of volatile variable
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
		//
		if(fpSent == NULL) TRACE_HERE("Internal panic! Lost way to report WriteTo result");
	}

	// Set fpSent to NULL BEFORE calling back so that chained send may set new value
	NotifyOrReturn fp1 = GetResetSendReturn();
	if(fp1 == NULL)
	{
		SetMutexFree();
		return;
	}

	//	SetMutexFree() is splitted because of calling back
	if(pendingSendSize == 0)	// pending WriteTo()
	{
		pendingSendBuf = NULL;	// So that WriteTo() chaining is possible, see also BufferData()
		SetMutexFree();
		fp1(this, FSP_Send, bytesBuffered);
	}
	else if(pendingSendSize > 0)	// while pendingSendBuf == NULL
	{
		int m = pendingSendSize;	// the size of the requested buffer
		void * p = pControlBlock->InquireSendBuf(m);
		SetMutexFree();
		if(m >= pendingSendSize)
		{
			fp1(this, FSP_Send, m);
		}
		else if(p != NULL && pControlBlock->CountSendBuffered() == 0)
		{
			pControlBlock->sendWindowHeadPos = 0;
			pControlBlock->sendBufferNextPos = 0;
			fp1(this, FSP_Send, pControlBlock->sendBufferBlockN * MAX_BLOCK_SIZE);
			// Not pendingSendSize. See also ControlBlock::InquireSendBuf()
		}
	}
	else
	{
		SetMutexFree();
	}
}


// Given
//	int &	[_In_] length of data in pendingSendBuf to send [_Out_] length of data scheduled to send
// Return
//	number of bytes buffered in the send queue
// TODO: encryption and/or compression
// TODO: persist piggyback 
int LOCALAPI CSocketItemDl::BufferData(int len)
{
	ControlBlock::PFSP_SocketBuf p = pControlBlock->GetLastBufferedSend();
	// UNRESOLVED! milky-payload: apply FIFD instead of FIFO
	int m = len;
	if (m <= 0)
		return -EDOM;
	//
	// pack the byte stream, TODO: encryption and compression
	if(p != NULL && ! p->GetFlag<IS_COMPLETED>())
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
		if (m == 0)
			goto l_finish;
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
		if (m <= 0)
			break;
		//
		pendingSendBuf += MAX_BLOCK_SIZE;
		p = GetSendBuf();
	}
	//
l_finish:
	pendingSendSize = m;
	// 	Depending on eomSending flag and the state set the last packet
	if (pendingSendSize == 0)
	{
		if (eomSending == EndOfMessageFlag::END_OF_MESSAGE)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
		}
		else if (eomSending == EndOfMessageFlag::END_OF_SESSION)
		{
			p->SetFlag<TO_BE_CONTINUED>(false);
			p->SetFlag<IS_COMPLETED>();
			p->opCode = ADJOURN;
		}
		// otherwise WriteTo following may put further data into the last packet buffer
	}
	if (StateEqual(RESUMING))
	{
		p = PeekNextToSend();	// assert(p != NULL);
		if (p->opCode == ADJOURN)
			SetState(PAUSING);
		else
			p->opCode = RESTORE;
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
//TODO...
//[API: Send]
//ACTIVE<-->[Snd PURE_DATA{might be changed to KEEP_ALIVE on flight}]
//PAUSING-->[Snd RESTORE]-->RESUMING
//CLOSABLE-->[Snd RESTORE]-->RESUMING
//RESUMING<-->{Buffer PURE_DATA}
int LOCALAPI CSocketItemDl::PrepareToSend(void * buf, int len, bool toBeContinued)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetLastBufferedSend();
	int r = pControlBlock->MarkSendQueue(buf, len, toBeContinued);
	if(r < 0)
	{
#ifdef TRACE
	printf_s("\nMarkSendQueue 0x%08X, len = %d, toBeContinued = %d, returned %d\n", (LONG)buf, len, (int)toBeContinued, r);
#endif
		return r;
	}

	// Automatically mark the previous last packet as completed. See also BufferData()
	if (skb != NULL)
	{
#ifdef TRACE
		printf_s("SendInline automatically closed previous message sent by WriteTo() or implicit welcome\n");
#endif
		skb->SetFlag<TO_BE_CONTINUED>(false);
		skb->SetFlag<IS_COMPLETED>();
		//^it might be redundant, but did little harm
	}
	if(StateEqual(RESUMING))
	{
		skb = PeekNextToSend();
		if (skb->opCode == ADJOURN)
			SetState(PAUSING);
		else
			skb->opCode = RESTORE;
	}

	return r;
}
