/*
 * DLL to service FSP upper layer application
 * part of the SessionCtrl class, Recv, Peek and UnlockPeeded
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
//	FSPHandle		the socket handle
//	PeekCallback	the callback function pointer, mandatory
// Do
//	Get the start pointer and the data length in the receive buffer,
//	If there are data available, call back the given function.
//  If there is no data availabe, register the call back function and return immediately
// Return
//	0 if no error, negative if error detected on calling the function
DllExport
int FSPAPI RecvInline(FSPHANDLE hFSPSocket, CallbackPeeked fp1)
{
	TRACE_HERE("called");
	//
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(fp1 == NULL)
			return -EDOM;
		return p->RecvInline(fp1);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Given
//	FSPHANDLE		the FSP socket handle
//	void *			the start pointer of the receive buffer
//	int				the capacity in byte of the receive buffer
//	NotifyOrReturn	the function called back when either end of message reached,
//					connection terminated or receive buffer fulfilled
// Return
//	0 if no immediate error, negative if error, positive if it is the length of the available data
// Remark
//	ULA should exploit ReadFrom to accept compressed/encrypted data
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	If very large chunk of message is to be received, one should exploit RecvInline()
//	together with application layer decompression and/or decryption. See also WriteTo()
DllExport
int FSPAPI ReadFrom(FSPHANDLE hFSPSocket, void *buf, int capacity, NotifyOrReturn fp1)
{
	register CSocketItemDl *p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(fp1 == NULL)
			return -EDOM;
		return p->ReadFrom(buf, capacity, fp1);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// See ::RecvInline()
int CSocketItemDl::RecvInline(PVOID fp1)
{
	TRACE_HERE("BEFORE WaitSetMutex");
	if(! WaitSetMutex())
	{
		TRACE_HERE("deadlock encountered?");
		return -EINTR;
	}
	TRACE_HERE("AFTER WaitSetMutex");

	if(waitingRecvBuf != NULL)
	{
		TRACE_HERE(" -EADDRINUSE most likely by unfinished ReadFrom");
		SetMutexFree();
		return -EDEADLK;
	}

	if(InterlockedCompareExchangePointer((PVOID *) & fpPeeked, fp1, NULL) != NULL)
	{
		TRACE_HERE("calling convention error: cannot receive inline before previous RecvInline called back");
		SetMutexFree();
		return -EBUSY;
	}
	//
	SetEndOfRecvMsg(false);
	if(! IsRecvBufferEmpty())
	{
		SetMutexFree();
		return SelfNotify(FSP_NotifyDataReady);
	}

	SetMutexFree();
	return 0;
}



// Given
//	void *			the start pointer of the receive buffer
//	int				the capacity in byte of the receive buffer
// Do
//	Register internal
// Return
//	0 if no immediate error, negative on error
int LOCALAPI CSocketItemDl::ReadFrom(void * buffer, int capacity, PVOID fp1)
{
#ifdef TRACE
	printf_s("ReadFrom the FSP pipe to 0x%08X: byte[%d]\n", (LONG)buffer,  capacity);
#endif
	if(! WaitSetMutex())
	{
		TRACE_HERE("deadlock encountered?");
		return -EINTR;
	}

	if(InterlockedCompareExchangePointer((PVOID *) & fpReceive, fp1, NULL) != NULL)
	{
		TRACE_HERE("calling convention error: cannot read the stream before previous ReadFrom called back");
		SetMutexFree();
		return -EBUSY;
	}

	// Check whether previous ReadFrom finished (no waitingRecvBuf), effectively serialize receiving
	if(InterlockedCompareExchangePointer((PVOID *) & waitingRecvBuf, buffer, NULL) != NULL)
	{
		TRACE_HERE(" -EADDRINUSE most likely by previous ReadFrom");
		SetMutexFree();
		return -EDEADLK;
	}
	// TODO: check whether the buffer overlapped?

	bytesReceived = 0;
	waitingRecvSize = capacity;
	SetEndOfRecvMsg(false);	// See also FetchReceived()

	if(fpPeeked != NULL)
	{
		SetMutexFree();
		return 0;
	}
	// NO! We do not reset fpPeeked. RecvInline() just takes precedence over ReadFrom()

	if(! IsRecvBufferEmpty())
	{
		SetMutexFree();
		return SelfNotify(FSP_NotifyDataReady);
	}

	SetMutexFree();
	return 0;
}



// Return number of bytes actually delivered (might be exploding if decompressed and decrypted)
// TODO: decrypt, decompress
inline
int LOCALAPI CSocketItemDl::DeliverData(void *p, int n)
{
	if(n > waitingRecvSize)
		return -ENOMEM;
	//
	memcpy(waitingRecvBuf, p, n);
	waitingRecvBuf += n;
	bytesReceived += n;
	waitingRecvSize -= n;

	return n;	// TODO: should count into decrypt (sub tag size) decompress
}


inline
int CSocketItemDl::FetchReceived()
{
	int m = 0;	// note that left border of the receive window slided in the loop body
	for(ControlBlock::PFSP_SocketBuf p = pControlBlock->FirstReceived(); p->GetFlag<IS_COMPLETED>(); p = pControlBlock->FirstReceived())
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
			return -EFAULT;

		if(DeliverData(GetRecvPtr(p), p->len) < 0)
			break;

		// Set flag in a manner that it would not be re-delivered even IS_DELIVERED flag is not checked
		p->SetFlag<IS_COMPLETED>(false);
		p->SetFlag<IS_DELIVERED>();
		m += p->len;

		// Slide the left border of the receive window before possibly set the flag 'end of received message'
		pControlBlock->SlideRecvWindowByOne();
		if(! p->GetFlag<TO_BE_CONTINUED>())
		{
			SetEndOfRecvMsg();
			break;
		}
		// What? An imcomplete 'to be continued' intermediate packet received?
		if(p->len != MAX_BLOCK_SIZE)
			return -EFAULT;
	}
	//
	return m;
}


// Remark
//	fpReceive would not be reset if internal memeory allocation error detected
//	If RecvInline() failed (say, due to compression and/or encryption), data may be picked up by ReadFrom()
//	SetMutexFree() is splitted because of calling back
//	ULA should make sure that the socket is freed in the callback function (if recycling is notified)
void CSocketItemDl::ProcessReceiveBuffer()
{
#ifdef TRACE_PACKET
	printf_s("Process receive buffer in state %s\n", stateNames[pControlBlock->state]);
#endif
	// As LLS may set the state into CLOSABLE before DLL have been ready to process the process buffer,
	// it should be legal to deliver data in CLOSABLE state, but not CLOSED
	if(! StateEqual(CHALLENGING) && ! StateEqual(ESTABLISHED) && ! StateEqual(RESUMING) && ! StateEqual(CLONING) && ! StateEqual(CLOSABLE))
	{
#ifdef TRACE
		printf_s("Is it illegal to ProcessReceiveBuffer in state %s\n", stateNames[pControlBlock->state]);
#else
		SetMutexFree();
		return;
#endif
	}
	if (IsRecvBufferEmpty())
	{
#ifdef TRACE
		printf_s("Receive buffer is empty when ", __FUNCTION__);
#endif
		SetMutexFree();
		return;
	}
	//
	int n;
	// RecvInline takes precedence
	if(fpPeeked != NULL)
	{
#ifdef TRACE_PACKET
		printf_s("RecvInline...\n");
#endif
		bool b;
		void *p = pControlBlock->InquireRecvBuf(n, b);
#ifdef TRACE_PACKET
		printf_s("Data to deliver: 0x%08X, length = %u, eom = %d\n", (LONG)p, n, (int)!b);
#endif
		if(! b)
		{
			TRACE_HERE("TODO: code review: whether a pure ADJOURN command can terminate a message");
			SetEndOfRecvMsg();
		}
		else if(n == 0)
		{
			TRACE_HERE("Nothing to deliver");
			mutex = SHARED_FREE;
			goto l_return;
		}
		//
		CallbackPeeked fp1 = fpPeeked;
		// Reset fpPeeked so that crash recovery by chained ReadFrom() is possible
		// If end-of-message encountered reset fpPeeked so that RecvInline() may work
		if(! b || n < 0)
			fpPeeked = NULL;
		//
		SetMutexFree();
		if(n < 0)
			fp1(this, NULL, (size_t) n, false);
		else
			fp1(this, p, n, b);

		goto l_return;
	}

	if(waitingRecvBuf == NULL || waitingRecvSize <= 0 || fpReceive == NULL)
	{
#ifdef TRACE
		printf_s("When ULA have called neither RecvInline() nor ReadFrom(),\n"
			"what received should be buffered as is\n");
#endif
		SetMutexFree();
		goto l_return;
	}

	n = FetchReceived();
	if(n < 0)
	{
#ifdef TRACE
		printf_s("FetchReceived() return %d\n"
			"UNRESOLVED! Crash recovery? waitingRecvBuf or fpReceive is not reset yet.\n"
			, n);
#endif
		SetMutexFree();
		NotifyError(FSP_NotifyOverflow, n);
		return;
	}
	//
	if(IsEndOfRecvMsg() || waitingRecvSize <= 0)
		FinalizeRead();
	else
		SetMutexFree();

l_return:
	// Even if ULA does not fetch the received data may it be closable
	if (IsRecvBufferEmpty())
	{
#ifdef TRACE
		printf_s("The last packet received is ADJOURN. The session is paused.\n");
#endif
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetLastReceived();
		if (skb->opCode == ADJOURN)
		{
			SetState(CLOSABLE);
			Call<FSP_LazyAckAdjourn>();
		}
	}
	else if (pControlBlock->IsClosable())
	{
#ifdef TRACE
		printf_s("A full message with ADJOURN as the trailer is in the buffer.\n"
			"The session is paused.\n");
#endif
		SetState(CLOSABLE);
		Call<FSP_LazyAckAdjourn>();
	}
	//
	if (StateEqual(CLOSABLE))
		SelfNotify(FSP_NotifyFlushed);
}



void CSocketItemDl::FinalizeRead()
{
	NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID volatile *) & fpReceive, NULL);
	waitingRecvBuf = NULL;
	SetMutexFree();
	fp1(this, FSP_NotifyDataReady, 0);
}
