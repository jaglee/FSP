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
//	NotifyOrReturn	the function called back when either EoT reached,
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
	if(! WaitUseMutex())
		return -EINTR;

	if(waitingRecvBuf != NULL)
	{
		TRACE_HERE(" -EADDRINUSE most likely by unfinished ReadFrom");
		SetMutexFree();
		return -EDEADLK;
	}

	if(InterlockedExchangePointer((PVOID *) & fpPeeked, fp1) != NULL)
	{
		TRACE_HERE("warning: Receive-inline called before previous RecvInline called back");
	}
	//
	endOfPeerMessage = 0;
	if(!IsRecvBufferEmpty())
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
	if(! WaitUseMutex())
		return -EINTR;
	//
	if(InterlockedCompareExchangePointer((PVOID *) & fpReceived, fp1, NULL) != NULL)
	{
		TRACE_HERE("calling convention error: cannot read the stream before previous ReadFrom called back");
		SetMutexFree();
		return -EBUSY;
	}

	// Check whether previous ReadFrom finished (no waitingRecvBuf), effectively serialize receiving
	if(InterlockedCompareExchangePointer((PVOID *) & waitingRecvBuf, buffer, NULL) != NULL)
	{
		TRACE_HERE("-EADDRINUSE most likely by previous ReadFrom");
		SetMutexFree();
		return -EDEADLK;
	}
	// TODO: check whether the buffer overlapped?

	bytesReceived = 0;
	waitingRecvSize = capacity;
	endOfPeerMessage = 0;	// See also FetchReceived()

	if(fpPeeked != NULL)
	{
		SetMutexFree();
		return 0;
	}
	// NO!We do not reset fpPeeked. RecvInline() just takes precedence over ReadFrom()

	if(!IsRecvBufferEmpty())
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



// Return
//	-EDOM	(-33)	if the packet size does not comform to the protocol
//	-EFAULT (-14)	if the packet buffer was broken
//	positive or zero if no error
inline
int CSocketItemDl::FetchReceived()
{
	int m = 0;	// note that left border of the receive window slided in the loop body
	// firstly, skip those already delivered
	ControlBlock::PFSP_SocketBuf p;
	while(!IsRecvBufferEmpty() && (p = pControlBlock->GetFirstReceived())->opCode == 0)
	{
		pControlBlock->SlideRecvWindowByOne();
	}
	//
	for(; p->opCode != 0 && p->GetFlag<IS_FULFILLED>(); p = pControlBlock->GetFirstReceived())
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
			return -EFAULT;
		//
		if(p->len > 0)
		{
			if(DeliverData(GetRecvPtr(p), p->len) < 0)
				break;
			//
			m += p->len;
		}
		//
		p->SetFlag<IS_FULFILLED>(false);	// release the buffer
		// Slide the left border of the receive window before possibly set the flag 'end of received message'
		pControlBlock->SlideRecvWindowByOne();
		//
		if(_InterlockedExchange8((char *)& p->opCode, 0) == PERSIST && p->len == 0)
			continue;	// A payloadless PERSIST is just a special acknowledgement
		//
		if(p->GetFlag<END_OF_TRANSACTION>())
		{
			endOfPeerMessage = 1;
			break;
		}
		// 'be free to accept': both _COMMIT && !END_OF_TRANSACTION and PERSIST && len == 0 && !END_OF_TRANSACTION
		// are illegal as well, but we refuse only !END_OF_TRANSACTION && len != 0 && len != MAX_BLOCK_SIZE
		if(p->len != MAX_BLOCK_SIZE)
			return -EDOM;
	}
	//
	return m;
}



// Remark
//	It is meant to be called by the soft interrupt handling entry function where the mutex lock has been obtained
//	and it sets the mutex lock free on leave.
//	fpReceived would not be reset if internal memeory allocation error detected
//	If RecvInline() failed (say, due to compression and/or encryption), data may be picked up by ReadFrom()
//	ULA should make sure that the socket is freed in the callback function (if recycling is notified)
void CSocketItemDl::ProcessReceiveBuffer()
{
#ifdef TRACE
	printf_s("Process receive buffer in state %s\n", stateNames[pControlBlock->state]);
#endif
	//
	CallbackPeeked fp1 = fpPeeked;
	int n;
	// RecvInline takes precedence
	if(fp1 != NULL)
	{
#ifdef TRACE
		printf_s("RecvInline...\n");
#endif
		bool b;
		void *p = pControlBlock->InquireRecvBuf(n, b);
#ifdef TRACE
		printf_s("Data to deliver: 0x%08X, length = %u, eot = %d\n", (LONG)p, n, (int)b);
#endif
		// If end-of-transaction encountered reset fpPeeked so that RecvInline() may work
		if(b)
		{
#ifdef TRACE
			printf_s("Message terminated\n");
#endif
			endOfPeerMessage = 1;
			fpPeeked = NULL;
		}
		if(n == 0)	// (n == 0 && !b) when the last message is a payloadless PERSIST with the EoT flag set
		{
			TRACE_HERE("Nothing to deliver");
			SetMutexFree();
			return;
		}
		// UNRESOLVED!Reset fpPeeked so that crash recovery by chained ReadFrom() is possible if(n < 0) ?
		//
		SetMutexFree();
		if(n < 0)
			fp1(this, NULL, (int32_t)n, false);
		else
			fp1(this, p, (int32_t)n, b);
		return;
	}

	// it is possible that data is buffered and waiting to be delivered to ULA
	if(waitingRecvBuf == NULL || waitingRecvSize <= 0 || fpReceived == NULL)
	{
		SetMutexFree();
		return;
	}

	n = FetchReceived();
	if(n < 0)
	{
#ifdef TRACE
		printf_s("FetchReceived() return %d\n"
			"UNRESOLVED! Crash recovery? waitingRecvBuf or fpRecept is not reset yet.\n"
			, n);
#endif
		SetMutexFree();
		return;
	}
	//
	if(endOfPeerMessage || waitingRecvSize <= 0)
		FinalizeRead();
	else
		SetMutexFree();
}



void CSocketItemDl::FinalizeRead()
{
	NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *) & fpReceived, NULL);
	waitingRecvBuf = NULL;
	SetMutexFree();
	// due to multi-task nature it could be already reset in the caller although fpReceived has been checked here
	if(fp1 != NULL)
		fp1(this, FSP_NotifyDataReady, bytesReceived);
}
