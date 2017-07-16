/*
 * DLL to service FSP upper layer application
 * Receive/Read/Fetch functions
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
//	CallbackPeeked	the pointer of the function called back when some data is available
// Do
//	Register the call back function. Trigger a software interrupt
//	to call back the given function if there are data available immediately.
//  Return immediately if there is no data available.
// Return
//	0 if no error, negative if error detected on calling the function
// Remark
//	The the start pointer and the available data size in the receive buffer
//	are returned by passing as the parameters of the callback function
DllExport
int FSPAPI RecvInline(FSPHANDLE hFSPSocket, CallbackPeeked fp1)
{
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
//	positive if it is the length of the available data
//	0 if no immediate error
//	-EFAULT if some ridiculous exception has arised
//	-EBUSY if previous asynchronous Read operation has not completed
//	-EDEADLK if cannot obtain the mutual exclusive lock
//	-EADDRINUSE if previous ReadFrom has not completed
// Remark
//	NotifyOrReturn is called when receive buffer is full OR end of transaction encountered
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until either the buffer is fulfilled or the peer's transmit transactin has been committed
//	ULA should check whether the transmit transaction is committed by calling FSPControl. See also WriteTo
DllExport
int FSPAPI ReadFrom(FSPHANDLE hFSPSocket, void *buf, int capacity, NotifyOrReturn fp1)
{
	register CSocketItemDl *p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->ReadFrom(buf, capacity, fp1);
	}
	catch (...)
	{
		return -EFAULT;
	}
}



// See ::RecvInline()
int CSocketItemDl::RecvInline(CallbackPeeked fp1)
{
	if (!WaitUseMutex())
		return -EDEADLK;

	if (waitingRecvBuf != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}

	if (InterlockedExchangePointer((PVOID *)& fpPeeked, fp1) != NULL)
	{
#ifdef TRACE
		printf_s("\nFiber#%u, warning: Receive-inline called before previous RecvInline called back\n", fidPair.source);
#endif
	}
	//
	peerCommitPending = peerCommitted = 0;	// See also ProcessReceiveBuffer()
	if (HasDataToDeliver())
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
//	NotifyOrReturn	the pointer of the function called back
// Do
//	Register internal function pointer
// Return
//	positive, the number of octets received immediately
//	0 if no immediate error
//	negative on error
// See ::RecvFrom()
// TODO: check whether the buffer overlapped?
int LOCALAPI CSocketItemDl::ReadFrom(void * buffer, int capacity, NotifyOrReturn fp1)
{
#ifdef TRACE
	printf_s("ReadFrom the FSP pipe to 0x%08X: byte[%d]\n", (LONG)buffer, capacity);
#endif
	if (!WaitUseMutex())
		return -EDEADLK;
	//
	if (InterlockedCompareExchangePointer((PVOID *)& fpReceived, fp1, NULL) != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	// Check whether previous ReadFrom finished (no waitingRecvBuf), effectively serialize receiving
	if (InterlockedCompareExchangePointer((PVOID *)& waitingRecvBuf, buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}

	peerCommitPending = peerCommitted = 0;	// See also FetchReceived()
	bytesReceived = 0;
	waitingRecvSize = capacity;

	// We do not reset fpPeeked. RecvInline() just takes precedence over ReadFrom()
	if (fpPeeked != NULL)
	{
		SetMutexFree();
		return 0;
	}

	// blocking mode: loop until EoT reached, or the buffer is full
	if (fpReceived != NULL)
	{
		bool b = HasDataToDeliver();
		SetMutexFree();
		return b ? SelfNotify(FSP_NotifyDataReady) : 0;
	}

	// If it is blocking, wait until every slot in the receive buffer has been filled
	// or the peer has committed the transmit transaction
	uint64_t t0 = GetTickCount64();
	int r;
	while ((r = FetchReceived()) >= 0 && bytesReceived < capacity)
	{
		do
		{
			if (peerCommitted)
				goto l_postloop;
			SetMutexFree();
			Sleep(50);
			if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
				return -EDEADLK;
			if (!WaitUseMutex())
				return -EDEADLK;
		} while (!HasDataToDeliver());
	}
l_postloop:
	if(peerCommitted)
		FlushDecodeState();
	//
	waitingRecvBuf = NULL;
	SetMutexFree();
	//
	if (r < 0)
		return r;
	return bytesReceived;
}



// Return
//	-EDOM	(-33)	if the packet size does not comform to the protocol
//	-EFAULT (-14)	if the packet buffer was broken
//	-ENOMEM (-12)	if it is to decompress, but there is no enough memory for internal buffer
//	non-negative: number of octets fetched. might be zero
// Remark
//	Left border of the receive window is slided if RecvInline has been called but the inquired receive buffer has not been unlocked
inline
int CSocketItemDl::FetchReceived()
{
	ControlBlock::PFSP_SocketBuf p;
	int n, sum = 0;
	// Skip payload-less PERSIST meant to be in-band acknowledgment that starts a new transmit transaction
	while(HasDataToDeliver())
	{
		p = pControlBlock->GetFirstReceived();
		if(p->opCode == PERSIST)
		{
			if(p->len > 0)
				goto l_continue;
		}
		else if(p->opCode != 0)
		{
			goto l_continue;
		}
		pControlBlock->SlideRecvWindowByOne();
	}
	return 0;
	//
l_continue:
	if(p->GetFlag<Compressed>() && pDecodeState == NULL && !AllocDecodeState())
		return -ENOMEM;
	//
	for(; p->GetFlag<IS_FULFILLED>(); p = pControlBlock->GetFirstReceived())
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
			return -EFAULT;
		octet * srcBuf = GetRecvPtr(p) + offsetInLastRecvBlock;
		if(p->len > offsetInLastRecvBlock)
		{
			if(pDecodeState == NULL)
			{
				n = min(waitingRecvSize, p->len - offsetInLastRecvBlock);
				memcpy(waitingRecvBuf, srcBuf, n);
				waitingRecvBuf += n;
				bytesReceived += n;
				waitingRecvSize -= n;
			}
			else if(waitingRecvSize > 0)
			{
				int m = waitingRecvSize;
				n = Decompress(waitingRecvBuf, m, srcBuf, p->len - offsetInLastRecvBlock);
				if(n < 0)
					return n;
				waitingRecvBuf += m;
				bytesReceived += m;
				waitingRecvSize -= m;
			}
			else
			{
				// Decompress would gobble data into internal buffer as much as possible
				// even if there's no free space in the external waitingRecvBuf
				n = 0;
			}
			//
			sum += n;
			offsetInLastRecvBlock += n;
		}
		//
		if (p->len > offsetInLastRecvBlock)
			break;
		//
		_InterlockedExchange8((char *)& p->opCode, 0);
		p->SetFlag<IS_FULFILLED>(false);	// release the buffer
		// Slide the left border of the receive window before possibly set the flag 'end of received message'
		pControlBlock->SlideRecvWindowByOne();
		offsetInLastRecvBlock = 0;
		//
		if(p->GetFlag<TransactionEnded>())
		{
			peerCommitted = 1; // might be copied to peerCommitPending and then cleared by FlushDecodeState
			FlushDecodeState();
			break;
		}
		//
		if(p->len != MAX_BLOCK_SIZE)
			return -EDOM;
	}
	//
	return sum;
}



// Remark
//	It is meant to be called by the soft interrupt handling entry function where the mutex lock has been obtained
//	and it sets the mutex lock free on leave.
//	LLS FSP_AdRecvWindow may be called before DLL SetMutexFree.
//	Advertise the receive window size to the peer unless error encountered, even if nothing is delivered.
void CSocketItemDl::ProcessReceiveBuffer()
{
#ifdef TRACE
	printf_s("Fiber#%u process receive buffer in %s\n", fidPair.source, stateNames[pControlBlock->state]);
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
		printf_s("Data to deliver@%p, length = %d, eot = %d\n", p, n, (int)b);
#endif
		// If end-of-transaction encountered reset fpPeeked so that RecvInline() may work
		if(b)
		{
#ifdef TRACE
			printf_s("Transmit transaction terminated\n");
#endif
			peerCommitted = 1;
			fpPeeked = NULL;
		}
		else if(n == 0) // when the last message is a payload-less PERSIST without the EoT flag set
		{
			Call<FSP_AdRecvWindow>();
			SetMutexFree();
			return;
		}
		// Do not reset fpPeeked because it may require double-deliver if round-robin
		//
		SetMutexFree();
		if(n < 0)
		{
			fp1(this, NULL, (int32_t)n, false);
			return;
		}
		//
		fp1(this, p, (int32_t)n, b);
		WaitUseMutex();
		// Assume the call-back function did not mess up the receive queue
		MarkReceiveFinished(n);
		if (HasDataToDeliver())
		{
			SetMutexFree();
			SelfNotify(FSP_NotifyDataReady);
		}
		else
		{
			SetMutexFree();
		}
		//
		Call<FSP_AdRecvWindow>();
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
		SetMutexFree();
#ifdef TRACE
		printf_s("FetchReceived() return %d when ProcessReceiveBuffer\n", n);
#endif		
		if(fpReceived != NULL)
			fpReceived(this, FSP_NotifyDataReady, n);
		else
			NotifyError(FSP_NotifyDataReady, n);
		return;
	}

	Call<FSP_AdRecvWindow>();

	if(peerCommitted || waitingRecvSize <= 0)
	{
		NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *) & fpReceived, NULL);
		waitingRecvBuf = NULL;
		SetMutexFree();
		// due to multi-task nature it could be already reset in the caller although fpReceived has been checked here
		if(fp1 != NULL)
			fp1(this, FSP_NotifyDataReady, bytesReceived);
	}
	else
	{
		SetMutexFree();
	}
}
