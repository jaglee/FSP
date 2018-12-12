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


/// Commented in FSP_API.h
DllExport
int FSPAPI RecvInline(FSPHANDLE hFSPSocket, CallbackPeeked fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	if(fp1 == NULL)
		return -EDOM;
	return p->RecvInline(fp1);
}



/// Commented in FSP_API.h
DllExport
int FSPAPI ReadFrom(FSPHANDLE hFSPSocket, void *buf, int capacity, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	return p->ReadFrom(buf, capacity, fp1);
}




// Given
//	CallbackPeeked	the pointer of the function called back when some data is available
// Do
//	Register the call back function. Trigger a software interrupt
//	to call back the given function if there are data available immediately.
// Return
//	0 if no error, negative if error detected on calling the function
// Remark
//  Return immediately if there is no data available yet.
//	Each calling of RecvInline() should accept one and only one transmit transaction from the peer
int CSocketItemDl::RecvInline(CallbackPeeked fp1)
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	if (waitingRecvBuf != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}

	if (peerCommitPending)
	{
		SetMutexFree();
		return -EDOM;	// May not call RecvInline if previous ReadFrom with decompression unfinished
	}

	if (InterlockedExchangePointer((PVOID *)& fpPeeked, fp1) != NULL)
	{
#ifdef TRACE
		printf_s("\nFiber#%u, warning: Receive-inline called before previous RecvInline called back\n", fidPair.source);
#endif
	}
	//
	EnablePolling();
	if (! HasDataToDeliver())
	{
		SetMutexFree();
		return 0;
	}
	// Let's the polling timer to call ProcessReceiveBuffer if nested
	if (chainingReceive)
	{
		SetMutexFree();
		return 0;
	}

	ProcessReceiveBuffer();
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
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);
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

	bytesReceived = 0;
	waitingRecvSize = capacity;

	// We do not reset fpPeeked. RecvInline() just takes precedence over ReadFrom()
	if (fpPeeked != NULL)
	{
		SetMutexFree();
		return 0;
	}
	peerCommitted = 0;	// See also ProcessReceiveBuffer

	if (fpReceived != NULL)
	{
		bool b = HasDataToDeliver();
		EnablePolling();
		// Let's the polling timer to call ProcessReceiveBuffer if nested
		if (!b || chainingReceive)
		{
			SetMutexFree();
			return 0;
		}
		ProcessReceiveBuffer();
		return 0;
	}

	// If it is blocking, wait until every slot in the receive buffer has been filled
	// or the peer has committed the transmit transaction
	int32_t r;
	while ((r = FetchReceived()) >= 0 && _InterlockedOr((LONG *)&bytesReceived, 0) < capacity)
	{
		uint64_t t0 = GetTickCount64();
		do
		{
			if (peerCommitted)
				goto l_postloop;
			SetMutexFree();
			Sleep(TIMER_SLICE_ms);
			if (GetTickCount64() - t0 > COMMITTING_TIMEOUT_ms)
				return -EDEADLK;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : -EINTR);
		} while (!HasDataToDeliver());
	}
	// Assert: if(peerCommitted) the decode buffer MUST have been flushed. See also FlushDecodeBuffer()
l_postloop:
	waitingRecvBuf = NULL;
	SetMutexFree();
	//
	if (r < 0)
		return r;
	return bytesReceived;
}



// Return
//	-EDOM	(-33)	if the PERSIST packet of the size of some packet does not comform to the protocol
//	-EFAULT (-14)	if the packet buffer was broken
//	-ENOMEM (-12)	if it is to decompress, but there is no enough memory for internal buffer
//	non-negative: number of octets fetched. might be zero
// Remark
//	Left border of the receive window is slided if RecvInline has been called
//	but the inquired receive buffer has not been unlocked
//	A payload-less PERSIST with EndOfTransaction flag set would make it return instantly
//	Automatically decompress, but the return value is the size of the raw data, not the decompression result
int32_t CSocketItemDl::FetchReceived()
{
	// Data that remain in the internal decompression buffer must be fetched firstly
	if (HasInternalBufferedToDeliver())
	{
		FlushDecodeBuffer();
		if (peerCommitted)
			return 0;
	}
	if (pControlBlock->CountDeliverable() <= 0)
		return 0;

	ControlBlock::PFSP_SocketBuf p = pControlBlock->GetFirstReceived();
	if(p->GetFlag<Compressed>() && pDecodeState == NULL && !AllocDecodeState())
		return -ENOMEM;

	// First received block of a clone connection or a new transmit transaction is right-aligned
	// See also @LLS::PlacePayload and @LLS::CopyOutPlainText
	if ((p->opCode == MULTIPLY || p->opCode == PERSIST) && p->len > 0 && offsetInLastRecvBlock == 0)
	{
		offsetInLastRecvBlock = MAX_BLOCK_SIZE - p->len;
		p->len = MAX_BLOCK_SIZE;	// make sure it is right-aligned
	}
	// Note that decompression may make offsetInLastRecvBlock > MAX_BLOCK_SIZE - p->len

	int nPacket = 0;
	int sum = 0;
	int n;
	for (; p->IsComplete(); p = pControlBlock->GetFirstReceived())
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
			// Decompress would gobble data into internal buffer as much as possible
			// even if there's no free space in the external waitingRecvBuf
			else
			{
				int m = waitingRecvSize;
				n = Decompress(waitingRecvBuf, m, srcBuf, p->len - offsetInLastRecvBlock);
				if(n < 0)
					return n;
				waitingRecvBuf += m;
				bytesReceived += m;
				waitingRecvSize -= m;
			}
			//
			sum += n;
			offsetInLastRecvBlock += n;
		}
		//
		// So that remaining payload may be processed after the internal decompress buffer has free space
		if (p->len > offsetInLastRecvBlock)
			break;
		offsetInLastRecvBlock = 0;

		bool b = p->GetFlag<TransactionEnded>();
		p->ReInitMarkDelivered();
		p->ClearFlags();
		nPacket++;
		//
		if(b)
		{
			peerCommitted = 1;	// might be copied to peerCommitPending and then cleared by FlushDecodeBuffer
			if(pDecodeState != NULL)
				FlushDecodeBuffer();
			break;
		}

		if (p->len != MAX_BLOCK_SIZE)
		{
#ifndef NDEBUG
			printf_s("%p: this segment of stream is terminated for TCP compatibility.\n"
					 "Payload length of last packet is %d\n", this, p->len);
#endif
			if (pDecodeState != NULL)
				FlushDecodeBuffer();
			break;
		}
	}
	//
	pControlBlock->AddRoundRecvBlockN(pControlBlock->recvWindowHeadPos, nPacket);
	InterlockedAdd((LONG *)&pControlBlock->recvWindowFirstSN, nPacket);
	return sum;
}



// Remark
//	It is meant to be called by the soft interrupt handling entry function where the mutex lock has been obtained
//	and it sets the mutex lock free on leave.
void CSocketItemDl::ProcessReceiveBuffer()
{
l_recursion:
	int32_t n;

	// Conventional stream mode takes precedence
	if (waitingRecvBuf != NULL && waitingRecvSize > 0)
	{
		peerCommitted = 0;	// So that new flag might be retrieved
		n = FetchReceived();
		if (n < 0)
		{
			SetMutexFree();
#ifdef TRACE
			printf_s("FetchReceived() return %d when ProcessReceiveBuffer\n", n);
#endif		
			if (fpReceived != NULL)
				fpReceived(this, FSP_NotifyDataReady, n);
			else
				NotifyError(FSP_NotifyDataReady, n);
			return;
		}

		if (peerCommitted || waitingRecvSize <= 0)
		{
			NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *)& fpReceived, NULL);
			waitingRecvBuf = NULL;
			SetMutexFree();
			// due to multi-task nature it could be already reset in the caller although fpReceived has been checked here
			if (fp1 != NULL)
				fp1(this, FSP_NotifyDataReady, bytesReceived);
		}
		else
		{
			SetMutexFree();
		}

		return;
	}

	CallbackPeeked fp1 = (CallbackPeeked)InterlockedExchangePointer((PVOID *)& fpPeeked, NULL);
	if (fp1 == NULL)
	{
		SetMutexFree();
		return;
	}

	// First received block of a clone connection or a new transmit transaction is right-aligned
	// See also @LLS::PlacePayload and @LLS::CopyOutPlainText
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetFirstReceived();
	int32_t m;
	bool eot;
	BYTE *p = pControlBlock->InquireRecvBuf(n, m, eot);
	if(p != NULL && (skb->opCode == PERSIST || skb->opCode == MULTIPLY))
		p += MAX_BLOCK_SIZE - skb->len;	// See also FetchReceived()
#ifdef TRACE
	printf_s("RecvInline, data to deliver@%p, length = %d, eot = %d\n", p, n, (int)eot);
#endif
	if (!eot && n == 0)	// Redundant soft-interrupt shall be simply ignored
	{
		fpPeeked = fp1;
		SetMutexFree();
		return;
	}

	chainingReceive = 1;
	SetMutexFree();
	// It is possible that no meaningful payload is received but an EoT flag is got.
	// The callback function should work in such senario
	// It is also possible that p == NULL while n is the error code. The callback function MUST handle such scenario
	// If the callback function happens to be updated, prefer the new one
	if (fp1(this, p, n, eot))
		InterlockedCompareExchangePointer((PVOID *)&fpPeeked, fp1, NULL);
	chainingReceive = 0;
	if (!WaitUseMutex())
		return;	// it could be disposed in the callback function
#ifndef NDEBUG
	if (skb != pControlBlock->GetFirstReceived())
	{
		printf_s("The receive queue was messed up?!\n");
		BREAK_ON_DEBUG();
	}
#endif
	// Assume the call-back function did not mess up the receive queue
	if (eot || n > 0)
	{
		pControlBlock->MarkReceivedFree(m);
		offsetInLastRecvBlock = 0;
		if (HasDataToDeliver())
			goto l_recursion;
	}
	// If (n < 0) some unrecoverable error has occur. Should avoid the risk of dead-loop.

	SetMutexFree();
}
