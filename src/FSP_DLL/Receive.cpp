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
		return -EBADF;
	if(fp1 == NULL)
		return -EINVAL;
	return p->RecvInline(fp1);
}



/// Commented in FSP_API.h
DllSpec
void* FSPAPI TryRecvInline(FSPHANDLE hFSPSocket, int32_t* pSize, bool* pFlag)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if (p == NULL)
	{
		*pSize = -EBADF;
		return NULL;
	}
	if (pFlag == NULL)
	{
		*pSize = -EINVAL;
		return NULL;
	}
	return p->TryRecvInline(*pSize, *pFlag);
}



/// Commented in FSP_API.h
DllExport
int FSPAPI ReadFrom(FSPHANDLE hFSPSocket, void *buf, int capacity, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EBADF;
	return p->ReadFrom(buf, capacity, fp1);
}



// Return
//	positive number if some warning
//	0 if no error
//	negative if error occurred
inline
int CSocketItemDl::TryUnlockPeeked()
{
	int32_t nBlock = _InterlockedExchange((PLONG)&pendingPeekedBlocks, 0);
	if (nBlock == 0)
		return 1;
	if (nBlock < 0)
		return -EFAULT;
	return pControlBlock->MarkReceivedFree(nBlock);
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

	int r = TryUnlockPeeked();
	if (r < 0)
	{
		SetMutexFree();
		return r;
	}

	if (waitingRecvBuf != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}
	if (offsetInLastRecvBlock != 0)
	{
		SetMutexFree();
		return -EDOM;	// May not call RecvInline if previous ReadFrom unfinished
	}
	if (peerCommitPending)
	{
		SetMutexFree();
		return -EDOM;	// May not call RecvInline if previous ReadFrom with decompression unfinished
	}

#ifndef NDEBUG
	if (_InterlockedExchangePointer((PVOID*)&fpPeeked, (PVOID)fp1) != NULL)
		printf_s("\nFiber#%u, warning: Receive-inline called before previous RecvInline called back\n", fidPair.source);
#else
	_InterlockedExchangePointer((PVOID*)&fpPeeked, (PVOID)fp1);
#endif
	return TailFreeMutexAndReturn(0);
}



// Given
//	int32_t &	Placeholder to store the length of octet stream peeked
//	bool &		Placeholder to store the EoT flag value
// Return
//	NULL if no data available or error, where the error number is stored in the placeholder meant to store the length
//	non-NULL if it points to the start address of the inline receive buffer,
//	where the length of the octet stream available is stored in its placeholder,
//	and the value of the EoT flag is stored in its placeholder, respectively
void* LOCALAPI CSocketItemDl::TryRecvInline(int32_t &size, bool &flag)
{
	if (!WaitUseMutex())
	{
		size = (IsInUse() ? -EDEADLK : -EINTR);
		return NULL;
	}

	size = TryUnlockPeeked();
	if (size < 0)
	{
		SetMutexFree();
		return NULL;
	}

	if (waitingRecvBuf != NULL)
	{
		SetMutexFree();
		size = -EADDRINUSE;
		return NULL;
	}
	if (offsetInLastRecvBlock != 0)
	{
		SetMutexFree();
		size = -EDOM;
		return NULL;	// May not call RecvInline if previous ReadFrom unfinished
	}
	if (peerCommitPending)
	{
		SetMutexFree();
		size = -EDOM;	// May not call RecvInline if previous ReadFrom with decompression unfinished
		return NULL;
	}

	octet* p = pControlBlock->InquireRecvBuf(size, pendingPeekedBlocks, flag);
	SetMutexFree();
	return p;
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
// TODO: make read idle (waiting some data available) time-out configurable? 
int LOCALAPI CSocketItemDl::ReadFrom(void* buffer, int capacity, NotifyOrReturn fp1)
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	int32_t r = TryUnlockPeeked();
	if (r < 0)
	{
		SetMutexFree();
		return r;
	}
	//
	if (_InterlockedCompareExchangePointer((PVOID*)&fpReceived, (PVOID)fp1, NULL) != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}

	// Check whether previous ReadFrom finished (no waitingRecvBuf), effectively serialize receiving
	if (_InterlockedCompareExchangePointer((PVOID*)&waitingRecvBuf, buffer, NULL) != NULL)
	{
		SetMutexFree();
		return -EADDRINUSE;
	}

	bytesReceived = 0;
	waitingRecvSize = capacity;

	// We do not reset fpPeeked. RecvInline() just takes precedence over ReadFrom()
	if (fpPeeked != NULL)
		return TailFreeMutexAndReturn(0);

	peerCommitted = 0;	// See also ProcessReceiveBuffer

	if (fpReceived != NULL)
		return TailFreeMutexAndReturn(0);

	// If it is blocking, wait until every slot in the receive buffer has been filled
	// or the peer has committed the transmit transaction
	while ((r = FetchReceived()) >= 0 && LCKREAD(bytesReceived) < capacity)
	{
		uint64_t t0 = GetTickCount64();
		do
		{
			if (peerCommitted)
				goto l_postloop;
			SetMutexFree();
			Sleep(TIMER_SLICE_ms);
			if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us/1000)
				return -EDEADLK;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : -EINTR);
		} while (!HasDataToDeliver());
	}
	// Assert: if(peerCommitted) the decode buffer MUST have been flushed. See also FlushDecodeBuffer()
l_postloop:
	waitingRecvBuf = NULL;

	return TailFreeMutexAndReturn(r < 0 ? r : bytesReceived);
}



// Return
//	-EFAULT (-14)	if the packet buffer was broken
//	-ENOMEM (-12)	if it is to decompress, but there is no enough memory for internal buffer
//	non-negative: number of octets fetched. might be zero
// Remark
//	NULCOMMIT packet which is payload-less would make it return instantly.
//	Left border of the receive window is slided if RecvInline has been called
//	but the inquired receive buffer has not been unlocked
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
		// but preserve the packet flag for EoT detection, etc.
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
	_InterlockedExchangeAdd((PLONG)&pControlBlock->recvWindowFirstSN, nPacket);
	//^memory barrier is mandatory
	return sum;
}



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
#ifndef NDEBUG
			printf_s("FetchReceived() return %d when ProcessReceiveBuffer\n", n);
#endif		
			if (fpReceived != NULL)
				fpReceived(this, FSP_Receive, n);
			else
				NotifyError(FSP_Receive, n);
			return;
		}

		if (peerCommitted || waitingRecvSize <= 0)
		{
			NotifyOrReturn fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID *)& fpReceived, NULL);
			waitingRecvBuf = NULL;
			if (fp1 != NULL)
				fp1(this, FSP_Receive, bytesReceived);
			return;
		}

		return;
	}

	// To avoid phantom double delivery of the payload
	if (pendingPeekedBlocks != 0)
		return;

	CallbackPeeked fp1 = (CallbackPeeked)_InterlockedExchangePointer((PVOID *)& fpPeeked, NULL);
	if (fp1 == NULL)
		return;

	bool eot;
	octet* p = pControlBlock->InquireRecvBuf(n, pendingPeekedBlocks, eot);
#if defined(TRACE) && defined(TRACE_VERBOSE)
	printf_s("RecvInline, data to deliver@%p, length = %d, eot = %d; %d blocks scanned\n", p, n, (int)eot, pendingPeekedBlocks);
#endif
	if (!eot && n == 0)	// Redundant soft-interrupt shall be simply ignored
	{
		assert(pendingPeekedBlocks == 0);
		fpPeeked = fp1;
		return;
	}

	// It is possible that no meaningful payload is received but an EoT flag is got.
	// The callback function should work in such scenario
	// It is also possible that p == NULL while n is the error code. The callback function MUST handle such scenario
	// If the callback function happens to be updated, prefer the new one
	bool b = fp1(this, p, n, eot);
	if (!IsInUse())
		return;
	if (b)
		_InterlockedCompareExchangePointer((PVOID*)&fpPeeked, (PVOID)fp1, NULL);

	if (n < 0)
	{
#ifdef TRACE
		printf_s("The callback function returned %d\n", n);
#endif
		return;
	}

	// protected it from dead loop caused by receive queue messed up
	int r = TryUnlockPeeked();
	offsetInLastRecvBlock = 0;
	if (r < 0)
	{
#ifdef TRACE
		printf_s("The receive queue was messed up? TryUnlockPeeked return %d\n", r);
#endif
		return;
	}

	// it could be shutdown gracefully in the callback function, however there may be data pending to deliver
	if (GetState() >= CLOSED)
		return;

	// If (n < 0) some unrecoverable error has occur. Should avoid the risk of dead-loop.
	if (n >= 0 && HasDataToDeliver())
		goto l_recursion;
	//^former condition equals (n > 0 || n == 0 && eot) because (!eot && n == 0) has been excluded

	return;
}
