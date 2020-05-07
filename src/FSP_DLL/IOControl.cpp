/*
 * DLL to service FSP upper layer application, mutual exclusive locks for I/O operation
 * I/O control functions to get/set session parameters
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


SOCKET		CSocketItemDl::sdPipe = INVALID_SOCKET;
CSocketItemDl* CSocketItemDl::headOfInUse = NULL;


// These two functions are created in sake of unit test
DllExport
FSPHANDLE FSPAPI CreateFSPHandle()
{
	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	FSP_SocketParameter stubParameter;
	PFSP_Context psp1 = &stubParameter;
	memset(psp1, 0, sizeof(FSP_SocketParameter));
	return (CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1));
}



DllExport
void FSPAPI FreeFSPHandle(FSPHANDLE h)
{
	((CSocketItemDl *)h)->Free();
}



DllSpec void FSPAPI FSP_IgnoreNotice(FSPHANDLE, FSP_ServiceCode, int) {}



// When use FSPControl to enumerate interfaces,
// 'value' is the pointer to the first element of an array of IN6_PKTINFO structure
// and the 'ipi6_ifindex' field of the first element should store the size of the array
// return number of available interfaces with configured IPv4/IPv6 address
// which might be zero. negative if error.



// Given
//	FSPHANDLE			the handle to the FSP socket
//	FSP_ControlCode		the code of the control point
//	ULONG_PTR			the value to be set
// Do
//	Set the value of the control point designated by the code
// Return
//	0 if no error
//	-EDOM if some parameter is out of scope
//	-EINTR if exception thrown
DllExport
int FSPAPI FSPControl(FSPHANDLE hFSPSocket, FSP_ControlCode controlCode, ULONG_PTR value)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		switch(controlCode)
		{
		case FSP_GET_EXT_POINTER:
			*(ULONG_PTR *)value = (ULONG_PTR)pSocket->GetExtentOfULA();
			break;
		case FSP_SET_EXT_POINTER:
			pSocket->SetExtentOfULA((uint64_t)value);
			break;
		case FSP_SET_CALLBACK_ON_ERROR:
			pSocket->SetCallbackOnError((NotifyOrReturn)value);
			break;
		case FSP_SET_CALLBACK_ON_REQUEST:
			pSocket->SetCallbackOnRequest((CallbackRequested)value);
			break;
		case FSP_SET_CALLBACK_ON_CONNECT:
			pSocket->SetCallbackOnAccept((CallbackConnected)value);
			break;
		case FSP_GET_PEER_COMMITTED:
			*((int *)value) = pSocket->HasPeerCommitted() ? 1 : 0;
			break;
		default:
			return -EINVAL;
		}
		return 0;
	}
	catch(...)
	{
		return -EINTR;
	}
}



// Return whether previous ReadFrom or ReadInline has reach an end-of-transaction mark.
// A shortcut for FSPControl(FSPHANDLE, FSP_GET_PEER_COMMITTED, ...);
DllSpec
void * FSPAPI GetExtPointer(FSPHANDLE hFSPSocket)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		return (void *)pSocket->GetExtentOfULA();
	}
	catch (...)
	{
		return NULL;
	}
}


DllSpec
bool FSPAPI HasReadEoT(FSPHANDLE hFSPSocket)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		return pSocket->HasPeerCommitted();
	}
	catch (...)
	{
		return false;
	}
}



DllSpec
PFSP_Context FSPAPI GetFSPContext(FSPHANDLE hFSPSocket)
{
	try
	{
		CSocketItemDl* pSocket = (CSocketItemDl*)hFSPSocket;
		return pSocket->GetFSPContext();
	}
	catch (...)
	{
		return NULL;
	}
}



DllSpec
int FSPAPI GetProfilingCounts(FSPHANDLE hFSPSocket, PSocketProfile pSnap)
{
	try
	{
		CSocketItemDl* pSocket = (CSocketItemDl*)hFSPSocket;
		return pSocket->GetProfilingCounts(pSnap);
	}
	catch (...)
	{
		return false;
	}
}



int CSocketItemDl::GetProfilingCounts(PSocketProfile pSnap)
{
	if (!WaitUseMutex())
		return -EDEADLK;
	//
	if (pControlBlock == NULL || !InIllegalState())
	{
		SetMutexFree();
		return -EBADF;
	}
	//
	int r = (int)sizeof(pControlBlock->perfCounts);
	memcpy(pSnap, & pControlBlock->perfCounts, r);
	SetMutexFree();
	return r;
}




// Do
//	Try to obtain the slim-read-write mutual-exclusive lock of the FSP socket
// Return
//	true if obtained the mutual-exclusive lock
//	false if timed out
// Remark
//	if there is some thread that has exclusive access on the lock, wait patiently
bool CSocketItemDl::WaitUseMutex()
{
	uint64_t t0 = GetTickCount64();
	while(!TryMutexLock())
	{
		// possible dead lock: should trace the error in debug mode!
		if(GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us/1000)
			return false;
		if(!IsInUse())
			return false;
		//
		Sleep(TIMER_SLICE_ms);
	}
	//
	return IsInUse();
}



// Return
//	true if having obtained the mutual-exclusive lock and having the session control block validated
//	false if either timed out in obtaining the lock or found that the session control block invalid
// Remark
//	Dispose the DLL FSP socket resource if to return false
bool CSocketItemDl::LockAndValidate()
{
	if (!WaitUseMutex())
		return false;

	if(InIllegalState())
	{
#ifndef NDEBUG
		printf_s(
			"\nDescriptor#%p, event to be processed, but the socket is in state %s[%d]?\n"
			, this
			, stateNames[pControlBlock->state], pControlBlock->state);
#endif
		Free();
		return false;
	}

	return true;
}



// Given
//	int		the value meant to be returned
// Do
//	Process the receive buffer and send queue, then free the mutex and return the value
// Remark
//	ULA function may be called back on processing the receive buffer or send queue,
//	and this function SHALL be called as the 'parameter' of the return statement
//	Processing the receive buffer takes precedence because receiving is to free resource
int  CSocketItemDl::TailFreeMutexAndReturn(int r)
{
	if (HasDataToDeliver() && (fpReceived != NULL || fpPeeked != NULL))
	{
		ProcessReceiveBuffer();
		if (!TryMutexLock())
			return r;
	}
	//
	if (HasFreeSendBuffer() && (fpSent != NULL || pendingSendBuf != NULL))
		ProcessPendingSend();
	else
		SetMutexFree();
	//
	return r;
}



// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	SNotification signal;
	while (recv(CSocketItemDl::sdPipe, (char*)&signal, sizeof(SNotification), 0) > 0)
	{
		for (CSocketItemDl* p = CSocketItemDl::headOfInUse; p != NULL; p = (CSocketItemDl*)p->next)
		{
			if (p->fidPair.source == signal.fiberID 
			|| (p->pControlBlock != NULL && p->pControlBlock->nearEndInfo.idALF == signal.fiberID))
			{
				p->ProcessNotice(signal.sig);
				break;
			}
		}
	}

	for (CSocketItemDl* p = CSocketItemDl::headOfInUse; p != NULL; p = (CSocketItemDl*)p->next)
	{
		NotifyOrReturn fp1 = p->context.onError;
		p->Dispose();
		if (fp1 != NULL)
			fp1(p, FSP_Reset, -EIO);	// Reset because I/O error (cannot communicate with LLS)
	}
}



void CSocketItemDl::ProcessNotice(FSP_NoticeCode notice)
{
	char c = _InterlockedExchange8(&pControlBlock->nmi, 0);
	// If non-maskable interrupted, abort any waitable loop
	bool available = (c == 0 || _InterlockedExchange8(&inUse, 0) != 0);

	if (available)
	{
		uint64_t t0 = GetTickCount64();
		while (!TryMutexLock())
		{
			if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us / 1000)
			{
				available = 0;
				break;
			}
			//
			Sleep(TIMER_SLICE_ms);
		}
		//
		if (pControlBlock == NULL || InIllegalState())
			available = false;
	}
	//
	if (!available)
		return;

	// NMI takes precedence over any pending notices in the stream
	if (c != 0)
	{
		lowerLayerRecycled = 1;
		notice = (FSP_NoticeCode)c;
	}
#ifdef TRACE
	printf_s("\nIn local fiber#%u, state %s\tnotice: %s\n"
		, fidPair.source, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
	//
	switch (notice)
	{
	case FSP_NotifyListening:
		CancelTimeout();		// See also ::ListenAt
		SetMutexFree();
		break;
	case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
	case FSP_NotifyAccepted:
	case FSP_NotifyMultiplied:	// See also @LLS::Connect()
	case FSP_NotifyDataReady:
	case FSP_NotifyBufferReady:
	case FSP_NotifyToCommit:
	case FSP_NotifyFlushed:
	case FSP_NotifyToFinish:
		noticeVector |= short(1 << int(notice));
		if(_InterlockedCompareExchange8(&processingNotice, 1, 0) == 0)
			ScheduleProcessNV(this);
		SetMutexFree();
		break;
	case FSP_NameResolutionFailed:
		FreeAndNotify(InitConnection, ENOENT);
		// UNRESOLVED!? There could be some remedy if name resolution failed?
		return;
	case FSP_IPC_Failure:
		FreeAndNotify(FSP_Reset, EIO);	// Memory access error because of bad address
		break;
	case FSP_MemoryCorruption:
		FreeAndNotify(FSP_Reset, EFAULT);	// Memory access error because of bad address
		return;
	case FSP_NotifyReset:
		FreeAndNotify(FSP_Reset, ECONNRESET);
		break;
	case FSP_NotifyTimeout:
		FreeAndNotify(FSP_Reset, ETIMEDOUT);// Reset because of time-out
		return;
	default:
		;	// Just skip unknown notices in sake of resynchronization
	}
}



void CSocketItemDl::ProcessNoticeVector()
{
	if (!LockAndValidate())
		return;
	if (noticeVector == 0)
	{
		processingNotice = 0;
		SetMutexFree();
		return;
	}

l_loop:
	FSP_NoticeCode notice = NullNotice;
	FSP_Session_State s0;
	NotifyOrReturn fp1;
	for (int i = int(FSP_NotifyAccepting); i <= int(FSP_NotifyToFinish); i++)
	{
		if ((noticeVector & short(1 << i)) != 0)
		{
			noticeVector &= ~short(1 << i);
			notice = FSP_NoticeCode(i);
#ifdef TRACE
			printf_s("\nIn local fiber#%u, notice: %s, vector = 0x%X\n"
				, fidPair.source, noticeNames[notice], noticeVector);
#endif
			break;
		}
	}
	switch (notice)
	{
	case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
		if (context.onAccepting != NULL && pControlBlock->HasBacklog())
			ProcessBacklogs();
		goto l_preloop;
	case FSP_NotifyAccepted:
		CancelTimeout();		// If any
		// Asynchronous return of Connect2, where the initiator may cancel data transmission
		if (InState(CONNECT_AFFIRMING))
		{
			ToConcludeConnect();// SetMutexFree();
			break;
		}
		fp1 = (NotifyOrReturn)context.onAccepted;
		SetMutexFree();
		if (fp1 != NULL)
			((CallbackConnected)fp1)(this, &context);
		if (!LockAndValidate())
			break;
		ProcessReceiveBuffer();	// SetMutexFree();
		break;
	case FSP_NotifyMultiplied:	// See also @LLS::Connect()
		CancelTimeout();		// If any
		fidPair.source = pControlBlock->nearEndInfo.idALF;
		ProcessReceiveBuffer();	// SetMutexFree();
		if (!LockAndValidate())
			break;
		// To inherently chain WriteTo/SendInline with Multiply
		ProcessPendingSend();	// SetMutexFree();
		break;
	case FSP_NotifyDataReady:
		_InterlockedExchange8(&pControlBlock->isDataAvailable, 0);
		ProcessReceiveBuffer();	// SetMutexFree();
		break;
	case FSP_NotifyBufferReady:
		_InterlockedExchange8(&pControlBlock->hasFreedBuffer, 0);
		ProcessPendingSend();	// SetMutexFree();
		break;
	case FSP_NotifyToCommit:
		s0 = GetState();		// ProcessReceiveBuffer may cause state migration
		ProcessReceiveBuffer();	// SetMutexFree();
		if (!LockAndValidate())
			break;
		// Even if there's no callback function to accept data/flags (as in blocking receive mode)
		// the peerCommitted flag can be set if no further data to deliver
		if (!HasDataToDeliver())
			peerCommitted = 1;
		// UNRESOLVED!? Race with LLS is not managed properly? Assume no competing Read?
		goto l_preloop;
	case FSP_NotifyFlushed:
		s0 = GetState();		// ProcessPendingSend may cause state migration
		//
		ProcessPendingSend();	// SetMutexFree();
		//
		if (s0 == CLOSABLE && initiatingShutdown)
		{
			if (!LockAndValidate())
				break;
			if (GetState() == CLOSABLE)
			{
				SetState(PRE_CLOSED);
				AppendEoTPacket();
			}
			goto l_preloop;
		}
		else if (s0 <= CLOSABLE)
		{
#ifdef TRACE
			printf_s("State = %s, initiatingShutdown = %d\n", stateNames[s0], initiatingShutdown);
#endif
			fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpCommitted, NULL);
			if (fp1 != NULL)
				fp1(this, FSP_Send, 0);
		}
		break;
	case FSP_NotifyToFinish:
		// RELEASE implies both NULCOMMIT and ACK_FLUSH, any way call back of shutdown takes precedence 
		// See also @LLS::OnGetRelease
		if (initiatingShutdown)
		{
			fp1 = fpFinished;
			RecycLocked();		// CancelTimer(); SetMutexFree();
			if (fp1 != NULL)
				fp1(this, FSP_Shutdown, 0);
		}
		else
		{
			fp1 = fpFinished;
			if (fp1 == NULL)
				fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpCommitted, NULL);
			ProcessReceiveBuffer();	// SetMutexFree();
			if (fp1 != NULL)
				fp1(this, FSP_Shutdown, 0);		// passive shutdown
		}
		break;
	default:
		goto l_preloop;
	}
	if (!LockAndValidate())
	{
		processingNotice = 0;
		return;
	}

l_preloop:
	if (noticeVector != 0)
		goto l_loop;
	processingNotice = 0;
	SetMutexFree();
	return;
}




// The function called back as the polling timer fires each round
void CSocketItemDl::TimeOut()
{
	bool b = TryMutexLock();
	if (!IsInUse())
	{
		if (b)
			SetMutexFree();
		return;
	}

	if (IsTimedOut())
	{
		if(!b)
		{
			inUse = 0;	// Force WaitUseMutex to abort
			return;		// And try to gain the mutex at the next round unless the socket is recycled
		}

		NotifyOrReturn fp1 = context.onError;
		Free();
		if (fp1 != NULL)
			fp1(this, commandLastIssued, -ETIMEDOUT);
		return;
	}

	// Try to gain the mutex lock in the next round
	if (!b)
		return;
	// There used to be polling mode read/write here

	SetMutexFree();
}
