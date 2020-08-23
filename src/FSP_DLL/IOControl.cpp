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



// Release the mutex lock, may release the memory as well if the operation is pending
void CSocketItemDl::SetMutexFree()
{
	if (toReleaseMemory)
	{
		CSocketItem::Destroy();
		// 'bzero' covers toReleaseMemory and locked
		bzero((octet*)this + sizeof(CSocketItem), sizeof(CSocketItemDl) - sizeof(CSocketItem));
	}
	else
	{
		_InterlockedExchange8(&locked, 0);
	}
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
		FreeWithReset();
		return false;
	}

	return true;
}



// Given
//	int		the value meant to be returned
// Do
//	Process the receive buffer and send queue, then free the mutex and return the value
// Remark
//	This function SHALL be called as the 'parameter' of the return statement
//	It creates new parallel thread to process the receive buffer and/or send buffer
int  CSocketItemDl::TailFreeMutexAndReturn(int r)
{
	if (HasDataToDeliver())
	{
		_InterlockedCompareExchange8((char*)&receiveNotice, FSP_NotifyDataReady, 0);
		ScheduleReceiveCallback();
	}
	if (HasFreeSendBuffer())
	{
		_InterlockedCompareExchange8((char*)&sendAllowedNotice, FSP_NotifyBufferReady, 0);
		ScheduleSendCallback();
	}
	
	SetMutexFree();
	//
	return r;
}


// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	SNotification signal;
	while (recv(SDPipe(), (char*)&signal, sizeof(SNotification), 0) > 0)
	{
#ifdef TRACE
		printf_s("\nIn pipeline: notice %s to local fiber#%u\n", noticeNames[signal.sig], signal.fiberID);
#endif
		CSocketItemDl* p = CSocketItemDl::headOfInUse;
		while (p != NULL)
		{
			if (p->fidPair.source == signal.fiberID
			|| (p->pControlBlock != NULL && p->pControlBlock->nearEndInfo.idALF == signal.fiberID))
			{
				p->ProcessNotice(signal.sig);
				break;
			}
			p = (CSocketItemDl*)p->next;
		}
		// Reset socket at LLS side on missing event target. See also 'Call<FSP_Reset>()' :
		if (p == NULL && signal.sig < FSP_IPC_Failure)
		{
			SCommandToLLS cmd;
			cmd.opCode = FSP_Reset;
			cmd.fiberID = signal.fiberID;
			send(SDPipe(), (char*)&cmd, sizeof(SCommandToLLS), 0);
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
	uint64_t t0 = GetTickCount64();
	while (!TryMutexLock())
	{
		if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us / 1000)
		{
			_InterlockedExchange8(&inUse, 0);
			return;
		}
		//
		Sleep(TIMER_SLICE_ms);
	}

	if (pControlBlock == NULL || InIllegalState())
		return;

	char c = _InterlockedExchange8(&pControlBlock->nmi, 0);
	// If non-maskable interrupted, abort any waitable loop
	// NMI takes precedence over any pending notices in the stream
	if (c != 0)
	{
		_InterlockedExchange8(&inUse, 0);
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
		break;
	case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
	case FSP_NotifyAccepted:
	case FSP_NotifyMultiplied:	// See also @LLS::Connect()
		_InterlockedCompareExchange8((char *)&oneshotNotice, notice, 0);
		CancelTimeout();		// If any
		ScheduleOneshotCallback();
		break;
	case FSP_NotifyDataReady:
		_InterlockedCompareExchange8((char*)&receiveNotice, notice, 0);
		ScheduleReceiveCallback();
		break;
	case FSP_NotifyBufferReady:
		_InterlockedCompareExchange8((char*)&sendAllowedNotice, notice, 0);
		ScheduleSendCallback();
		break;
	case FSP_NotifyToCommit:
		receiveNotice = notice;	// overwrite whatever existed
		ScheduleReceiveCallback();
		break;
	case FSP_NotifyFlushed:
		sendAllowedNotice = notice;	// overwrite whatever existed
		ScheduleSendCallback();
		break;
	case FSP_NotifyToFinish:
		_InterlockedCompareExchange8((char*)&oneshotNotice, notice, 0);
		ScheduleOneshotCallback();
		break;
	case FSP_NameResolutionFailed:
	case FSP_IPC_Failure:
	case FSP_MemoryCorruption:
	case FSP_NotifyReset:
	case FSP_NotifyTimeout:
		oneshotNotice = notice;	// NMI overwrite whatever existed
		ScheduleOneshotCallback();
		break;
	default:
		;	// Just skip unknown notices in sake of resynchronization
	}
	//
	SetMutexFree();
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
		FreeWithReset();
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



//
void CSocketItemDl::CallBackOneshot()
{
	uint64_t t0 = GetTickCount64();
	while (!TryMutexLock())
	{
		if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us / 1000)
		{
			_InterlockedExchange8(&inUse, 0);
			return;
		}
		//
		Sleep(TIMER_SLICE_ms);
	}

	if (pControlBlock == NULL || InIllegalState())
		return;

	//
	FSP_NoticeCode c = (FSP_NoticeCode)_InterlockedExchange8((char *)&oneshotNotice, 0);
	void *fp1;
	switch (c)
	{
	case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
		if (context.onAccepting != NULL && pControlBlock->HasBacklog())
			ProcessBacklogs();
		SetMutexFree();
		break;
	case FSP_NotifyAccepted:
		CancelTimeout();		// If any
		// Asynchronous return of Connect2, where the initiator may cancel data transmission
		if (InState(CONNECT_AFFIRMING))
		{
			ToConcludeConnect();// SetMutexFree();
			break;
		}
		fp1 = context.onAccepted;
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
	case FSP_NotifyToFinish:
		// RELEASE implies both NULCOMMIT and ACK_FLUSH, any way call back of shutdown takes precedence 
		// See also @LLS::OnGetRelease
		if (initiatingShutdown)
		{
			fp1 = fpFinished;
			RecycLocked();		// CancelTimer(); SetMutexFree();
			if (fp1 != NULL)
				((NotifyOrReturn)fp1)(this, FSP_Shutdown, 0);
		}
		else
		{
			fp1 = fpFinished;
			if (fp1 == NULL)
				fp1 = _InterlockedExchangePointer((PVOID*)&fpCommitted, NULL);
			ProcessReceiveBuffer();	// SetMutexFree();
			if (fp1 != NULL)
				((NotifyOrReturn)fp1)(this, FSP_Shutdown, 0);		// passive shutdown
		}
		break;
	case FSP_NameResolutionFailed:
		FreeAndNotify(InitConnection, ENOENT);
		// UNRESOLVED!? There could be some remedy if name resolution failed?
		break;
	case FSP_IPC_Failure:
		FreeAndNotify(FSP_Reset, EIO);	// Memory access error because of bad address
		break;
	case FSP_MemoryCorruption:
		FreeAndNotify(FSP_Reset, EFAULT);	// Memory access error because of bad address
		break;
	case FSP_NotifyReset:
		FreeAndNotify(FSP_Reset, ECONNRESET);
		break;
	case FSP_NotifyTimeout:
		FreeAndNotify(FSP_Reset, ETIMEDOUT);// Reset because of time-out
		break;
	default:
		;	// Just skip unknown notices in sake of resynchronization
	}
}




void CSocketItemDl::CallBackOnReceive()
{
	uint64_t t0 = GetTickCount64();
	while (!TryMutexLock())
	{
		if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us / 1000)
		{
			_InterlockedExchange8(&inUse, 0);
			return;
		}
		//
		Sleep(TIMER_SLICE_ms);
	}

	if (pControlBlock == NULL || InIllegalState())
		return;

	FSP_NoticeCode c = (FSP_NoticeCode)_InterlockedExchange8((char*)&receiveNotice, 0);
	_InterlockedExchange8(&pControlBlock->isDataAvailable, 0);

	ProcessReceiveBuffer();					// SetMutexFree();
	if (c != FSP_NotifyToCommit)
		return;

	if (!LockAndValidate())
		return;
	// Even if there's no callback function to accept data/flags (as in blocking receive mode)
	// the peerCommitted flag can be set if no further data to deliver
	if (!HasDataToDeliver())
		peerCommitted = 1;
	// UNRESOLVED!? Race with LLS is not managed properly? Assume no competing Read?
	SetMutexFree();
}




void CSocketItemDl::CallBackOnBufferReady()
{
	uint64_t t0 = GetTickCount64();
	while (!TryMutexLock())
	{
		if (GetTickCount64() - t0 > SESSION_IDLE_TIMEOUT_us / 1000)
		{
			_InterlockedExchange8(&inUse, 0);
			return;
		}
		//
		Sleep(TIMER_SLICE_ms);
	}

	if (pControlBlock == NULL || InIllegalState())
		return;

	FSP_NoticeCode c = (FSP_NoticeCode)_InterlockedExchange8((char*)&sendAllowedNotice, 0);
	_InterlockedExchange8(&pControlBlock->hasFreedBuffer, 0);

	FSP_Session_State s0 = GetState();	// ProcessPendingSend may cause state migration
	ProcessPendingSend();				// SetMutexFree();
	if (c != FSP_NotifyFlushed)
		return;

	if (!LockAndValidate())
		return;
	if (s0 == CLOSABLE && initiatingShutdown)
	{
		if (GetState() == CLOSABLE)
		{
			SetState(PRE_CLOSED);
			AppendEoTPacket();
		}
		SetMutexFree();
	}
	else if (s0 <= CLOSABLE)
	{
#ifdef TRACE
		printf_s("State = %s, initiatingShutdown = %d\n", stateNames[s0], initiatingShutdown);
#endif
		NotifyOrReturn fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpCommitted, NULL);
		SetMutexFree();
		if (fp1 != NULL)
			fp1(this, FSP_Send, 0);
	}
}
