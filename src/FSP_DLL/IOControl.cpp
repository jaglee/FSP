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



// Set the function to be called back when the connection is established
DllSpec
int FSPAPI SetOnConnected(FSPHANDLE h, CallbackConnected fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(h);
	if (p == NULL)
		return -EBADF;
	return p->SetOnConnected(fp1);
}



// Set the function to be called back on LLS error encountered
DllSpec
int FSPAPI SetOnError(FSPHANDLE h, NotifyOrReturn fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(h);
	if (p == NULL)
		return -EBADF;
	return p->SetOnError(fp1);
}



// Set the function to be called back on connection multiplication requested by the remote end
DllSpec
int FSPAPI SetOnMultiplying(FSPHANDLE h, CallbackRequested fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(h);
	if (p == NULL)
		return -EBADF;
	return p->SetOnMultiplying(fp1);
}



// Set the function to be called back on passively shutdown by the remote end
DllSpec
int FSPAPI SetOnRelease(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if (p == NULL)
		return -EBADF;
	return p->SetOnRelease((PVOID)fp1);
}



// Return whether previous ReadFrom or ReadInline has reach an end-of-transaction mark.
// A shortcut for FSPControl(FSPHANDLE, FSP_GET_PEER_COMMITTED, ...);
DllSpec
void * FSPAPI GetExtPointer(FSPHANDLE hFSPSocket)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		return pSocket->IsInUse() ? (void *)pSocket->GetExtentOfULA() : NULL;
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
	if (pControlBlock == NULL)
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




bool CSocketItemDl::TryMutexLock()
{
	pthread_t id1 = pthread_self();
	pthread_t id0 = (pthread_t)_InterlockedCompareExchangePointer(&lockOwner, id1, 0);
	if (id0 == 0 || id0 == id1)
	{
		lockDepth++;
		return true;
	}
	return false;
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
		if(toCancel || !IsInUse())
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
	pthread_t id1 = pthread_self();
	if (lockOwner != id1 || --lockDepth > 0)
		return;
	if (toReleaseMemory)
	{
		if (pControlBlock != NULL)
			Call<FSP_Reset>();
		CSocketItem::Destroy();
		// 'bzero' covers toReleaseMemory and locked
		bzero((octet*)this + sizeof(CSocketItem), sizeof(CSocketItemDl) - sizeof(CSocketItem));
	}
	else
	{
		lockOwner = 0;
	}
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
		_InterlockedCompareExchange8((char *)&pControlBlock->receiveNotice, FSP_NotifyDataReady, NullNotice);
		ArrangeCallbackOnReceive();
	}

	if (HasFreeSendBuffer())
	{
		_InterlockedCompareExchange8((char *)&pControlBlock->sendAllowedNotice, FSP_NotifyBufferReady, NullNotice);
		ArrangeCallbackOnSent();
	}

	SetMutexFree();
	//
	return r;
}



// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketDLLTLB::WaitEventToDispatch()
{
	SNotification signal;
	while (GetNoticeFromPipe(&signal))
	{
#ifdef TRACE
		printf_s("\nIn pipeline: notice %s to local fiber#%u\n", noticeNames[signal.sig], signal.fiberID);
#endif
		CSocketItemDl* p = headOfInUse;
		while (p != NULL)
		{
			if (p->fidPair.source == signal.fiberID
			|| (p->pControlBlock != NULL && p->pControlBlock->nearEndInfo.idALF == signal.fiberID))
			{
				if (!p->WaitUseMutex())
				{
					p->ResetAndNotify(FSP_Reset, EDEADLK);
					break;;
				}
				switch (signal.sig)
				{
				case FSP_IPC_Failure:
					if (p->commandLastIssued != FSP_Multiply)
						p->ResetAndNotify(FSP_Reset, EIO);
#ifdef TRACE
					else
						printf_s("Failed to make clone of connection Fiber#%u", p->fidPair.source);
#endif
					break;
				case FSP_NameResolutionFailed:
					p->ResetAndNotify(InitConnection, ENOENT);
					// UNRESOLVED!? There could be some remedy if name resolution failed?
					break;
				case FSP_MemoryCorruption:
					p->ResetAndNotify(FSP_Reset, EFAULT);	// Memory access error because of bad address
					break;
				case FSP_NotifyReset:
					p->ResetAndNotify(FSP_Reset, ECONNRESET);
					break;
				case FSP_NotifyTimeout:
					p->ResetAndNotify(FSP_Reset, ETIMEDOUT);// Reset because of time-out
					break;
				default:
					;	// otherwise should take use of shared memory for IPC
				}
				p->SetMutexFree();
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
			SendToPipe(&cmd);
		}
	}
#ifdef TRACE
	printf_s("\nThe notice channel from LLS is closed.\n");
#endif
	for (CSocketItemDl* p = headOfInUse; p != NULL; p = (CSocketItemDl*)p->next)
	{
		p->NotifyError(FSP_Reset, -EIO);	// Reset because I/O error (cannot communicate with LLS)
		p->Dispose();
	}
}




void CSocketItemDl::ProcessNoticeLocked(FSP_NoticeCode notice)
{
#ifdef TRACE
	printf_s("\nIn local fiber#%u, state %s\tnotice: %s\n"
		, fidPair.source, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
	//
	FSP_Session_State s0;
	switch (notice)
	{
	case FSP_NotifyListening:
		CancelTimeout();		// See also ::ListenAt
		break;
	case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
		if (context.onAccepting != NULL && pControlBlock->HasBacklog())
			ProcessBacklogs();
		break;
	case FSP_NotifyAccepted:
		CancelTimeout();		// If any
		s0 = GetState();
		peerCommitted = (s0 == COMMITTING2 || s0 == CLOSABLE);
		ArrangeCallbackOnAccepted();
		break;
	case FSP_NotifyConnected:
		// Asynchronous return of Connect2, where the initiator may cancel data transmission
		CancelTimeout();		// If any
		ToConcludeConnect();
		ArrangeCallbackOnAccepted();
		// Assume that the call back function would fetch received data on demand
		break;
	case FSP_NotifyMultiplied:	// See also @LLS::Connect()
		CancelTimeout();		// If any
		fidPair.source = pControlBlock->nearEndInfo.idALF;
		// OnSent takes precedence because multiplying needs acknowledgement at first
		s0 = GetState();
		peerCommitted = (s0 == COMMITTING2 || s0 == CLOSABLE);
		ArrangeCallbackOnSent();
		ArrangeCallbackOnAccepted();
		// Assume that the call back function would fetch received data on demand
		break;
	default:
		;	// Just skip unknown notices in sake of resynchronization
	}
}



// The function called back as the polling timer fires each round
void CSocketItemDl::DoPolling()
{
	bool b = TryMutexLock();
	if (IsTimedOut())
	{
		// See also Dispose()
		if (!b)
		{
			toCancel = 1;
			return;		// And try to gain the mutex at the next round unless the socket is recycled
		}

		NotifyError(commandLastIssued, -ETIMEDOUT);
		SetMutexFree();
		return;
	}

	// Try to gain the mutex lock in the next round
	if (!b)
		return;

	if (!IsInUse())
	{
		if (b)
			SetMutexFree();
		return;
	}

	// Only after it has been successfully locked may the state be tested
	// UNRESOLVED!? But how to log this internal chaoes?
	register FSP_Session_State s = (FSP_Session_State)_InterlockedOr8((char*)&pControlBlock->state, 0);
	if (s <= 0 || s > LARGEST_FSP_STATE)
	{
		NotifyError(commandLastIssued, -EBADF);
		SetMutexFree();
		return;
	}

	FSP_NoticeCode notice = (FSP_NoticeCode)_InterlockedExchange8((char *)&pControlBlock->singletonotice, NullNotice);
	if (notice != NullNotice)
		ProcessNoticeLocked(notice);

	if (pControlBlock->receiveNotice != NullNotice)
		ArrangeCallbackOnReceive();

	if (pControlBlock->sendAllowedNotice != NullNotice)
		ArrangeCallbackOnSent();

	SetMutexFree();
}



void CSocketItemDl::CallBackOnAccepted()
{
	// Although rare, race condition does exist
	if (!WaitUseMutex())
		return;
	context.onAccepted(this, &context);
	SetMutexFree();
}



void CSocketItemDl::CallBackOnReceive()
{
	// Although rare, race condition does exist
	if (!WaitUseMutex())
		return;

	FSP_NoticeCode c = (FSP_NoticeCode)_InterlockedExchange8((char*)&pControlBlock->receiveNotice, 0);
	if (c == 0)
	{
		SetMutexFree();
		return;
	}
#ifdef TRACE
	printf_s("\nCallBackOnReceive in local fiber#%u, notice: %s\n"
		, fidPair.source, noticeNames[c]);
#endif

	ProcessReceiveBuffer();

	if (c == FSP_NotifyToCommit && !HasDataToDeliver())
	{
		peerCommitted = 1;
	}
	//^The peerCommitted flag can be set if no further data to deliver
	// even if there's no callback function to accept data/flags (as in blocking receive mode).

	SetMutexFree();
}



void CSocketItemDl::CallBackOnBufferReady()
{
	// Although rare, race condition does exist
	if (!WaitUseMutex())
		return;

	FSP_NoticeCode c = (FSP_NoticeCode)_InterlockedExchange8((char*)&pControlBlock->sendAllowedNotice, 0);
	if (c == 0)
	{
		SetMutexFree();
		return;
	}
#ifdef TRACE
	printf_s("\nCallBackOnBufferReady in local fiber#%u, notice: %s\n"
		, fidPair.source, noticeNames[c]);
#endif

	ProcessPendingSend();

	if (c == FSP_NotifyFlushed)
	{
		if (GetState() == CLOSABLE && initiatingShutdown)
		{
			SetState(PRE_CLOSED);
			AppendEoTPacket();
		}
		else
		{
			NotifyOrReturn fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpCommitted, NULL);
#ifdef TRACE
			printf_s("State: %s, initiatingShutdown = %d\n", stateNames[GetState()], initiatingShutdown);
#endif
			if (fp1 != NULL)
				fp1(this, FSP_Send, 0);
		}
	}
	else if (c == FSP_NotifyToFinish && initiatingShutdown)
	{
		NotifyOrReturn fp2 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpFinished, NULL);
		if (fp2 != NULL)
			fp2(this, FSP_Shutdown, 0);
	}

	SetMutexFree();
}



void CSocketItemDl::ArrangeCallbackOnAccepted()
{
	if (context.onAccepted != NULL)
		socketsTLB.ScheduleWork(this, &CSocketItemDl::CallBackOnAccepted);
}



void CSocketItemDl::ArrangeCallbackOnReceive()
{
	if (fpPeeked != NULL || fpReceived != NULL
	 || (pControlBlock->receiveNotice == FSP_NotifyToFinish && fpFinished != NULL))
	{
		socketsTLB.ScheduleWork(this, &CSocketItemDl::CallBackOnReceive);
	}
	else
	{
		CallBackOnReceive();
	}
}



void CSocketItemDl::ArrangeCallbackOnSent()
{
	if (fpCommitted != NULL || fpSent != NULL)
		socketsTLB.ScheduleWork(this, &CSocketItemDl::CallBackOnBufferReady);
	else
		CallBackOnBufferReady();
}
