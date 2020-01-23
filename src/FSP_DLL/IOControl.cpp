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
	CommandNewSession objCommand;
	FSP_SocketParameter stubParameter;
	PFSP_Context psp1 = &stubParameter;
	memset(psp1, 0, sizeof(FSP_SocketParameter));
	return (CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand));
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
			return -EDOM;
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



// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	register long vector = 0;
	while (LockAndValidate())
	{
		register FSP_NoticeCode notice = (FSP_NoticeCode)_InterlockedExchange8(&pControlBlock->notices.nmi, NullNotice);
		// data race does occur, so we have to double-test to avoid lost of suppressed soft interrupts
		// built-in rule: bit 0 of the soft interrupt vector is the flag for DLL being in event loop
		if (notice == NullNotice)
		{
			if (vector == 0)
			{
				vector = _InterlockedExchange(&pControlBlock->notices.vector, 1) & ((1 << SMALLEST_FSP_NMI) - 2);
				if (vector == 0)
				{
					vector = _InterlockedExchange(&pControlBlock->notices.vector, 0) & ((1 << SMALLEST_FSP_NMI) - 2);
					if (vector == 0)
					{
						SetMutexFree();
						break;
					}
					//
					_InterlockedOr(&pControlBlock->notices.vector, 1);
				}
			}
			notice = NullNotice;
			for (register int i = 1; i <= LARGEST_FSP_NOTICE; i++)
			{
				if (vector & (1 << i))
				{
					notice = (FSP_NoticeCode)i;
					vector ^= 1 << i;
					break;
				}
			}
			assert(notice != NullNotice);
		}
#ifdef TRACE
		printf_s("\nIn local fiber#%u, state %s\tnotice: %s\n"
			, fidPair.source, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
		if (notice > FSP_NotifyToFinish)
			lowerLayerRecycled = 1;
		//
		FSP_Session_State s0;
		NotifyOrReturn fp1;
		switch (notice)
		{
		case FSP_NotifyListening:
			CancelTimeout();		// See also ::ListenAt
			SetMutexFree();
			break;
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
			fp1 = (NotifyOrReturn)context.onAccepted;
			SetMutexFree();
			if (fp1 != NULL)
				((CallbackConnected)fp1)(this, &context);
			if (!LockAndValidate())
				return;
			ProcessReceiveBuffer();	// SetMutexFree();
			break;
		case FSP_NotifyMultiplied:	// See also @LLS::Connect()
			CancelTimeout();		// If any
			fidPair.source = pControlBlock->nearEndInfo.idALF;
			ProcessReceiveBuffer();	// SetMutexFree();
			if (!LockAndValidate())
				return;
			// To inherently chain WriteTo/SendInline with Multiply
			ProcessPendingSend();	// SetMutexFree();
			break;
		case FSP_NotifyDataReady:
			ProcessReceiveBuffer();	// SetMutexFree();
			break;
		case FSP_NotifyBufferReady:
			ProcessPendingSend();	// SetMutexFree();
			break;
		case FSP_NotifyToCommit:
			// See also FSP_NotifyDataReady, compare with FSP_NotifyFlushed
			ProcessReceiveBuffer();	// SetMutexFree();
			if (!LockAndValidate())
				return;
			// Even if there's no callback function to accept data/flags (as in blocking receive mode)
			// the peerCommitted flag can be set if no further data to deliver
			if (!HasDataToDeliver())
				peerCommitted = 1;
			//
			if (InState(CLOSABLE) && initiatingShutdown)
			{
				SetState(PRE_CLOSED);
				AppendEoTPacket();
				Call<FSP_Urge>();
			}
			SetMutexFree();
			break;
		case FSP_NotifyFlushed:
			ProcessPendingSend();	// SetMutexFree();
			if (!LockAndValidate())
				return;
			//
			s0 = GetState();
			if (!initiatingShutdown || s0 < CLOSABLE)
			{
				fp1 = NULL;
				if (s0 == COMMITTED || s0 >= CLOSABLE)
					fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpCommitted, fp1);
				SetMutexFree();
				if (fp1 != NULL)
					fp1(this, FSP_Send, 0);
			}
			else if (s0 == CLOSABLE)
			{
				SetState(PRE_CLOSED);
				AppendEoTPacket();
				Call<FSP_Urge>();
				SetMutexFree();
			}
#ifndef NDEBUG
			else
			{
				printf_s("Protocol implementation error?\n"
					"Should not get FSP_NotifyFlushed in state later than CLOSABLE after graceful shutdown.\n");
			}
#endif
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
		case FSP_NotifyRecycled:
			fp1 = context.onError;
			EnableLLSInterrupt();
			RecycLocked();		// CancelTimer(); SetMutexFree();
			if (!initiatingShutdown && fp1 != NULL)
				fp1(this, FSP_Shutdown, ENXIO);		// a warning for unexpected shutdown
			return;
		case FSP_NameResolutionFailed:
			FreeAndNotify(InitConnection, (int)notice);
			// UNRESOLVED!? There could be some remedy if name resolution failed?
			return;
		case FSP_IPC_CannotReach:
			fp1 = context.onError;
			s0 = GetState();
			Free();
			if (fp1 == NULL)
				return;
			//
			if (s0 == LISTENING)
				fp1(this, FSP_Listen, -EIO);
			else if (s0 != CHALLENGING)
				fp1(this, (s0 == CLONING ? FSP_Multiply : InitConnection), -EIO);
			return;
		case FSP_MemoryCorruption:
		case FSP_NotifyTimeout:
		case FSP_NotifyReset:
			FreeAndNotify(NullCommand, (int)notice);
			return;
		default:
			;	// But NullNotice is impossible
		}
	}
	if (pControlBlock == NULL)
		Free();
}



// The function called back as soon as the one-shot timer counts down to 0
// Suppose that the lower layer recycle LRU
void CSocketItemDl::TimeOut()
{
	bool b = TryMutexLock();
	if (!IsInUse())
	{
		if (b)
			SetMutexFree();
		return;
	}

	if (!b)
	{
		AddOneShotTimer(TIMER_SLICE_ms);
		inUse = 0;	// Force WaitUseMutex to abort
		return;
	}

	FreeAndNotify(NullCommand, (int)FSP_NotifyTimeout);
}
