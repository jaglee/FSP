/*
 * DLL to service FSP upper layer application
 * Shutdown, Dispose and related functions
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

// return 0 if no error, negative if error, positive if warning
DllExport
int FSPAPI Dispose(FSPHANDLE hFSPSocket)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	return p->Dispose();
}



// Dispose the socket, recycle the ULA TCB, inform LLS on demand
// Return
//	0 if no error
//	negative if it is the error number
// Remark
//	For active/initiative socket the LLS TCB cache is kept if it is not aborted
//	For passive/listening socket it releases LLS TCB as well, and to expect NotifyRecycled
int  CSocketItemDl::Dispose()
{
	if (InState(NON_EXISTENT))
		return 0;

	uint64_t t0 = GetTickCount64();
	inUse = 0;	
	//^So that WaitUseMutex of other thread could be interrupted
	// Expanding and tuning WaitUseMutex():
	while (!TryMutexLock())
	{
		if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			return -EDEADLK;
		//
		Sleep(TIMER_SLICE_ms);
	}
	if(pControlBlock == NULL || pControlBlock->state >= CLOSABLE)
		return RecycLocked();
	//
	SetMutexFree();
	return Call<FSP_Reject>() ? 0 : -EIO;
}



// UNRESOLVED!? Implement LRU for better performance
// assume the socket has been locked
int CSocketItemDl::RecycLocked()
{
	FreeAndDisable();
	SetMutexFree();
	return 0;
}



// Make sure resource is kept until other threads leave critical section
// Does NOT waits for all callback functions to complete before returning
// in case of deadlock when the function itself is called in some call-back function
void CSocketItemDl::Disable()
{
	register HANDLE h;
	CancelPolling();
	CancelTimeout();
	if((h = InterlockedExchangePointer((PVOID *) & theWaitObject, NULL)) != NULL)
		UnregisterWaitEx(h, NULL);
	//
	CSocketItem::Destroy();
	memset((octet *)this + sizeof(CSocketItem), 0, sizeof(CSocketItemDl) - sizeof(CSocketItem));
}



// Set the function to be called back on passively shutdown by the remote end
DllSpec
int FSPAPI SetOnRelease(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if (p == NULL)
		return -EFAULT;
	return p->SetOnRelease(fp1);
}



// Try to terminate the session gracefully provided that the peer has commit the transmit transaction
// Return 0 if no immediate error, or else the error number
// The callback function might return code of delayed error
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	return p->Shutdown(fp1);
}



// [API:Shutdown]
//	PEER_COMMIT-->COMMITTING2-->{try to commit first}CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	COMMITTING2-->{try to commit first}CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	SHUT_REQUESTED-->CLOSED
//	PRE_CLOSED<-->{keep state with warning}
//	CLOSED<-->{keep state with warning}
//	{otherwise: illegal to Shutdown. May abort the connection by calling Dispose instead}
// Remark
//	Although the result is a side-effect, when the socket is already closed 
//	reset of fpFinished prevents it from being called recursively.
int CSocketItemDl::Shutdown()
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : 0);

	if (lowerLayerRecycled || InState(SHUT_REQUESTED) || InState(CLOSED))
	{
		NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID*)& fpFinished, NULL);
		RecycLocked();		// CancelTimer(); SetMutexFree();
		if (fp1 != NULL)
			fp1(this, FSP_NotifyRecycled, InState(SHUT_REQUESTED) ? 0 : EAGAIN);
		return 0;
	}

	if (initiatingShutdown != 0)
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}
	initiatingShutdown = 1;

#ifndef _NO_LLS_CALLABLE
	int32_t deinitWait = DEINIT_WAIT_TIMEOUT_ms;
	FSP_Session_State s = GetState();
	if (s <= ESTABLISHED || s == COMMITTING || s == COMMITTED)
	{
		SetMutexFree();
		return -EDOM;	// Wait for the peer to commit a transmit transaction first before shutdown!
	}
	//
	SetEoTPending();
	if(s == PEER_COMMIT)
	{
		if (HasDataToCommit())
		{
			// flush internal buffer for compression, if it is non-empty
			if (HasFreeSendBuffer())
			{
				BufferData(pendingSendSize);
				Call<FSP_Urge>();
			}
		}
		else if (skbImcompleteToSend != NULL)
		{
			// terminating the last packet of the stream
			skbImcompleteToSend->SetFlag<TransactionEnded>();
			skbImcompleteToSend->ReInitMarkComplete();
			skbImcompleteToSend = NULL;
			MigrateToNewStateOnCommit();
			// No, RELEASE packet may not carry payload.
			AppendEoTPacket(RELEASE);
			Call<FSP_Urge>();
			//^It may or may not be success, but it does not matter
		}
		else if (AppendEoTPacket(RELEASE))
		{
			Call<FSP_Urge>();
		}
		s = GetState();	// it may be in COMMITTING2 or still in PEER_COMMIT state
	}
	//
	if (s == COMMITTING2)
	{
		if (fpFinished != NULL)
		{
			SetMutexFree();
			return 0;		// asynchronous mode
		}
		//
		int r = BlockOnCommit();
		if (r < 0)
			return r;
		// BlockOnCommit would free the mutex lock on error
		s = GetState();
	}
	//
	for (; s != CLOSED && s != NON_EXISTENT; s = GetState())
	{
		if (s == CLOSABLE)
		{
			SetState(PRE_CLOSED);
			if (IsEoTPending() && AppendEoTPacket(RELEASE))
				Call<FSP_Urge>();
			//
			if (fpFinished != NULL)
			{
				SetMutexFree();
				return 0;
			}
		}
		SetMutexFree();
		if (fpFinished != NULL)
			return 0;		// asynchronous mode
		//
		Sleep(TIMER_SLICE_ms);
		//
		if (s >= CLOSABLE)
		{
			deinitWait -= TIMER_SLICE_ms;
			if (deinitWait <= 0)
				return ETIMEDOUT;		// Warning, not fatal error
		}
		//
		if (!WaitUseMutex())
			return (IsInUse() ? -EDEADLK : 0);
	}
#endif
	SetMutexFree();
	return 0;
}
