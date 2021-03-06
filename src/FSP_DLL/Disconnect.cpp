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
		return -EBADF;
	return p->Dispose();
}



// Try to terminate the session gracefully provided that the peer has commit the transmit transaction
// Return 0 if no immediate error, or else the error number
// The callback function might return code of delayed error
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if (p == NULL)
		return -EBADF;
	return p->Shutdown(fp1);
}



// Dispose the socket, recycle the ULA TCB, inform LLS on demand
// Return
//	0 if no error
//	negative if it is the error number
// Remark
//	Unlike other function, mutex lock is treated specially
int  CSocketItemDl::Dispose()
{
	toCancel = 1;
	//^So that WaitUseMutex of other thread could be interrupted

	timestamp_t t0 = NowUTC();
	while (!TryMutexLock())
	{
		if (int64_t(NowUTC() - t0 - MAX_LOCK_WAIT_ms * 1000) > 0)
			return -EDEADLK;
		Sleep(TIMER_SLICE_ms);
	}

	if (pControlBlock == NULL)
	{
		lockOwner = 0;
		return 0;
	}

	toReleaseMemory = 1;
	if (lockDepth <= 1)
		FreeWithReset();
	else
		lockDepth--;
	return 0;
}



// Make sure resource is kept until other threads leave critical section
// Does NOT waits for all callback functions to complete before returning
// in case of deadlock when the function itself is called in some call-back function
// UNRESOLVED!? TODO: Connection resurrection should be able to reuse cached state
void CSocketItemDl::Free()
{
	RecycleSimply();
	CSocketItem::Destroy();
	bzero((octet*)this + sizeof(CSocketItem), sizeof(CSocketItemDl) - sizeof(CSocketItem));
}



// Given
//	ALFID_T		the Application Layer Fiber ID in the local context 
//	ALFID_T		the Application Layer Fiber ID of the parent connection
//	uint32_t	reason code
// Do
//	Instruct LLS to reject the request (if it were to accept)
//	or reset the connection (if it were to multiply)
void LOCALAPI CSocketItemDl::RejectRequest(ALFID_T id1, ALFID_T idParent, uint32_t rc)
{
	CommandRejectRequest objCommand;
	objCommand.opCode = FSP_Reject;
	objCommand.fiberID = id1;
	objCommand.idParent = idParent;
	objCommand.reasonCode = rc;
	Call((UCommandToLLS*)&objCommand);
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
		return (IsInUse() ? -EDEADLK : -EAGAIN);

	if (initiatingShutdown != 0)
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}
	// Avoid double-entering dead-loop, see also WaitEventToDispatch
	if (fpCommitted != NULL)
	{
		SetMutexFree();
		return -EBUSY;
	}
	initiatingShutdown = 1;

	// It prevents dead-loop to check whether it is already in CLOSED state before proactive shut-down
	FSP_Session_State s = GetState();
	if (s == SHUT_REQUESTED || s == CLOSED)
	{
		NotifyOrReturn fp1 = (NotifyOrReturn)_InterlockedExchangePointer((PVOID*)&fpFinished, NULL);
		if (s == SHUT_REQUESTED)
		{
			SetState(CLOSED);
			Call<FSP_Shutdown>();
		}		// assert: FSP_NotifyToFinish has been received and processed. See also WaitEventToDispatch
		//
		if (fp1 != NULL)
			fp1(this, FSP_Shutdown, 0);
		SetMutexFree();
		return 0;
	}

#ifndef _NO_LLS_CALLABLE
	if (s <= ESTABLISHED || s == COMMITTING || s == COMMITTED)
	{
		SetMutexFree();
		return -EDOM;	// Wait for the peer to commit a transmit transaction first before shutdown!
	}
	//
	SetEoTPending();
	if (s == PEER_COMMIT)
	{
		if (HasDataToCommit())
		{
			// flush internal buffer for compression, if it is non-empty
			if (HasFreeSendBuffer())
				BufferData(pendingSendSize);
			// or else just to wait
		}
		else if (skbImcompleteToSend != NULL)
		{
			// terminating the last packet of the stream
			skbImcompleteToSend->SetFlag<TransactionEnded>();
			skbImcompleteToSend->ReInitMarkComplete();
			skbImcompleteToSend = NULL;
			SetState(PRE_CLOSED);
			AppendEoTPacket();
		}
		else
		{
			SetState(PRE_CLOSED);
			AppendEoTPacket();
		}
	}
	//
	if (s == PEER_COMMIT || s == COMMITTING2)
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
	// It must be in CLOSABLE state or later, or NON_EXISTENT after BlockOnCommit
	if (s == CLOSABLE)
	{
		SetState(PRE_CLOSED);
		if (IsEoTPending())
			AppendEoTPacket();
		//
		if (fpFinished != NULL)
		{
			SetMutexFree();
			return 0;
		}
	}
	//
	int32_t deinitWait = CLOSING_TIME_WAIT_ms;
	while (s != SHUT_REQUESTED && s != CLOSED && s != NON_EXISTENT)
	{
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
		//
		deinitWait -= TIMER_SLICE_ms;
		if (deinitWait <= 0)
		{
			Dispose();
			return ETIMEDOUT;		// Warning, not fatal error
		}
		//
		if (!WaitUseMutex())
			return (IsInUse() ? -EDEADLK : 0);

		s = GetState();
	}
#endif
	if (s == SHUT_REQUESTED)
		SetState(s = CLOSED);
	//
	SetMutexFree();
	return 0;
}



// Given
//	CSocketItemDl *		the pointer to the DLL FSP socket
// Do
//	Try to put the socket in the list of the free socket items
void CSocketDLLTLB::FreeItem(CSocketItemDl* p)
{
	CSocketItemDl& r = *p;
	AcquireMutex();

	if (_InterlockedExchange8(&p->inUse, 0) == 0)
	{
		ReleaseMutex();
		return;
	}

	// detach it from inUse list
	if (r.prev == NULL)
		headOfInUse = (CSocketItemDl*)r.next;
	else
		r.prev->next = r.next;

	// attach it to free list
	r.next = NULL;
	r.prev = tail;
	if (tail == NULL)
	{
		head = tail = p;
	}
	else
	{
		tail->next = p;
		tail = p;
	}

	ReleaseMutex();
}
