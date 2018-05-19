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



int  CSocketItemDl::Dispose()
{

	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : 0);
	if (chainingReceive == 0 && chainingSend == 0)
		return RecycLocked();
	toDispose = 1;
	SetMutexFree();
	return 0;
}



// return 0 if no error, positive if some warning
// assume the socket has been locked
int CSocketItemDl::RecycLocked()
{
	register int r = 0;
	if (! lowerLayerRecycled)
	{
		if (Call<FSP_Recycle>())
		{
			SetMutexFree();
			return r;	// Free the socket item when FSP_Recycle called back
		}
		// Shall be rare to fall through:
		r = EIO;		// LLS would eventually timed-out
	}
	//
	FreeAndDisable();
	SetMutexFree();
	return r;
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
}



// Try to terminate the session gracefully, automatically commit if not yet 
// Return 0 if no immediate error, or else the error number
// The callback function 'onFinish' might return code of delayed error
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(hFSPSocket);
	if(p == NULL)
		return -EFAULT;
	return p->Shutdown();
}



// [API:Shutdown]
//	CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	PRE_CLOSED<-->{keep state}
//	{ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTED, COMMITTING2}{try to commit first, chain async-shutdown}
//	{otherwise: connection not ever established yet}-->{Treat 'Shutdown' command as 'Abort'}
//	ALWAYS assume that only after it has finished receiving is shutdown called
// Remark
//	Shutdown is always somewhat blocking. It is deliberate blocking
//	if 'onFinish' function pointer in the connection context is NULL,
//	undeliberate if it internally waits for previous Commit to finish.
//	And it always assume that the caller does not accept further data
//	In deliberate blocking mode, it sends RELEASE immediately
//	after data has been committed but does not wait for acknowledgement
int CSocketItemDl::Shutdown()
{
	if(! WaitUseMutex())
		return (IsInUse() ? -EDEADLK : 0);

	if(initiatingShutdown)
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}
	initiatingShutdown = 1;

	if (lowerLayerRecycled || InState(CLOSED))
	{
		SetMutexFree(); // So that SelfNotify may call back instantly
		if (context.onFinish != NULL)
			SelfNotify(FSP_NotifyToFinish);
		//^because initiatingShutdown is set FSP_NotifyRecycled is reported to ULA instead
		return 0;
	}

#ifndef _NO_LLS_CALLABLE
	if(! AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for shutdown");
		SetMutexFree();
		return -EFAULT;
	}
#endif

	if (fpCommitted != NULL && context.onFinish != NULL)
	{
		SetMutexFree();
		return 0;	// Full-fledged asynchronous mode
	}

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
#ifndef _NO_LLS_CALLABLE
	do
	{
		if (!InState(COMMITTED) && !InState(CLOSABLE) && !InState(PRE_CLOSED))
		{
			int r = Commit();
			if (r < 0)
				return r;
			if (!WaitUseMutex())
				return (IsInUse() ? -EDEADLK : 0);
		}
		//
		if (InState(CLOSABLE))
		{
			bool b = Call<FSP_Shutdown>();
			if (context.onFinish != NULL || !b)
			{
				SetMutexFree();
				return (b ? 0 : -EIO);
			}
		}
		//
		bool b = InState(CLOSED) || InState(NON_EXISTENT);
		SetMutexFree();
		if (b)
			return 0;
		//
		Sleep(TIMER_SLICE_ms);
	} while (WaitUseMutex());
#endif
	return (IsInUse() ? -EDEADLK : 0);
}
