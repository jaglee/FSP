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
	register CSocketItemDl *p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->Recycle(true);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// return 0 if no error, positive if some warning
// an ill-behaviored ULA could be punished by dead-lock
int CSocketItemDl::Recycle(bool reportError)
{
	if(! IsInUse())
		return EAGAIN;	// warning: already disposed

	register int r = 0;
	if (! lowerLayerRecycled)
	{
		isDisposing = reportError ? 1 : 0;
		bool b = Call<FSP_Recycle>();
		if(b)
			return r;	// Free the socket item when FSP_Recycle called back
		// Shall be rare to fall through:
		r = EIO;		// LLS would eventually timed-out
	}
	//
	NotifyOrReturn fp1 = context.onError;
	CSocketItemDl::FreeItem(this);
	Disable();
	if(reportError && fp1 != NULL)
		fp1(this, FSP_Recycle, -EINTR);
	return r;
}



// Try to commit current transmit transaction
// Return 0 if no immediate error, or else the error number
// The callback function might return code of delayed error
// If the pointer of the callback function is null, 
// blocks until it reaches the state that the transmit transaction has been comitted
DllSpec
int FSPAPI Commit(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->Commit(fp1);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Try to terminate the session gracefully, automatically commit if not yet 
// Return 0 if no immediate error, or else the error number
// The callback function might return code of delayed error
// If the pointer of the callback function is null, blocks until the socket is closed
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		return p->Shutdown(fp1);
	}
	catch(...)
	{
		return -EFAULT;
	}
}




// [API:Shutdown]
//	CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	PRE_CLOSED<-->{keep state}
//	{ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTED, COMMITTING2}{try to commit first, chain async-shutdown}
//	{otherwise: connection not ever established yet}-->{Treat 'Shutdown' command as 'Abort'}
//	ALWAYS assume that only after it has finished receiving is shutdown called
int LOCALAPI CSocketItemDl::Shutdown(NotifyOrReturn fp1)
{
	if(! WaitUseMutex())
		return -EDEADLK;

	if(pControlBlock == NULL || InIllegalState())
	{
		SetMutexFree();
		return -EBADF;
	}

	if(initiatingShutdown)
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}

	if (InState(PRE_CLOSED))
	{
		SetMutexFree();
		return -EBADF;	// If it is in PRE_CLOSED state it MUST be initiatingShutdown!
	}

	initiatingShutdown = 1;

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
	CancelTimer();	// If any; typically because of previous Commit. Shutdown could override Commit
	if(! AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for shutdown");
		SetMutexFree();
		return -EFAULT;
	}

	// If it is committing, wait until it finishes.
	while(fpCommitted != NULL)
	{
		SetMutexFree();
		Sleep(50);
		if(! WaitUseMutex())
			return -EDEADLK;
	}
	fpCommitted = fp1;

	if(InState(CLOSED))
	{
		SetMutexFree(); // So that SelfNotify may call back instantly
		SelfNotify(FSP_NotifyToFinish);
		return 0;
	}

	if(lowerLayerRecycled)
	{
		SetMutexFree();	// So that SelfNotify may call back instantly
		SelfNotify(FSP_NotifyToFinish);
		return 0;
	}

	if (InState(CLOSABLE))
	{
		SetState(PRE_CLOSED);
		SetMutexFree();
		return (Call<FSP_Shutdown>() ? 0 : -EIO);
	}

	return Commit();
}



// Internal API for committing/flushing a transmit transaction
// Assume that it has obtained the mutex lock
// It is somewhat a little tricky to commit a transmit tranaction:
// Case 1, it is in sending a stream or obtaining send buffer, and there are yet some data to be buffered
// Case 2, the send queue is empty at all
// Case 3, there is set some block to be sent in the send queue
// Case 4, all blocks have been sent and the tail of the send queue has already been marked EOT
// Case 5, all blocks have been sent and the tail of the send queue could not set with EOT flag
// [API:Commit]
//	{COMMITTED, CLOSABLE, PRE_CLOSED, CLOSED}-->{keep state}
//	{ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTED, COMMITTING2}{try to commit first, chain async-shutdown}
//	{otherwise: failed}
int LOCALAPI CSocketItemDl::Commit(NotifyOrReturn fp1)
{
	if(! WaitUseMutex())
		return -EDEADLK;

	if(pControlBlock == NULL || InIllegalState())
	{
		SetMutexFree();
		return -EBADF;
	}

	if(InterlockedExchangePointer((PVOID *)& fpCommitted, fp1) != NULL)
	{
#if defined(TRACE) && !defined(NDEBUG)
		printf_s("Commit: the socket is already in commit or graceful shutdown process.\n");
#endif
		SetMutexFree();
		return -EAGAIN;	
	}

	if (InState(COMMITTED) || InState(CLOSABLE) || InState(PRE_CLOSED) || InState(CLOSED))
	{
		SetMutexFree();	// So that SelfNotify may call back instantly
		SelfNotify(FSP_NotifyFlushed);
		return 0;	// It is already in a state that the near end's last transmit transactio has been committed
	}

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
	if(! AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for Commit");
		SetMutexFree();
		return -EFAULT;
	}

	return Commit();
}



int CSocketItemDl::Commit()
{
	isFlushing = 1;

	// The last resort: flush sending stream if it has not yet been committed
	if (InState(COMMITTED))
	{
		SetMutexFree();
		return 0;
	}

	if (InState(COMMITTING) || InState(COMMITTING2))
	{
		SetMutexFree();
		return EBUSY;	// a warning saying that it is COMMITTING
	}

	if (!TestSetState(ESTABLISHED, COMMITTING) && !TestSetState(PEER_COMMIT, COMMITTING2))
	{
		SetMutexFree();
		Recycle();
		return EDOM;	// A warning say that the connection is aborted actually, for it is not in the proper state
	}

	bool yetSomeDataToBuffer = (pendingSendSize > 0);
	SetMutexFree();

	if(fpCommitted == NULL)
	{
		if(! yetSomeDataToBuffer && !Call<FSP_Commit>())
		{
#ifdef TRACE
			printf_s("Fatal error during Commit! Cannot call LLS\n");
#endif
			return -EIO;
		}
		// Assume the caller has set time-out clock
		do
		{
			Sleep(50);
		} while(!InState(CLOSABLE) && !InState(CLOSED)); 
		//
		return 0;
	}

	// Case 1 is handled in DLL while case 2~5 are handled in LLS
	return yetSomeDataToBuffer ? 0 : (Call<FSP_Commit>() ? 0 : -EIO);
}
