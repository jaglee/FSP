/*
 * DLL to service FSP upper layer application
 * part of the SessionCtrl class, Reset and Shutdown
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
		return p->Recycle();
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// return 0 if no error, negative if error, positive if warning
// an ill-behaviored ULA would be punished by dead-lock
int CSocketItemDl::Recycle()
{
	if(! IsInUse())
		return EAGAIN;	// warning: already disposed

	if (lowerLayerRecycled)
	{
		RespondToRecycle();
		return 0;
	}
	bool b = Call<FSP_Recycle>();
	if(b)
		return 0;	// Free the socket item when FSP_Recycle called back
	// Shall be rare:
	socketsTLB.FreeItem(this);
	Disable();
	BREAK_ON_DEBUG();
	return -EIO;
}



// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	-EINTR if locking of the socket was interrupted
//	-EIO if the shutdown packet cannot be sent
//	EAGAIN if the connection is already in the progress of shutdown
//	EBADF if the connection is already released
//	EDOM if the connection could ony be shutdown prematurely, i.e.it is a RESET actually
//	0 if no error
// Remark
//	It is assumed that when Shutdown was called ULA did not expect further data from the remote end
//	The caller should make sure Shutdown is not carelessly called more than once
//	in a multi-thread continual communication context or else connection reuse(resurrection) may be broken
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
//	ESTABLISHED-->COMMITTING {chain async-shutdown}
//	COMMITTING <--> {chain async-shutdown}
//	PEER_COMMIT-->COMMITTING2{chain async-shutdown}
//	COMMITTING2<--> {chain async-shutdown}
//	CLOSABLE-->PRE_CLOSED-->[Send RELEASE]
//	ALWAYS assume that only after it has finished receiving is shutdown called
int LOCALAPI CSocketItemDl::Shutdown(NotifyOrReturn fp1)
{
	if(lowerLayerRecycled)	// no mutex required?!
	{
		RespondToRecycle();
		return 0;
	}

#if defined(TRACE) && !defined(NDEBUG)
	if(InterlockedExchangePointer((PVOID *)& fpRecycled, fp1) != NULL)
		printf_s("Shutdown: the socket is already in graceful shutdown process.\n");
#else
	InterlockedExchangePointer((PVOID *)& fpRecycled, fp1);
#endif

	if(! WaitUseMutex())
		return -EINTR;

	// assert: if the socket is in CLOSED state its LLS image must have been recycled 
	if(pControlBlock == NULL || InState(NON_EXISTENT) || InState(CLOSED))
	{
		SetMutexFree();
		return EBADF;	// A warning saying that the socket has already been closed thoroughly
	}

	initiatingShutdown = 1;

	if (InState(PRE_CLOSED))
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
	if(! AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for shutdown");
		SetMutexFree();
		return -EFAULT;
	}

	if (InState(CLOSABLE))
	{
		SetState(PRE_CLOSED);
		SetMutexFree();
		return (Call<FSP_Shutdown>() ? 0 : -EIO);
	}

	return Commit();
}



// Reserved API for committing/flushing a transmit transaction
// Assume that it has obtained the mutex lock
// It is somewhat a little tricky to commit a transmit tranaction:
// Case 1, it is in sending a stream or obtaining send buffer, and there are yet some data to be buffered
// Case 2, the send queue is empty at all
// Case 3, there is set some block to be sent in the send queue
// Case 4, all blocks have been sent and the tail of the send queue has already been marked EOT
// Case 5, all blocks have been sent and the tail of the send queue could not set with EOT flag
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

	// Case 1 is handled in DLL while case 2~5 are handled in LLS
	return yetSomeDataToBuffer ? 0 : (Call<FSP_Commit>() ? 0 : -EIO);
}


// Callback for SHUTDOWN, triggered by the near end, to recycle the socket
// Important! ULA should not access the socket itself anyway
// UNRESOLVED!? Should it be thread-safe?!
void CSocketItemDl::RespondToRecycle()
{
	NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *)& fpRecycled, NULL);
	socketsTLB.FreeItem(this);
	Disable();
	if (fp1 != NULL)
		fp1(this, FSP_NotifyRecycled, 0);
}
