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
	TRACE_HERE("called");
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
	TRACE_HERE("called");
	if(! IsInUse())
		return EAGAIN;	// warning: already disposed

	// The shared control block MUST be preserved, or else LLS might encountered error
	// So every time a control block is re-used, it MUST be re-initialized
	socketsTLB.FreeItem(this);
	if (lowerLayerRecycled)
	{
		RespondToRecycle();
		return 0;
	}
	return Call<FSP_Recycle>() ? 0 : -EIO;
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
	TRACE_HERE("called");
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



// PEER_COMMIT-->[API:Send{ flush }]-->COMMITTING2{ chain async - shutdown }
// CLOSABLE-->[Send RELEASE]-->PRE_CLOSED
// ALWAYS assume that only after it has finished receiving is shutdown called
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
	if(InState(NON_EXISTENT) || InState(CLOSED))
	{
		SetMutexFree();
		return EBADF;	// A warning saying that the socket has already been closed thoroughly
	}

	initiatingShutdown = 1;
	isFlushing = 1;

	if (InState(PRE_CLOSED))
	{
		SetMutexFree();
		return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
	}

	// Send RELEASE and wait echoed RELEASE. LLS to signal FSP_NotifyRecycled, NotifyReset or NotifyTimeout
	if (InState(CLOSABLE))
	{
		SetState(PRE_CLOSED);
		SetMutexFree();
		return (Call<FSP_Shutdown>() ? 0 : -EIO);
	}

	// The last resort: flush sending stream if it has not yet been committed
	int r = 0;
	if(InState(COMMITTED))
		goto l_finish;

	if(InState(COMMITTING) || InState(COMMITTING2))
	{
		r = EBUSY;	// a warning saying that it is COMMITTING
		goto l_finish;
	}

	if(! TestSetState(ESTABLISHED, COMMITTING) && ! TestSetState(PEER_COMMIT, COMMITTING2))
	{
		SetMutexFree();
		Recycle();
		return EDOM;	// A warning say that the connection is aborted actually, for it is not in the proper state
	}

	r = (Call<FSP_Commit>() ? 0 : -EIO);

l_finish:
	AddOneShotTimer(TRASIENT_STATE_TIMEOUT_ms);
	SetMutexFree();
	return r;
}



// Callback for SHUTDOWN, triggered by the near end, to recycle the socket
// Important! ULA should not access the socket itself anyway
// UNRESOLVED!? Should it be thread-safe?!
void CSocketItemDl::RespondToRecycle()
{
	NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *)& fpRecycled, NULL);
	socketsTLB.FreeItem(this);
	this->Destroy();
	if (fp1 != NULL)
		fp1(this, FSP_NotifyRecycled, 0);
}
