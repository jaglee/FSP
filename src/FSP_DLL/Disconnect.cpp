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
	return Call<FSP_Recycle>() ? 0 : -EIO;
}




// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	-EBADF if the connection is not in proper state
//	-EINTR if locking of the socket was interrupted
//	-EIO if the shutdown packet cannot be sent
//	EDOM if the connection is shutdown down prematurely, i.e.it is a RESET actually
//	EBADF if the connection is already closed
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
		if (p == NULL)
			return -EBADF;
		//
		// ALWAYS assume shutdown is only called after it has finished receiving
		if(! p->WaitUseMutex())
			return -EINTR;

		if(p->InState(CLOSED) || p->InState(NON_EXISTENT))
		{
			p->SetMutexFree();
			return EBADF;	// A warning saying that the socket has already been closed
		}

		if (p->InState(PRE_CLOSED))
		{
			p->SetMutexFree();
			return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
		}

		if (p->InState(COMMITTED) || p->InState(CLOSABLE))
		{
			// Send RELEASE and wait peer's RELEASE. LLS to signal NotifyFinish, NotifyReset or NotifyTimeout
			p->SetMutexFree();
			return (p->Call<FSP_Shutdown>() ? 0 : -EIO);
		}

		if(! p->TestSetState(ESTABLISHED, COMMITTING)
		&& ! p->TestSetState(RESUMING, COMMITTING)
		&& ! p->InState(COMMITTING)
		&& ! p->TestSetState(PEER_COMMIT, COMMITTING2)
		&& ! p->InState(COMMITTING2))
		{
			p->SetMutexFree();
			p->Recycle();
			return EDOM;	// A warning say that the connection is aborted, actually
		}

		if(! p->SetFlushingFP(fp1))
		{
			p->SetMutexFree();
			return -EAGAIN;
		}

		p->SetFlushing(CSocketItemDl::FlushingFlag::FLUSHING_SHUTDOWN);
		p->SetMutexFree();
		return p->Commit();
	}
	catch(...)
	{
		return -EFAULT;
	}
}
