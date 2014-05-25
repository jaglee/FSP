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

// abort the connection indicated by the give socket handle instantly
// return 0 if no zero, negative if error, positive if warning
DllExport
int FSPAPI Reset(FSPHANDLE hFSPSocket)
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
		return 1;	// warning: already disposed

	// The shared control block MUST be preserved, or else LLS might encountered error
	// So every time a control block is re-used, it MUST be re-initialized
	socketsTLB.FreeItem(this);
	return Call<FSP_Dispose>() ? 0 : -EIO;
}


// Given
//	FSPHANDLE		the FSP socket
// Do
//	Check state at first (in CLOSABLE state just return, not in [ACTIVE, PAUSING, RESUMING] return error)  
//	Then migrate to the PAUSING state and urge LLS to queue and send, if possibly, the ADJOURN command
// Remark
//	The connection would be set to the PAUSING state immediately. In the PAUSING state, no data would be accepted
DllSpec
int FSPAPI Adjourn(FSPHANDLE hFSPSocket)
{
	TRACE_HERE("called");

	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(p == NULL)
			return -EBADF;
		//
		if(p->StateEqual(CLOSABLE) || p->StateEqual(CLOSED) || p->StateEqual(NON_EXISTENT))
		{
			p->NotifyError(FSP_NotifyFlushed, 0);
			return 0;
		}
		//
		if(! p->StateEqual(ESTABLISHED) && ! p->StateEqual(PAUSING) && ! p->StateEqual(RESUMING))
			return -EDOM;
		//
		p->SetFlushing();
		return p->Adjourn();
	}
	catch(...)
	{
		return -EFAULT;
	}
}




// Given
//	FSPHANDLE		the FSP socket
// Do
//	Check state at first:
//		in CLOSABLE state make state migration immediate and return,
//		in CLOSED state just return, 
//		not in [ACTIVE, PAUSING, RESUMING] return error
//	Set FLUSHING_SHUTDOWN flag so that 'Adjourn' is permanent otherwise
// Remark
//	The caller should make sure Shutdown is not carelessly called more than once in a multi-thread,
//	continual communication context or else connection reuse(resurrection) may be broken
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket)
{
	TRACE_HERE("called");
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(p == NULL)
			return -EBADF;
		//
		// ALWAYS assume shutdown is only called after it has finished receiving
		// UNRESOLVED! TODO: timeout management?
		if(! p->WaitSetMutex())
			return -EINTR;
		if(! p->IsInUse() || p->StateEqual(CLOSED) || p->StateEqual(NON_EXISTENT))
		{
			p->SelfNotify(FSP_NotifyRecycled);
			p->SetMutexFree();
			return EBADF;	// A warning saying that the socket has already been closed
		}

		if (p->StateEqual(CLOSABLE))
		{
			p->SetMutexFree();
			return p->Call<FSP_Shutdown>();
		}

		if(! p->TestSetState(ESTABLISHED, PAUSING) && ! p->StateEqual(PAUSING) && ! p->TestSetState(RESUMING, PAUSING))
		{
			p->SetMutexFree();
			return -EDOM;
		}

		p->SetFlushing(CSocketItemDl::FlushingFlag::FLUSHING_SHUTDOWN);
		p->SetMutexFree();
		return p->Adjourn();
	}
	catch(...)
	{
		return -EFAULT;
	}
}




// Remark
//	CLOSABLE-->[Snd FINISH]-->CLOSED
//	Assume [API:Adjourn] has been called if it is not in CLOSABLE state
// See also ToConcludeClose()
// TODO: End of Message shall be delivered to ULA
// When the SCB is in PAUSING state, LLS triggers the synchronization event whenever a legitimate ACK_FLUSH is received
// The event handler in DLL check the SCB state. If it adheres to rule, the state would be changed into CLOSABLE
// and the working process would callback the notification function
void CSocketItemDl::ToConcludeAdjourn()
{
	// Only all packet sent acknowledged(and no further data to send) may it be closable
	// there might be some curious packet in the receive buffer but it is assumed
	// that ULA could afford possible loss of remote data in the PAUSING state
	if(pControlBlock->CountSendBuffered() != 0)
	{
		TRACE_HERE("On ACK_FLUSH there should be no data in flight");
		SetMutexFree();
		return;
	}
	SetState(CLOSABLE);
	//
	char isFlushing = GetResetFlushing();
	SetMutexFree();
	if(isFlushing == ONLY_FLUSHING)
	{
#ifdef TRACE
		printf_s("ONLY_FLUSHING\n");
#endif
		NotifyError(FSP_NotifyFlushed, 0);
	}
	else if(isFlushing == FLUSHING_SHUTDOWN)
	{
#ifdef TRACE
		printf_s("FLUSHING_SHUTDOWN\n");
#endif
		Call<FSP_Shutdown>();
	}
}


// RESET
//	{CONNECT_BOOTSTRAP, CHALLENGING, CONNECT_AFFIRMING, QUASI_ACTIVE, CLONING, ACTIVE, PAUSING, RESUMING, CLOSABLE}
//		-->[Notify]-->NON_EXISTENT
//	Otherwise<-->{Ignore}
// Remark
//	ULA shall not re-free the socket
void CSocketItemDl::OnGetReset()
{
	FSP_Session_State s = (FSP_Session_State)InterlockedExchange((LONG *)& pControlBlock->state, NON_EXISTENT);
	SetMutexFree();
	if (s == PAUSING)
		NotifyError(FSP_NotifyFlushed, -ESRCH);	// got RESET while waiting(searching) ACK_FLUSH
	else
		NotifyError(FSP_NotifyReset, -EINTR);
	//
	socketsTLB.FreeItem(this);
	Destroy();	// this is different from Recyle()
}
