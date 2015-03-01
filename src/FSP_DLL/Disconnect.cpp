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
#include <time.h>

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
//	NotifyOrReturn	the callback function
// Return
//	-EBADF if the connection is not in valid context
//	-EDOM if the connection is not in proper state
//	-EIO if the COMMIT packet cannot be sent
//	0 if no immediate error
// Remark
//	the callback function may return delayed error such as Commit rejected the remote end
//	The connection would remain in the COMMITTED, CLOSABLE or CLOSED state,
//	or be set to the COMMITTING or COMMITTING2 state immediately.
DllSpec
int FSPAPI Commit(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	TRACE_HERE("called");

	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if (p == NULL || p->InState(NON_EXISTENT))
			return -EBADF;
		//
		if(! p->SetFlushing(fp1))
			return -EDOM;
		//
		if(p->InState(COMMITTED) || p->InState(CLOSABLE) || p->InState(PRE_CLOSED) || p->InState(CLOSED))
			return EBADF;	// warning that the socket has already been committed
		//
		return p->Commit();
	}
	catch(...)
	{
		return -EFAULT;
	}
}




// Given
//	FSPHANDLE		the FSP socket
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
int FSPAPI Shutdown(FSPHANDLE hFSPSocket)
{
	TRACE_HERE("called");
	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if (p == NULL || !p->IsInUse())
			return -EBADF;
		//
		// ALWAYS assume shutdown is only called after it has finished receiving
		// UNRESOLVED! TODO: timeout management?
		if(! p->WaitSetMutex())
			return -EINTR;

		if(p->InState(CLOSED) || p->InState(NON_EXISTENT))
		{
			p->SetMutexFree();
			return EBADF;	// A warning saying that the socket has already been closed
		}

		if (p->InState(COMMITTED) || p->InState(CLOSABLE))
		{
			// Send RELEASE and wait peer's RELEASE. LLS to signal NotifyFinish, NotifyReset or NotifyTimeout
			p->SetMutexFree();
			return (p->Call<FSP_Shutdown>() ? 0 : -EIO);
		}

		if (p->InState(PRE_CLOSED))
		{
			p->SetMutexFree();
			return EAGAIN;	// A warning saying that the socket is already in graceful shutdown process
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

		p->SetFlushing(CSocketItemDl::FlushingFlag::FLUSHING_SHUTDOWN);
		p->SetMutexFree();
		return p->Commit();
	}
	catch(...)
	{
		return -EFAULT;
	}
}



//[API: Commit]
//	{ACTIVE, RESUMING}-->COMMITTING-->[Urge COMMIT]
//	PEER_COMMIT-->COMMITTING2-->[Urge COMMIT]{restart keep-alive}
// Return
//	-EINTR if cannot gain the exclusive lock
//	-EDOM if in erraneous state
//	-ETIMEDOUT if blocked due to lack of buffer 
// Remark
//	It might be blocking to wait the send buffer slot to buffer the COMMIT packet
int CSocketItemDl::Commit()
{
	eomSending = EndOfMessageFlag::END_OF_SESSION;
	//
	if(! WaitSetMutex())
		return -EINTR;

	if (InState(ESTABLISHED) || InState(RESUMING))
	{
		SetState(COMMITTING);
	}
	else if (InState(PEER_COMMIT))
	{
		SetState(COMMITTING2);
	}
	else if (!InState(COMMITTING) && !InState(COMMITTING2))
	{
		SetMutexFree();
		return -EDOM;
	}
	//
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetLastBufferedSend();
	if(skb != NULL && skb->Lock())
	{
		if(skb->opCode == PURE_DATA || skb->opCode == RESUME || skb->opCode == PERSIST)
		{
			skb->SetFlag<TO_BE_CONTINUED>(false);
		}
		else
		{
			skb->Unlock();
			skb = NULL;
		}
	}
	// allocate new slot to hold the COMMIT packet
	if(skb == NULL)
	{
		time_t t0 = time(NULL);
		while((skb = pControlBlock->GetSendBuf()) == NULL)
		{
			SetMutexFree();
			Sleep(1);
			if(time(NULL) - t0 > TRASIENT_STATE_TIMEOUT_ms)
				return -ETIMEDOUT;
			if(! WaitSetMutex())
				return -EINTR;
		}
		skb->len = 0;
	}
	// UNRESOLVED! The IS_COMPLETED flag of COMMIT is reused for accumulative acknowledgment?
	skb->opCode = COMMIT;
	skb->SetFlag<IS_COMPLETED>();
	//
	skb->Unlock();
	SetMutexFree();
	return (Call<FSP_Urge>() ? 0 : -EIO);
}


// Remark
//	Assume [API:Commit] has been called if it is not in CLOSABLE state
// TODO: End of Message shall be delivered to ULA
void CSocketItemDl::ToConcludeCommit()
{
	char isFlushing = GetResetFlushing();
	SetMutexFree();
	if(isFlushing == ONLY_FLUSHING)
	{
#ifdef TRACE
		printf_s("ONLY_FLUSHING\n");
#endif
		NotifyOrReturn fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *)& fpCommit, NULL);
		if (fp1 != NULL)
			fp1(this, FSP_NotifyFlushed, 0);
	}
	else if(isFlushing == FLUSHING_SHUTDOWN)
	{
#ifdef TRACE
		printf_s("FLUSHING_SHUTDOWN\n");
#endif
		Call<FSP_Shutdown>();
	}
}
