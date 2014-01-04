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
//	NotifyOrReturn	the pointer to the function called back when it is in the CLOSABLE state
//					(or the operation is canceled)
// Do
//	Check state at first (in CLOSABLE state just return, not in [ACTIVE, PAUSING, RESUMING] return error)  
//	Then queue the ADJOURN command packet in the send buffer; if the last packet in the send buffer has
//	not been sent yet the ADJOURN command is piggybacked on that packet
// Remark
//	The connection would be set to the PAUSING state immediately. In the PAUSING state, no data would be accepted
DllSpec
int FSPAPI Adjourn(FSPHANDLE hFSPSocket, NotifyOrReturn fp1)
{
	TRACE_HERE("called");

	register CSocketItemDl * p = (CSocketItemDl *)hFSPSocket;
	try
	{
		if(p == NULL)
			return -EBADF;
		if(fp1 == NULL)
			return -EACCES;
		//
		if(p->StateEqual(CLOSABLE) || p->StateEqual(CLOSED) || p->StateEqual(NON_EXISTENT))
		{
			fp1(p, FSP_NotifyFlushed, 0);
			return 0;
		}
		//
		if(! p->StateEqual(ESTABLISHED) && ! p->StateEqual(PAUSING) && ! p->StateEqual(RESUMING))
			return -EDOM;
		//
		return p->Adjourn(fp1);
	}
	catch(...)
	{
		return -EFAULT;
	}
}


// DO
//	Append ADJOURN packet in the send queue. if the last packet in the queue is not sent yet and it is a data packet
//	(PURE_DATA, PERSIST or ADJOURN) then change the opcode to ADJOURN and mark it as EOM.
//	Urge LLS to send, silently
// Remark
//	Safely assume that receiving is disabled when PAUSING, to exploit asymmetry of FSP
//	See also ToConcludeAdjourn() and CSocketItemEx::TimeOut() in FSP_SRV(LLS)
int CSocketItemDl::Adjourn(NotifyOrReturn fp1)
{
	if(! WaitSetMutex())
		return -EINTR;	// ill-behaviored ULA would be punished by dead-loop

	pControlBlock->furtherToSend = false;	// if it is ever set to true
	SetState(PAUSING);
	SetFlushCallback(fp1);

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetLastBufferedSend();
	if (skb == NULL || skb->opCode != PURE_DATA && skb->opCode != PERSIST && skb->opCode != ADJOURN)
	{
#ifdef TRACE
		printf_s("\nNo packet to piggyback the ADJOURN command, allocate new\n");
#endif
		skb = GetSendBuf();
		if(skb == NULL)	// how on earth could it happen? ill-behaviored ULA
		{
#ifdef TRACE
			printf_s("\nThere is no space in the send window to buffer the new ADJOURN command!\n");
#endif
			SetMutexFree();
			return -ENOMEM;
		}
		skb->len = 0;
	} 
	else if(! skb->MarkInSending())
	{
#ifdef TRACE
		printf_s("\nThe last packet is being sent, cannot piggyback the ADJOURN command, allocate new\n");
#endif
		ControlBlock::PFSP_SocketBuf skb2 = GetSendBuf();
		if(skb2 == NULL)
		{
#ifdef TRACE
			printf_s("\nNo space in the send window to buffer the ADJOURN command while the last packet is being sent.\n");
#endif
			SetMutexFree();
			return -ENOMEM;
		}
		skb = skb2;
		skb->len = 0;
	}
	skb->opCode = ADJOURN;
	skb->SetFlag<TO_BE_CONTINUED>(false);
	skb->MarkUnsent();
	skb->SetFlag<IS_COMPLETED>();

	// don't care 'compressing' flag of the tail packet
	//
	SetMutexFree();
	//
	// Note that even if the sync-event happens to be triggered when sending, callback function
	// is not being called if there exists packet in flight 
	return Call<FSP_Send>(TRUE) ? 0 : -EIO;
}


// Given
//	FSPHANDLE		the FSP socket
// Do
//	Check state at first (in CLOSED state just return, in CLOSABLE state make state migration immediate and return,
//	  not in [ACTIVE, PAUSING, RESUMING] return error)
//  Chain Adjourn operation, with TryClose as the callback function
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
		if(p->IsClosable())
		{
			p->SetMutexFree();
			return p->Call<FSP_Shutdown>();
		}

		if(! p->TestSetState(ESTABLISHED, PAUSING) && ! p->StateEqual(PAUSING) && ! p->TestSetState(RESUMING, PAUSING))
		{
			p->SetMutexFree();
			return -EDOM;
		}

		p->SetMutexFree();
		return p->Adjourn(CSocketItemDl::TryClose);
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
void FSPAPI CSocketItemDl::TryClose(FSPHANDLE h, FSP_ServiceCode c, int r)
{ 
#ifdef TRACE
	printf_s("TryClose 0x%08X, service code = %d, return value = %d\n", (LONG)h, (int)c, r);
#endif
	try
	{
		if(c == FSP_NotifyFlushed && r >= 0)
			((CSocketItemDl *)h)->Call<FSP_Shutdown>();
		else
			((CSocketItemDl *)h)->NotifyError(c, r);
	}
	catch(...)
	{
		return;
	}
}



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
	NotifyOrReturn fp1 = GetResetFlushCallback();
	SetMutexFree();
	if(fp1 != NULL)	// for active adjourn acknowledged by ACK_FLUSH
		fp1(this, FSP_NotifyFlushed, 0);
}



// RESET
//	{CONNECT_BOOTSTRAP, CHALLENGING, CONNECT_AFFIRMING, QUASI_ACTIVE, CLONING, ACTIVE, PAUSING, RESUMING, CLOSABLE}-->[Notify]-->NON_EXISTENT
//	Otherwise<-->{Ignore}
// Remark
//	ULA shall not re-free the socket
void CSocketItemDl::OnGetReset()
{
	NotifyOrReturn fp1 = NULL;
	if(InterlockedExchange((unsigned int *) & pControlBlock->state, NON_EXISTENT) == PAUSING)
		fp1 = GetResetFlushCallback();

	SetMutexFree();
	if(fp1 != NULL)
		fp1(this, FSP_NotifyReset, -EINTR);
	else
		NotifyError(FSP_NotifyReset, -EINTR);
	//
	socketsTLB.FreeItem(this);
	Destroy();	// this is different from Recyle()
}
