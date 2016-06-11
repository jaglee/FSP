/*
 * DLL to service FSP upper layer application
 * Session control functions: Multiplication/Commitment/Resumption
 * Milk-transport is only implented on multiplicated secondary connection
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

/**
  Multiply
  - Generate MULTIPLY packet, encapsulate optional payload
  - Call LLS
  LLS/SynConnection
  - Allocate session ID
  - Transmit the start packet
  The peer' LLS:
  - OnGetMultiply
	- Check redundant
	- Check ICC
	- Put to backlog
  The peer's DLL:
  - WaitEventToDispatch, ToWelcomeMultiply
	- Send PERSIST/COMMIT
  The nearend's LLS:
  - OnGetCommit/OnGetPersist
	- Update peer's ID
  The nearend's DLL
	- Continue to send
 */

//[API: Multiply]
//	NON_EXISTENT-->CLONING-->[Send MULTIPLY]{enable retry}
// UNRESOLVED! ALLOCATED NEW SESSION ID in LLS?
// Given
//	FSPHANDLE		the handle of the parent FSP socket to be multiplied
//	PFSP_Context	the pointer to the parameter structure of the socket to create by multiplication
//	FlagEndOfMessage
//	NotifyOrReturn	the callback function pointer
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	The payload piggybacked should be specified by the 'welcome' message, where might be of zero length
//	Even the function return no immediate error, the callback function may be called with a NULL FSPHANDLE
//	which indicate some error has happened. In that case ULA might make further investigation by calling GetLastFSPError()
//	See also SendStream, FinalizeSend
DllExport
FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE hFSP, PFSP_Context psp1, FlagEndOfMessage flag, NotifyOrReturn fp1)
{
	TRACE_HERE("called");

	CommandNewSession objCommand;
	CSocketItemDl *p = CSocketItemDl::ToPrepareMultiply((CSocketItemDl *)hFSP, psp1, objCommand);
	if(p == NULL)
		return p;

	if(psp1->welcome != NULL)
	{
		p->pendingSendBuf = (BYTE *)psp1->welcome;
		p->bytesBuffered = 0;
		p->TestSetSendReturn(fp1);
		p->CheckCommitOrRevert(flag);
		// pendingSendSize set in BufferData
		p->BufferData(psp1->len);
		p->SetNewTransaction();
	}

	return p->CallCreate(objCommand, SynConnection);
}




// given
//	the handle of the FSP socket whose connection is to be duplicated,
//	the pointer to the socket parameter
//	[inout] pointer to the placeholder of an integer specifying the the minimum requested size of the buffer
//	the pointer to the callback function
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The MULTIPLY request is sent to the remote peer only when following SendInPlace was called
//	The handle returned might be useless, if CallbackConnected report error laterly
//	the capacity of immediately available buffer (might be 0) is outputted in the reference
//	As it is in CLONING state if onBufferReady is specified, it would be called but data would just be prebuffered
//	See also InquireSendBuf, SendInplace, FinalizeSend
DllExport
FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE hFSP, PFSP_Context psp1, int *pSize, CallbackBufferReady onBufferReady)
{
	TRACE_HERE("called");

	CommandNewSession objCommand;
	CSocketItemDl *p = CSocketItemDl::ToPrepareMultiply((CSocketItemDl *)hFSP, psp1, objCommand);
	if(p == NULL)
		return p;

	if(pSize != NULL && *pSize > 0)
	{
		p->pendingSendSize = *pSize;
		//
		void *buf = p->pControlBlock->InquireSendBuf(*pSize);
		if(buf == NULL)
		{
			socketsTLB.FreeItem(p);
			return NULL;
		}
		//
		if(onBufferReady != NULL)
			onBufferReady(p, buf, *pSize);
	}

	return p->CallCreate(objCommand, SynConnection);
}




CSocketItemDl * LOCALAPI CSocketItemDl::ToPrepareMultiply(CSocketItemDl *p, PFSP_Context psp1, CommandNewSession &)
{
	TRACE_HERE("called");
	if(p == NULL)
	{
		psp1->u.flags = EBADF;
		return NULL;
	}

	// TODO: SHOULD inherit the latest effective near address
	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	psp1->u.st.passive = 0;	// override what is provided by ULA
	CommandNewSession objCommand;
	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->u.flags = EBADF;	// E_HANDLE;
		return NULL;
	}

	// TODO: SHOULD install a new, derived session key!
	try
	{
		memcpy(& socketItem->pControlBlock->connectParams, & p->pControlBlock->connectParams, FSP_MAX_KEY_SIZE);
	}
	catch(int)	// could we really catch run-time memory access exception?
	{
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}

	socketItem->ToPrepareMultiply();

	return socketItem;
}



void CSocketItemDl::ToPrepareMultiply()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	skb->opCode = MULTIPLY;
	skb->len = 0;
	skb->InitFlags();	// locked, incomplete

	SetState(CLONING);
	SetNewTransaction();
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|-->/MULTIPLY/-->[API{Callback}]
//	|-->[{Return Accept}]-->{new context}ACTIVE/COMMITTING
//		-->[Send PERSIST]{start keep-alive}
//	|-->[{Return}:Reject]-->[Send RESET] {abort creating new context}
bool LOCALAPI CSocketItemDl::ToWelcomeMultiply(BackLogItem & backLog)
{
	// Multiply: but the upper layer application may still throttle it...fpRequested CANNOT read or write anything!
	PFSP_IN6_ADDR remoteAddr = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	SetNewTransaction();
	if( fpRequested == NULL	// This is NOT the same policy as ToWelcomeConnect
	 || fpRequested(this, & backLog.acceptAddr, remoteAddr) < 0 )
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	SetState(isFlushing > 0 ? COMMITTING : ESTABLISHED); // See also ToConcludeConnect()
	CheckToNewTransaction();
	return true;
}
