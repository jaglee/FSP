/*
 * DLL to service FSP upper layer application
 * Multiplication of Connection
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

//[API: Multiply]
//	NON_EXISTENT-->CLONING-->[Send MULTIPLY]{enable retry}
// Given
//	FSPHANDLE		the handle of the parent FSP socket to be multiplied
//	PFSP_Context	the pointer to the parameter structure of the socket to create by multiplication
//	int8_t			whether (TO_END_TRANSACTION, STREAM_COMPERSSION)
//	NotifyOrReturn	the pointer to the callback function
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	The payload piggybacked should be specified by the 'welcome' message, where might be of zero length
//	Even the function return no immediate error, the callback function may be called with a NULL FSPHANDLE
//	which indicate some error has happened.
//	See also SendStream, FinalizeSend
DllExport
FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE hFSP, PFSP_Context psp1, unsigned flag, NotifyOrReturn fp1)
{
	CSocketItemDl *p = CSocketItemDl::ToPrepareMultiply(hFSP, psp1);
	if(p == NULL)
		return p;

	FSPHANDLE h = p->WriteOnMultiplied(psp1, flag, fp1);
	if (h == NULL)
	{
		p->Free();
		return NULL;
	}
	return h;
}



//[API: Multiply]
//	NON_EXISTENT-->CLONING-->[Send MULTIPLY]{enable retry}
// Given
//	FSP_HANDLE			the handle of the FSP socket whose connection is to be duplicated,
//	PFSP_Context		the pointer to the socket parameter
//	CallbackBufferReady the pointer to the callback function
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	The MULTIPLY request is sent to the remote peer only when following SendInplace was called
//	The handle returned might be useless, if CallbackConnected report error later
//	the capacity of immediately available buffer (might be 0) is outputted in the reference
//	As it is in CLONING state if onBufferReady is specified, it would be called but data would just be prebuffered
//	See also InquireSendBuf, SendInplace, FinalizeSend
DllExport
FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE hFSP, PFSP_Context psp1, CallbackBufferReady onBufferReady)
{
	CSocketItemDl *p = CSocketItemDl::ToPrepareMultiply(hFSP, psp1);
	if(p == NULL)
		return p;

	if(onBufferReady != NULL)
	{
		int32_t m;
		octet *buf = p->pControlBlock->InquireSendBuf(& m);
		if(buf == NULL)
		{
			p->Free();
			return NULL;
		}
		//
		onBufferReady(p, buf, m);
	}

	return p->CompleteMultiply();
}



// Given
//	CSocketItemDl *		The parent socket item
//	PFSP_Context		The context of the new child connection
// Return
//	The new socket item
// Remark
//	Requirement of a command structure is rendered by CreateControlBlock
//	It is not hard-limited, but ULA shall only clone a connection in the
//	ESTABLISHED(COMMITTING, COMMITTED, PEER_COMMIT, COMMITTING2 or CLOSABLE) state
CSocketItemDl * LOCALAPI CSocketItemDl::ToPrepareMultiply(FSPHANDLE h, PFSP_Context psp1)
{
	CSocketItemDl *p = CSocketDLLTLB::HandleToRegisteredSocket(h);
	if(p == NULL)
	{
		psp1->flags = -EBADF;
		return NULL;
	}

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	psp1->passive = 0;	// override what is provided by ULA
	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1);
	if(socketItem == NULL)
	{
		psp1->flags = -EBADF;	// -E_HANDLE?
		return NULL;
	}

	try
	{
		socketItem->pControlBlock->connectParams = p->pControlBlock->connectParams;
		socketItem->pControlBlock->connectParams.idParent = p->fidPair.source;
		socketItem->pControlBlock->SetSendWindow(LCKREAD(p->pControlBlock->sendWindowNextSN) - 1);
		//^The receive window would be initialized in LLS
		// The MULTIPLY packet itself is sent in old key, while the packet next to MULTIPLY is send in derived key
		socketItem->SetState(CLONING);
		socketItem->SetNewTransaction();
	}
	catch(...)
	{
		socketItem->RecycleSimply();
		return NULL;
	}

	return socketItem;
}



inline
FSPHANDLE LOCALAPI CSocketItemDl::WriteOnMultiplied(PFSP_Context psp1, unsigned flag, NotifyOrReturn fp1)
{
	TestSetSendReturn((PVOID)fp1);
	if (psp1->welcome != NULL)
	{
		if ((flag & TO_COMPRESS_STREAM) && !AllocStreamState())
			return NULL;
		pendingSendBuf = (octet *)psp1->welcome;
		bytesBuffered = 0;
		// pendingSendSize set in BufferData
		if (!WaitUseMutex())
			return NULL;
		SetEoTPending((flag & TO_END_TRANSACTION) != 0);
		BufferData(psp1->len);
		SetMutexFree();
	}
	return CompleteMultiply();
}



// Do
//	Fill in the MULTPLY packet, construct and pass command to LLS
FSPHANDLE CSocketItemDl::CompleteMultiply()
{
	ControlBlock::PFSP_SocketBuf skb = SetHeadPacketIfEmpty(MULTIPLY);
	if (skb != NULL)
	{
		skb->opCode = MULTIPLY;
		skb->ReInitMarkComplete();
	}
	// See also InitCommand, CallCreate
	CommandCloneConnect cmd(pControlBlock->connectParams.idParent);
	CopyFatMemPointo(cmd);
	SetState(CLONING);
	if (!StartPolling() || !Call((UCommandToLLS*)&cmd))
	{
		RecycleSimply();
		return NULL;
	}

	return this;
}



//{ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|-->/MULTIPLY/-->[API{Callback}]-->{new context}CONNECT_AFFIRMING
//		|-->[{Return Accept}]
//			|{has payload prebuffered}-->{further LLS process}
//			|{without payload}-->[Send NULCOMMIT]
//		|-->[{Return}:Reject]-->{abort creating new context}
// See also
//	ToWelcomeConnect, ToConcludeConnect(), @LLS::ResponseToMultiply, @LLS::Recycle
bool LOCALAPI CSocketItemDl::ToWelcomeMultiply(SItemBackLog & backLog)
{
	PFSP_IN6_ADDR remoteAddr = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	// Multiplication is 0-RTT, it's allowed to prebuffer data to transmit
	SetState(CONNECT_AFFIRMING);
	SetNewTransaction();
	if (context.onAccepting != NULL	&& context.onAccepting(this, & backLog.acceptAddr, remoteAddr) < 0)
		return false;

	SetHeadPacketIfEmpty(NULCOMMIT);
	return true;
}
