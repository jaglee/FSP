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
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	The payload piggybacked should be specified by the 'welcome' message, where might be of zero length
//	Even the function return no immediate error, the callback function may be called with a NULL FSPHANDLE
//	which indicate some error has happened.
//	See also SendStream, FinalizeSend
DllExport
FSPHANDLE FSPAPI Multiply(FSPHANDLE hFSP, PFSP_Context psp1)
{
	CSocketItemDl* p = CSocketDLLTLB::HandleToRegisteredSocket(hFSP);
	if (p == NULL)
	{
		psp1->flags = -EBADF;
		return NULL;
	}

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	psp1->passive = 0;	// override what is provided by ULA
	CSocketItemDl* socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR)&addrAny, psp1);
	if (socketItem == NULL)
	{
		psp1->flags = -EBADF;	// -E_HANDLE?
		return NULL;
	}

	socketItem->pControlBlock->connectParams = p->pControlBlock->connectParams;
	socketItem->pControlBlock->connectParams.idParent = p->fidPair.source;
	socketItem->pControlBlock->SetSendWindow(LCKREAD(p->pControlBlock->sendWindowNextSN) - 1);
	//^The receive window would be initialized in LLS
	// The MULTIPLY packet itself is sent in old key, while the packet next to MULTIPLY is send in derived key

	return socketItem->InitiateCloning(psp1);
}



inline
FSPHANDLE LOCALAPI CSocketItemDl::InitiateCloning(PFSP_Context psp1)
{
	SetNewTransaction();

	context = *psp1;
	PrepareSendBuffer(MULTIPLY);

	// See also InitCommand, CallCreate
	CommandCloneConnect cmd(pControlBlock->connectParams.idParent);
	CopyFatMemPointo(cmd);
	SetState(CLONING);

	if (Call((UCommandToLLS*)&cmd) && StartPolling())
	{
#ifdef TRACE
		printf("New socket multiplied, fiber ID = %u.\n", this->fidPair.source);
#endif
		return this;
	}
	RecycleSimply();
	return NULL;
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
