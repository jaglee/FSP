/*
 * DLL to service FSP upper layer application
 * Session control functions: the passive and initiative creation of FSP connection
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
#include <assert.h>
#include <stdlib.h>
#include <tchar.h>

//[API: Listen]
//	NON_EXISTENT-->LISTENING
// Given
//	const PFSP_IN6_ADDR		list of IPv6 addresses that the passive socket to listen at.
//							terminated with IN6ADDR_ANY_INIT or IN6ADDR_LOOPBACK_INIT
//	PFSP_Context			the pointer to the parameter structure of the socket to create
// Return
//	NULL if it fails immediately, or else 
//  the handle of the passive FSP socket whose properties might be peek and/or set later
// Remark
//	FSP over UDP/IPv4 address SHALL be converted to 'cannonical' FSP-aligned IPv6 address
//	The handle returned might be unusable, if PFSP_Context::onError() report error laterly
DllSpec
FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR listenOn, PFSP_Context psp1)
{ 
	TRACE_HERE("called");

	// TODO: The welcome message CAN be larger
	if(psp1->len > MAX_BLOCK_SIZE - sizeof(FSP_AckConnectRequest))
	{
		// UNRESOLVED! Set last error?
		return NULL;
	}

	// TODO: UNRESOLVED! if srcAddr is NULL, allocate an interface IP automatically
	psp1->u.st.passive = 1;	// override what is provided by ULA
	CommandNewSession objCommand;
	//
	CSocketItemDl *socketItem = CSocketItemDl::CreateControlBlock(listenOn, psp1, objCommand);
	if(socketItem == NULL)
		return NULL;

	socketItem->SetState(LISTENING);
	// MUST set the state before calling LLS so that event-driven state transition may work properly

	return socketItem->CallCreate(objCommand, FSP_Listen);
}


//[API: Connect]
//	CLOSED-->{when RDSC hit}-->QUASI_ACTIVE-->[Send RESUME]{enable retry}
//	NON_EXISTENT-->CONNECT_BOOTSTRAP
// Given
//	const char *	resolvable name (not necessarily domain name) of the remote end
//	PFSP_Context	the pointer to the parameter structure of the socket to create
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	Socket address of the remote end would be resolved by LLS and stored in the control block
//	CallbackConnected() function whose pointer was given in the structure pointed by PSP_SocketParameter
//  would report later error by passing a NULL FSP handle as the first parameter
//	and a negative integer, which is the error number, as the second parameter if connection failed
// TODO: UNRESOLVED! RDSC management!?
DllSpec
FSPHANDLE FSPAPI Connect2(const char *peerName, PFSP_Context psp1)
{
	TRACE_HERE("called");

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	CommandNewSession objCommand;

	psp1->u.st.passive = 0;	// override what is provided by ULA
	psp1->welcome = NULL;	// an active connection request shall have no welcome message
	psp1->len = 0;			// or else memory access exception may occur

	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->u.flags = EBADF;	// E_HANDLE;
		return NULL;
	}
	socketItem->SetPeerName(peerName, strlen(peerName));

	return socketItem->CallCreate(objCommand, InitConnection);
}


// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connnection request or multiplication request
void CSocketItemDl::ProcessBacklog()
{
	// TODO: set the default interface to non-zero?
	CommandNewSession objCommand;
	BackLogItem		backLog;
	CSocketItemDl * socketItem;
	// firstly, fetch the backlog item
	while(pControlBlock->PopBacklog(& backLog) >= 0)
	{
		socketItem = PrepareToAccept(backLog, objCommand);
		if(socketItem == NULL)
		{
			TRACE_HERE("Process listening backlog: insufficient system resource?");
			this->InitCommand<FSP_Reject>(objCommand);
			this->Call(objCommand, sizeof(struct CommandToLLS));
			return;
		}
		// lost some possibility of code reuse, gain flexibility (and reliability)
		if(backLog.idParent == 0 && ! socketItem->ToWelcomeConnect(backLog)
		|| backLog.idParent != 0 && ! socketItem->ToWelcomeMultiply(backLog))
		{
			this->InitCommand<FSP_Reject>(objCommand);
			this->Call(objCommand, sizeof(objCommand));
			socketsTLB.FreeItem(this);
			continue;
		}
		//
		if(! socketItem->CallCreate(objCommand, SynConnection))
		{
			TRACE_HERE("Process listening backlog: cannot synchronize - local IPC error");
			socketsTLB.FreeItem(socketItem);
		}
	}
	// the backlog item would be kept even when InitCommand/InitCreate is called
}



// Given
//	BackLogItem &		the reference to the acception backlog item
//	CommandNewSession & the command context of the backlog
// Return
//	The pointer to the socket created for the new connection requested
CSocketItemDl * LOCALAPI CSocketItemDl::PrepareToAccept(BackLogItem & backLog, CommandNewSession & cmd)
{
	PFSP_IN6_ADDR pListenIP = (PFSP_IN6_ADDR) & backLog.acceptAddr;
	FSP_SocketParameter newContext = this->context;
	newContext.ifDefault = backLog.acceptAddr.ipi6_ifindex;
	newContext.u.st.passive = 0;
	// UNRESOLVED! check function pointers!?
	if(! this->context.u.st.passive)	// this->InState(LISTENING)
	{
		newContext.welcome = NULL;
		newContext.len = 0;
	}
	CSocketItemDl *pSocket = CreateControlBlock(pListenIP, &newContext, cmd);
	if(pSocket == NULL)
		return NULL;

	pSocket->pControlBlock->idParent = this->fidPair.source;
	// IP address, including Session ID stored in nearEnd[0] would be set by CreateControlBlock
	// Cached fiber ID in the DLL SocketItem stub is set by CreateControlBlock as well

	memcpy(pSocket->pControlBlock->peerAddr.ipFSP.allowedPrefixes
		, backLog.allowedPrefixes
		, sizeof(uint64_t)* MAX_PHY_INTERFACES);
	pSocket->pControlBlock->peerAddr.ipFSP.hostID = backLog.remoteHostID;
	pSocket->pControlBlock->peerAddr.ipFSP.fiberID = backLog.idRemote;

	pSocket->pControlBlock->connectParams = backLog;
	// UNRESOLVED!? Correct pSocket->pControlBlock->connectParams.allowedPrefixes in LLS

	pSocket->pControlBlock->SetRecvWindowHead(backLog.expectedSN);
	pSocket->pControlBlock->SetSendWindowWithHeadReserved(backLog.initialSN);
	
	return pSocket;
}


// Given
//	BackLogItem &	the reference to the acception backlog item
// Do
//	(ACK_CONNECT_REQ, Initial SN, Expected SN, Timestamp, Receive Window[, responder's half-connection parameter[, payload])
bool LOCALAPI CSocketItemDl::ToWelcomeConnect(BackLogItem & backLog)
{
	// Ask the upper layer whether to accept the connection...fpRequested CANNOT read or write anything!
	PFSP_IN6_ADDR p = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	//
	SetState(CHALLENGING);
	if(fpRequested != NULL && fpRequested(this, & backLog.acceptAddr, p) < 0)
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	FSP_ConnectParam *params = (FSP_ConnectParam *)GetSendPtr(skb);
	//
	memcpy(& pControlBlock->connectParams, & backLog, FSP_MAX_KEY_SIZE);

	params->listenerID = pControlBlock->idParent;
	params->hs.Set<MOBILE_PARAM>(sizeof(FSP_NormalPacketHeader));
	//
	skb->opCode = ACK_CONNECT_REQ;
	skb->len = sizeof(*params);	// the fixed header is generated on the fly
	//
	if(pendingSendBuf != NULL && pendingSendSize + skb->len <= MAX_BLOCK_SIZE)
	{
		memcpy((BYTE *)params + skb->len, pendingSendBuf, pendingSendSize);
		skb->len += pendingSendSize;
		//
		pendingSendBuf = NULL;
		pendingSendSize = 0;
	}
	// else let ProcessPendingSend eventually transmit the welcome message, if any
	skb->SetFlag<IS_COMPLETED>();
	// the packet is still locked

	return true;
}



// Auxiliary function that is called when a new connection request is acknowledged by the responder
// CONNECT_AFFIRMING-->[Rcv.ACK_CONNECT_REQ]-->[API{callback}]
//	|-->{Return Accept}-->ACTIVE-->[Send PERSIST]{start keep-alive}
//	|-->{Return Commit}-->COMMITTING-->[Send COMMIT]{enable retry}
//	|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
void CSocketItemDl::ToConcludeConnect()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv();
	BYTE *payload = GetRecvPtr(skb);

	// See also FSP_LLS$$CSocketItemEx::Connect()
	fidPair.source = pControlBlock->nearEnd[0].idALF;
	//^As by default Connect2 set the cached fiber ID in the DLL SocketItem to 0

	// Deliver the optional payload and skip the ACK_CONNECT_REQ packet
	// See also ControlBlock::InquireRecvBuf()
	// UNRESOLVED! Could welcome message be compressed?
	// TODO: Provide convient compress/decompress help routines
	// TODO: provide extensibility of customized compression/decompression method?
	context.welcome = payload;
	context.len = skb->len;
	context.u.st.compressing = skb->GetFlag<IS_COMPRESSED>();

	pControlBlock->SlideRecvWindowByOne();
	// Overlay CONNECT_REQUEST
	pControlBlock->sendWindowNextSN = pControlBlock->sendWindowFirstSN;

	TRACE_HERE("connection request has been accepted");
	SetMutexFree();

	int r = 0;
	if(fpAccepted != NULL)
		r = fpAccepted(this, &context);

	if(r < 0)
	{
		Recycle();
		return;
	}

	if(r == 0 && pControlBlock->hasPendingKey == 0)
		SetState(ESTABLISHED);
	else
		SetState(COMMITTING);
	//
	Call<FSP_Start>();
}



// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	uint32_t		the fiber ID, in host byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
DllSpec
uint32_t * TranslateFSPoverIPv4(PFSP_IN6_ADDR p, uint32_t dwIPv4, uint32_t fiberID)
{
	p->u.st.prefix = PREFIX_FSP_IP6to4;
	p->u.st.ipv4 = dwIPv4;
	p->u.st.port = DEFAULT_FSP_UDPPORT;
	p->idALF = htobe32(fiberID);
	return & p->idHost;
}



DllSpec
int FSPAPI InstallAuthenticKey(FSPHANDLE h, BYTE * key, int keySize, int32_t keyLife)
{
	if(keySize < FSP_MIN_KEY_SIZE || keySize > FSP_MAX_KEY_SIZE || keySize % sizeof(uint64_t) != 0 || keyLife <= 0)
		return -EDOM;
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)h;
		return pSocket->InstallKey(key, keySize, keyLife);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Given
//	BYTE *		byte stream of the key
//	int			length of the key, should be multiplication of 8
//	int32_t		life of the key, maximum number of packets that may utilize the key
// Return
//	-EGAIN	if installation of previous key was not yet synchronized with the peer
//	-EDOM	if domain error: either send queue or receive buffer should be empty
//	-EINTR	if gaining mutex is interrupted (timed out)
//	-EIO	if cannot trigger LLS to do the installation work through I/O
//	0		if no failure
// Remark
//	Installation of the new session key is usually asymmetric in the sense that one side
//	can figure out the shared secret before its peer have collected enough information
//	It is assumed that for security reason the key material exchanged should be of limited length
//	and only after the key material has been buffered to send or received thoroughly may InstallKey be called
//	See also CSocketItemDl::Commit
// UNRESOLVED! The state machine MUST be carefully reviewed. How about CONNECT_AFFIRMING? It is a temporal state.
int LOCALAPI CSocketItemDl::InstallKey(BYTE *key, int keySize, int32_t keyLife)
{
	if(_InterlockedCompareExchange8(& pControlBlock->hasPendingKey, 1, 0) != 0)
		return -EAGAIN;
	//
	memcpy(& pControlBlock->connectParams, key, keySize);
	pControlBlock->connectParams.keyLength = keySize;
	pControlBlock->connectParams.initialSN = keyLife;

	if(! WaitSetMutex())
		return -EINTR;

	// Install the new session key immediately if it is already in a definitely stable state
	// It is assumed that all data with old key have been buffered
	// when InstallAuthenticKey is called
	// It is also supposed that in the CLOSABLE state the receive buffer must be empty
	// so does it in CHALLENGING, CLONING, QUASI_ACTIVE or RESUMING state
	if(pControlBlock->CountReceived() == 0 || InState(PEER_COMMIT) || InState(COMMITTING2))
	{
		int r = Call<FSP_InstallKey>() ? 0 : -EIO;
		pControlBlock->hasPendingKey = 0;
		SetMutexFree();
		return r;
	}

	if (InState(ESTABLISHED) ||	InState(COMMITTED))
	{
		SetState(COMMITTING);
	}
	else if (! InState(COMMITTING))
	{
		SetMutexFree();
		return -EDOM;
	}

	// Automatically terminate the last message. Unlike Commit() the function fails if overflow occurred
	int r = pControlBlock->ReplaceSendQueueTailToCommit();
	_InterlockedCompareExchange8(& eomSending, END_OF_MESSAGE, 0);
	// END_OF_SESSION is not replaced

	SetMutexFree();
	if(r < 0)
		return -EDOM;
	else if(r > 0)
		return 0;
	else // if(r == 0)
		return Call<FSP_Urge>() ? 0 : -EIO;
}



// The sibling functions of Connect2() for 'fast reconnect', 'session resume'
// and 'connection multiplication' (ConnectMU), is in Multiply.cpp
