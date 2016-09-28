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

	socketItem->AddOneShotTimer(TRASIENT_STATE_TIMEOUT_ms);
	socketItem->sendCompressing = psp1->u.st.compressing;
	socketItem->SetState(LISTENING);
	// MUST set the state before calling LLS so that event-driven state transition may work properly
	return socketItem->CallCreate(objCommand, FSP_Listen);
}



//[API: Connect]
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
DllSpec
FSPHANDLE FSPAPI Connect2(const char *peerName, PFSP_Context psp1)
{
	TRACE_HERE("called");
	if(psp1->sendSize < 0 || psp1->recvSize < 0 || psp1->sendSize + psp1->recvSize > MAX_FSP_SHM_SIZE + MIN_RESERVED_BUF)
	{
		psp1->u.flags = ENOMEM;
		return NULL;
	}

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

	socketItem->AddOneShotTimer(TRASIENT_STATE_TIMEOUT_ms);
	socketItem->sendCompressing = psp1->u.st.compressing;
	socketItem->SetPeerName(peerName, strlen(peerName));
	return socketItem->CallCreate(objCommand, InitConnection);
}



// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connnection request or multiplication request
void CSocketItemDl::ProcessBacklog()
{
	// TODO: set the default interface to non-zero?
	CommandNewSession objCommand;
	BackLogItem		*pLogItem;
	CSocketItemDl * socketItem;
	// firstly, fetch the backlog item
	for(; (pLogItem = pControlBlock->backLog.Peek()) != NULL; pControlBlock->backLog.Pop())
	{
		socketItem = PrepareToAccept(*pLogItem, objCommand);
		if(socketItem == NULL)
		{
			TRACE_HERE("Process listening backlog: insufficient system resource?");
			this->InitCommand<FSP_Reject>(objCommand);
			this->Call(objCommand, sizeof(struct CommandToLLS));
			pControlBlock->backLog.Pop();
			return;
		}
		// lost some possibility of code reuse, gain flexibility (and reliability)
		if(pLogItem->idParent == 0 && ! socketItem->ToWelcomeConnect(*pLogItem)
		|| pLogItem->idParent != 0 && ! socketItem->ToWelcomeMultiply(*pLogItem))
		{
			this->InitCommand<FSP_Reject>(objCommand);
			this->Call(objCommand, sizeof(objCommand));
			socketsTLB.FreeItem(socketItem);
			continue;
		}
		//
		if(! socketItem->CallCreate(objCommand, FSP_Accept))
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
CSocketItemDl * CSocketItemDl::PrepareToAccept(BackLogItem & backLog, CommandNewSession & cmd)
{
	PFSP_IN6_ADDR pListenIP = (PFSP_IN6_ADDR) & backLog.acceptAddr;
	FSP_SocketParameter newContext = this->context;
	newContext.ifDefault = backLog.acceptAddr.ipi6_ifindex;

	// Inherit the NotifyOrReturn functions onError,
	// the CallbackConnected function onAccepted
	// but not CallbackRequested/onAccepting
	if(! this->context.u.st.passive)
	{
		newContext.welcome = NULL;
		newContext.len = 0;
	}
	else // this->InState(LISTENING)
	{
		newContext.onAccepting = NULL;
		newContext.u.st.passive = 0;
	}
	// If the incarnated connection could be cloned, onAccepting shall be set by FSPControl

	CSocketItemDl *pSocket = CreateControlBlock(pListenIP, &newContext, cmd);
	if(pSocket == NULL)
		return NULL;

	pSocket->pControlBlock->idParent = this->fidPair.source;
	// IP address, including Session ID stored in nearEndInfo would be set by CreateControlBlock
	// Cached fiber ID in the DLL SocketItem stub is set by CreateControlBlock as well

	memcpy(pSocket->pControlBlock->peerAddr.ipFSP.allowedPrefixes
		, backLog.allowedPrefixes
		, sizeof(uint64_t)* MAX_PHY_INTERFACES);
	pSocket->pControlBlock->peerAddr.ipFSP.hostID = backLog.remoteHostID;
	pSocket->pControlBlock->peerAddr.ipFSP.fiberID = backLog.idRemote;

	pSocket->pControlBlock->connectParams = backLog;
	// UNRESOLVED!? Correct pSocket->pControlBlock->connectParams.allowedPrefixes in LLS

	pSocket->pControlBlock->SetRecvWindow(backLog.expectedSN);
	pSocket->pControlBlock->SetSendWindow(backLog.initialSN);
	
	return pSocket;
}


// Given
//	BackLogItem &	the reference to the acception backlog item
// Do
//	(ACK_CONNECT_REQ, Initial SN, Expected SN, Timestamp, Receive Window[, responder's half-connection parameter[, payload])
bool LOCALAPI CSocketItemDl::ToWelcomeConnect(BackLogItem & backLog)
{
	PFSP_IN6_ADDR p = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	//
	SetNewTransaction();	// ACK_CONNECT_REQ is a singleton transmit transaction
	SetState(CHALLENGING);
	// Ask ULA whether to accept the connection. Note that context.onAccepting may not read or write
	if(context.onAccepting != NULL && context.onAccepting(this, & backLog.acceptAddr, p) < 0)
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	pControlBlock->sendBufferNextSN = pControlBlock->sendWindowFirstSN + 1;
	pControlBlock->sendBufferNextPos = 1;	// reserve the head packet
	//
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	FSP_ConnectParam *params = (FSP_ConnectParam *)GetSendPtr(skb);
	//
	memcpy(& pControlBlock->connectParams, & backLog, FSP_MAX_KEY_SIZE);

	params->listenerID = pControlBlock->idParent;
	params->hs.Set(PEER_SUBNETS, sizeof(FSP_NormalPacketHeader));
	//
	skb->version = THIS_FSP_VERSION;
	skb->opCode = ACK_CONNECT_REQ;
	skb->len = sizeof(*params);	// the fixed header is generated on the fly
	skb->InitFlags();
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
//	|-->{Return Accept}-->PEER_COMMIT/COMMITTING2-->{start keep-alive}
//	|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
void CSocketItemDl::ToConcludeConnect()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv();
	BYTE *payload = GetRecvPtr(skb);

	// See also FSP_LLS$$CSocketItemEx::Connect()
	fidPair.source = pControlBlock->nearEndInfo.idALF;
	//^As by default Connect2 set the cached fiber ID in the DLL SocketItem to 0

	// Deliver the optional payload and skip the ACK_CONNECT_REQ packet
	// See also ControlBlock::InquireRecvBuf()
	// UNRESOLVED! Could welcome message be compressed?
	// TODO: Provide convient compress/decompress help routines
	// TODO: provide extensibility of customized compression/decompression method?
	context.welcome = payload;
	context.len = skb->len;

	this->recvCompressed = skb->GetFlag<IS_COMPRESSED>();

	pControlBlock->SlideRecvWindowByOne();	// ACK_CONNECT_REQUEST, which may carry welcome
	// But // CONNECT_REQUEST does NOT consume a sequence number
	// See @LLS::OnGetConnectRequest

	TRACE_HERE("connection request has been accepted");
	SetMutexFree();

	SetNewTransaction();
	if(context.onAccepted != NULL && context.onAccepted(this, &context) < 0)
	{
		Recycle();
		return;
	}
	SetHeadPacketIfEmpty(PERSIST);
	SetState(isFlushing ? COMMITTING2 : PEER_COMMIT);
	// See also ToWelcomeMultiply, differs in state migration

	Call<FSP_Start>();
}


// Given
//	FSPOperationCode the header packet's operation code
// Do
//	Set the head packet
// Return
//	The pointer to the header packet's descriptor if the queue used to be non-empty
//	NULL if the send queue used to be empty
//	//skb->SetFlag<END_OF_TRANSACTION>();
//	But the payloadless PERSIST/MULTIPLY does NOT terminate the transmit transaction!
ControlBlock::PFSP_SocketBuf LOCALAPI CSocketItemDl::SetHeadPacketIfEmpty(FSPOperationCode c)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	ControlBlock::seq_t k = pControlBlock->sendWindowFirstSN;
	if(_InterlockedCompareExchange((LONG *)& pControlBlock->sendBufferNextSN, k + 1, k) != k)
		return skb;

	pControlBlock->sendBufferNextPos = 1;
	skb->version = THIS_FSP_VERSION;
	skb->opCode = c;
	skb->len = 0;
	skb->flags = 0;
	skb->SetFlag<IS_COMPLETED>();
	return NULL;
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
uint32_t * FSPAPI TranslateFSPoverIPv4(PFSP_IN6_ADDR p, uint32_t dwIPv4, uint32_t fiberID)
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
//	-EINTR	if cannot obtain the right lock
//	-EIO	if cannot trigger LLS to do the installation work through I/O
//	0		if no failure
// Remark
//	We need the mutex lock because it shall be atomic to copy in key material structure as the parameter
//	Normally only in CLOSABLE or COMMITTING2 state may a session key installed
//	however it is not checked because the function
//	might be called in the callback function before the right state migration
int LOCALAPI CSocketItemDl::InstallKey(BYTE *key, int keySize, int32_t keyLife)
{
	if(! WaitUseMutex())
		return -EINTR;

	memcpy(& pControlBlock->connectParams, key, keySize);
	pControlBlock->connectParams.keyLength = keySize;
	pControlBlock->connectParams.keyLife$initialSN = keyLife;

	SetMutexFree();
	return Call<FSP_InstallKey>() ? 0 : -EIO;
}
