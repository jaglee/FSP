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

	if(psp1->len > MAX_BLOCK_SIZE - sizeof(FSP_NormalPacketHeader) - sizeof(FSP_ConnectParam))
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
	socketItem->InitiateConnect();

	return socketItem->CallCreate(objCommand, InitConnection);
}



// Send the prepare-connection request packet (INITIATE_CONNECT, Timestamp, initiator's check code, 32-bit random)
// Remark: overlay formal connect request with the connect bootstrap packet
void CSocketItemDl::InitiateConnect()
{
	SConnectParam & initState = pControlBlock->u.connectParams;
	initState.timeStamp = NowUTC();
	rand_w32((uint32_t *) & initState,
		( sizeof(initState.cookie)
		+ sizeof(initState.initCheckCode)
		+ sizeof(initState.salt)
		+ sizeof(initState.initialSN) ) / sizeof(uint32_t) );
	// Remote session ID was set when the control block was created
	// Generate the private-public key pair
	keyTransferer.GenerateKey(FSP_PUBLIC_KEY_LEN << 3);

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetVeryFirstSendBuf(initState.initialSN);
	skb->opCode = INIT_CONNECT;
	skb->len = sizeof(FSP_InitiateRequest);
	//
	// Overlay INIT_CONNECT and CONNECT_REQUEST
	FSP_ConnectRequest & request = *(FSP_ConnectRequest *)GetSendPtr(skb);
	request.initCheckCode = initState.initCheckCode;
	request.salt = initState.salt;
	keyTransferer.ExportPublicKey((BYTE *)request.public_n);	// TO BE FIXED! Memory overflow?
	request.params.hs.Set<FSP_ConnectRequest, CONNECT_PARAM>();
	request.hsKey.Set<FSP_InitiateRequest, EPHEMERAL_KEY>();
	request.hs.Set<FSP_InitiateRequest, INIT_CONNECT>();	// See also AffirmConnect()
	//
	skb->SetFlag<IS_COMPLETED>();
	SetState(CONNECT_BOOTSTRAP);
	// MUST set the state before calling LLS so that event-driven state transition may work properly
}


// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connnection request or multiplication request
//	RESET, Timestamp echo, Initial SN echo, Expected SN echo, Reason
void CSocketItemDl::ProcessBacklog()
{
	// TODO: set the default interface to non-zero?
	CommandNewSession objCommand;
	BackLogItem backLog;
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
	if(! this->context.u.st.passive)	// this->StateEqual(LISTENING)
	{
		newContext.welcome = NULL;
		newContext.len = 0;
	}
	CSocketItemDl *pSocket = CreateControlBlock(pListenIP, &newContext, cmd);
	if(pSocket == NULL)
		return NULL;

	pSocket->pControlBlock->idParent = this->pairSessionID.source;
	// IP address, including Session ID stored in nearEnd[0] would be set by CreateControlBlock
	// Cached session ID in the DLL SocketItem stub is set by CreateControlBlock as well

	memcpy(pSocket->pControlBlock->peerAddr.ipFSP.allowedPrefixes, backLog.allowedPrefixes, sizeof(UINT64)* MAX_PHY_INTERFACES);
	pSocket->pControlBlock->peerAddr.ipFSP.hostID = backLog.remoteHostID;
	pSocket->pControlBlock->peerAddr.ipFSP.sessionID = backLog.idRemote;

	pSocket->pControlBlock->recvWindowFirstSN = backLog.expectedSN;
	pSocket->pControlBlock->receiveMaxExpected = backLog.expectedSN;
	
	return pSocket;
}


// Given
//	BackLogItem &	the reference to the acception backlog item
// Do
//	(ACK_CONNECT_REQUEST, Initial SN, Expected SN, Timestamp, Receive Window, responder's half-connection parameter, optional payload)
// Remark
//	Session key generated and encrypted
bool LOCALAPI CSocketItemDl::ToWelcomeConnect(BackLogItem & backLog)
{
	// Ask the upper layer whether to accept the connection...fpRequested CANNOT read or write anything!
	PFSP_IN6_ADDR p = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	SetState(CHALLENGING);
	if(fpRequested != NULL && fpRequested(this, & backLog.acceptAddr, p) < 0)
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetVeryFirstSendBuf(backLog.initialSN);
	FSP_AckConnectKey *pKey = (FSP_AckConnectKey *)GetSendPtr(skb);
	FSP_ConnectParam *params = (FSP_ConnectParam *)((BYTE *)pKey + sizeof(FSP_AckConnectKey));
	//
	InstallBootKey(backLog.bootKey, sizeof(backLog.bootKey));
	rand_w32((uint32_t *)pControlBlock->u.sessionKey
			, sizeof(pControlBlock->u.sessionKey) / sizeof(uint32_t));
	InstallSessionKey(pControlBlock->u.sessionKey);
	keyTransferer.Encrypt(pControlBlock->u.sessionKey, FSP_SESSION_KEY_LEN, pKey->encrypted);
	pKey->hsKey.Set<FSP_NormalPacketHeader, EPHEMERAL_KEY>();

	// TODO: handle of milky-payload; multihome/mobility support is always handled by LLS
	params->delayLimit = 0;
	// TODO: exploit initialSN to validate something?
	params->initialSN = 0;
	//^Here it is redundant, just ignore. See also LLS::OnConnectRequestAck
	params->listenerID = pControlBlock->idParent;
	params->hs.Set<CONNECT_PARAM>(sizeof(FSP_NormalPacketHeader) + sizeof(*pKey));
	//
	skb->opCode = ACK_CONNECT_REQUEST;
	skb->len = sizeof(*pKey) + sizeof(*params);	// the fixed header is generated on the fly
	skb->ZeroFlags();
	//
	if(pendingSendBuf != NULL && pendingSendSize + skb->len <= MAX_BLOCK_SIZE)
	{
		memcpy((BYTE *)pKey + skb->len, pendingSendBuf, pendingSendSize);
		skb->len += pendingSendSize;
		//
		pendingSendBuf = NULL;
		pendingSendSize = 0;
	}
	// else let ProcessPendingSend eventually transmit the welcome message, if any
	skb->SetFlag<IS_COMPLETED>();

#ifdef TRACE
	printf_s("Connect request accepted, it is in CHALLENGING\n");
#endif
	return true;
}


// Auxiliary function that is called when a new connection request is to be accepted
// in the new created context of the incarnation respondor OR multiplexing initiator
// Remark
//	It is legal to chain ReadFrom()/RecvInline()
//	However, it is illegal to chain WriteTo()/SendInline() if it has already migrated
//	to the CLOSABLE state from the CHALLENGING, CLONING, RESUMING or QUASI_ACTIVE state
void CSocketItemDl::ToConcludeAccept()
{
	TRACE_HERE("Connection has been accepted");
	SetMutexFree();
	if(fpAccepted != NULL)
		fpAccepted(this, &context);
}



// Auxiliary function that is called when a new connection request is acknowledged by the responder
//	CONNECT_AFFIRMING-->[Rcv ACK_CONNECT_REQUEST]-->[API{callback}]
//	|-->{Return Accept}-->ACTIVE-->[Snd PERSIST[start keep-alive}]
//	|-->{Return Commit}-->PAUSING-->[Snd ADJOURN{enable retry}]
//	|-->{Return Reject}-->[Snd RESET]-->NON_EXISTENT
void CSocketItemDl::ToConcludeConnect()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv();
	BYTE *payload = GetRecvPtr(skb);
	InstallSessionKey(payload + skb->len, FSP_PUBLIC_KEY_LEN);

	// See also FSP_LLS$$CSocketItemEx::Connect()
	pairSessionID.source = pControlBlock->nearEnd[0].u.idALT;
	//^As by default Connect2 set the cached session ID in the DLL SocketItem to 0

	// Deliver the optional payload and skip the ACK_CONNECT_REQUEST packet
	// See also ControlBlock::InquireRecvBuf()
	// UNRESOLVED! Could welcome message be compressed?
	// TODO: Provide convient compress/decompress help routines
	// TODO: provide extensibility of customized compression/decompression method?
	context.welcome = payload;
	context.len = skb->len;
	context.u.st.compressing = skb->GetFlag<IS_COMPRESSED>();

	pControlBlock->recvWindowHeadPos++;
	pControlBlock->recvWindowFirstSN++;

	TRACE_HERE("connection request has been accepted");

	// Overlay CONNECT_REQUEST, and yes, it is queued and might be followed by payload packet
	skb = pControlBlock->HeadSend();	// See also InitConnect() and AffirmConnect()
	// while version and sequence number remains as the same as very beginning INIT_CONNECT
	skb->opCode = PERSIST;
	skb->len = 0;
	skb->ZeroFlags();	// As it overlay CONNECT_REQUEST and the packet must have been sent

	SetMutexFree();

	int r = 0;
	if(fpAccepted != NULL)
		r = fpAccepted(this, &context);

	if(r < 0)
	{
		Recycle();
		return;
	}

	// if it is transactional the head packet should have already be changed to ADJOURN
	SetState(r == 0 ? ESTABLISHED : PAUSING);

#ifdef TRACE
	printf_s("Acknowledgement of connection request received, to PERSIST the connection.\n");
#endif
	if (!skb->GetFlag<BIT_IN_SENDING>())
	{
		skb->SetFlag<IS_COMPLETED>();
		Call<FSP_Send>();
	}
}


// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	UINT32		the 32-bit integer representation of the IPv4 address to be translated
//	UINT32		the session ID, in host byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
DllSpec
UINT32 * TranslateFSPoverIPv4(PFSP_IN6_ADDR p, UINT32 dwIPv4, UINT32 sessionID)
{
	p->u.st.prefix = PREFIX_FSP_IP6to4;
	p->u.st.ipv4 = dwIPv4;
	p->u.st.port = DEFAULT_FSP_UDPPORT;
	p->idALT = htobe32(sessionID);
	return & p->idHost;
}



// The sibling functions of Connect2() for 'fast reconnect', 'session resume'
// and 'connection multiplication' (ConnectMU), is in Multiply.cpp
	