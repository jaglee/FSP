/*
 * DLL to service FSP upper layer application
 * Establishment of the FSP connections
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
//	const PFSP_IN6_ADDR		the pointer to the IPv6 address that the passive socket to listen at
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
	// TODO: The welcome message CAN be larger
	if(psp1->len > MAX_BLOCK_SIZE - sizeof(FSP_AckConnectRequest))
	{
		psp1->flags = -EDOM;
		// UNRESOLVED! Set last error?
		return NULL;
	}

	psp1->passive = 1;	// override what is provided by ULA
	CommandNewSession objCommand;
	//
	CSocketItemDl *socketItem = CSocketItemDl::CreateControlBlock(listenOn, psp1, objCommand);
	if(socketItem == NULL)
		return NULL;

	if(! socketItem->AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for listen");
		socketItem->FreeAndDisable();
		return NULL;
	}

	socketItem->SetState(LISTENING);
	// MUST set the state before calling LLS so that event-driven state transition may work properly

	CSocketItemDl *p = socketItem->CallCreate(objCommand, FSP_Listen);
	if (p == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the LLS socket to listen");
		socketItem->FreeAndDisable();
	}
	return p;
}




//[API: Accept]
//	CHALLENGING-->COMMITTED/CLOSABLE
// Given
//	FSPHANDLE	the listening socket
// Return
//	One FSP socket that accepts remote connection request
// Remark
//	This function is blocking, called only
//	when the function pointer onAccepting is NULL in the socket parameter of ListenAt.
DllSpec
FSPHANDLE FSPAPI Accept1(FSPHANDLE h)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)h;
		return pSocket->Accept1();
	}
	catch (...)
	{
		return NULL;
	}
}



// Return
//	The socket handle if there is one backlog item successfully processed.
//	NULL if there is internal error
// Remark
//	This is function is blocking. It wait until success or internal error found
CSocketItemDl *CSocketItemDl::Accept1()
{
	BackLogItem	*pLogItem;
	while(LockAndValidate())
	{
		pLogItem = pControlBlock->backLog.Peek();
		if (pLogItem != NULL)
		{
			CSocketItemDl *p = ProcessOneBackLog(pLogItem);
			pControlBlock->backLog.Pop();
			SetMutexFree();
			return p;
		}
		//
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
	}
	//
	return NULL;
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
//	the function called back on connected should be given as the onAccepted function pointer
//  in the structure pointed by PSP_SocketParameter.
//	If it is NULL, this function is blocking
DllSpec
FSPHANDLE FSPAPI Connect2(const char *peerName, PFSP_Context psp1)
{
	if(psp1->sendSize < 0 || psp1->recvSize < 0 || psp1->sendSize + psp1->recvSize > MAX_FSP_SHM_SIZE + MIN_RESERVED_BUF)
	{
		psp1->flags = -ENOMEM;
		return NULL;
	}

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	CommandNewSession objCommand;

	psp1->passive = 0;		// override what is provided by ULA
	psp1->welcome = NULL;	// an active connection request shall have no welcome message
	psp1->len = 0;			// or else memory access exception may occur

	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->flags = -EBADF;	// -E_HANDLE ?
		return NULL;
	}

	if(! socketItem->AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for connect");
		socketItem->FreeAndDisable();
		return NULL;
	}

	socketItem->SetPeerName(peerName, strlen(peerName));
	socketItem->SetState(CONNECT_BOOTSTRAP);

	CSocketItemDl *p = socketItem->CallCreate(objCommand, InitConnection);
	if (p == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the LLS socket to request connection establishment");
		socketItem->FreeAndDisable();
	}

	if (psp1->onAccepted == NULL)
	{
		p = socketItem->WaitingConnectAck();
		if (p != NULL)
			p->CopyOutContext(psp1);
	}

	return p;
}



// Given
//	BackLogItem *	the fetched backlog item of the listening socket
// Do
//	create new socket, prepare the acknowledgement
//	and call LLS to send the acknowledgement to the connnection request or multiplication request
// Return
//	true if success
//	false if failed.
CSocketItemDl *CSocketItemDl::ProcessOneBackLog(BackLogItem	*pLogItem)
{
	// TODO: set the default interface to non-zero?
	CommandNewSession objCommand;
	CSocketItemDl * socketItem;
	//
	socketItem = PrepareToAccept(*pLogItem, objCommand);
	if (socketItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Process listening backlog: insufficient system resource?");
		RejectRequest(pLogItem->acceptAddr.idALF, ENOSPC);
		return NULL;
	}
	// lost some possibility of code reuse, gain flexibility (and reliability)
	if (pLogItem->idParent == 0 && !socketItem->ToWelcomeConnect(*pLogItem)
	|| pLogItem->idParent != 0 && !socketItem->ToWelcomeMultiply(*pLogItem))
	{
		RejectRequest(pLogItem->acceptAddr.idALF, EPERM);
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}
	//
	if (!socketItem->CallCreate(objCommand, FSP_Accept))
	{
		REPORT_ERRMSG_ON_TRACE("Process listening backlog: cannot synchronize - local IPC error");
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}
	//
	return socketItem;
}



// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connnection request or multiplication request
void CSocketItemDl::ProcessBacklogs()
{
	BackLogItem		*pLogItem;
	for (; (pLogItem = pControlBlock->backLog.Peek()) != NULL; pControlBlock->backLog.Pop())
	{
		ProcessOneBackLog(pLogItem);
	}
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
	if(! this->context.passive)
	{
		newContext.welcome = NULL;
		newContext.len = 0;
	}
	else // this->InState(LISTENING)
	{
		newContext.onAccepting = NULL;
		newContext.passive = 0;
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



// LISTENING-->|--[Rcv.CONNECT_REQUEST]-->{Notify}
//	| --[Rcv.CONNECT_REQUEST]-->{Notify}
//		| -->[API:Accept]
//			-->{new context}CHALLENGING-->[Send ACK_CONNECT_REQ]
// Given
//	BackLogItem &	the reference to the acception backlog item
// Do
//	(ACK_CONNECT_REQ, Initial SN, Expected SN, Timestamp, Receive Window[, responder's half-connection parameter[, payload])
// Return
//	true if to accept the connection
//	false if to reject
// Remark
//	As the connection context is yet to be prepared further, context.onAccepting MAYNOT read or write anything
bool LOCALAPI CSocketItemDl::ToWelcomeConnect(BackLogItem & backLog)
{
	PFSP_IN6_ADDR p = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	//
	SetState(CHALLENGING);
	SetNewTransaction();
	// ACK_CONNECT_REQ is a singleton transmit transaction
	// Ask ULA whether to accept the connection
	if(context.onAccepting != NULL && context.onAccepting(this, & backLog.acceptAddr, p) < 0)
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}
	if(pendingSendBuf != NULL && pendingSendSize + sizeof(FSP_AckConnectRequest) > MAX_BLOCK_SIZE)
	{
		// UNRESOLVED! report that ULA should not piggyback too large payload on ACK_CONNECT_REQ?
		return false;
	}

	pControlBlock->sendBufferNextSN = pControlBlock->sendWindowFirstSN + 1;
	pControlBlock->sendBufferNextPos = 1;	// reserve the head packet
	//
	memcpy(&pControlBlock->connectParams, &backLog, FSP_MAX_KEY_SIZE);
	//^following fields are filled later
	//
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	skb->version = THIS_FSP_VERSION;
	skb->opCode = ACK_CONNECT_REQ;
	skb->len = sizeof(FSP_AckConnectRequest);
	// And the content of the header is generated on the fly
	if(pendingSendBuf != NULL)
	{
		memcpy(GetSendPtr(skb) + skb->len, pendingSendBuf, pendingSendSize);
		skb->len += pendingSendSize;
		//
		pendingSendBuf = NULL;
		pendingSendSize = 0;
	}
	// else let ProcessPendingSend eventually transmit the welcome message, if any
	skb->InitFlags<TransactionEnded>();
	skb->ReInitMarkComplete();

	return true;
}



// Auxiliary function that is called when a new connection request is acknowledged by the responder
// CONNECT_AFFIRMING
//	|--[Rcv.ACK_CONNECT_REQ]-->[Notifiy]
//		|-->{Callback return to accept}
//			|-->{No Payload}-->COMMITTING2-->[Send ACK_START]
//			|-->{Has Payload}
//				|-->{EOT}-->COMMITTING2-->[Send PERSIST with EoT]
//				|-->{Not EOT}-->PEER_COMMIT-->[Send PERSIST]
//		|-->{Callback return to reject]-->NON_EXISTENT-->[Send RESET]
// Remark
//	Unlike ToWelcomeMultiply, 0RTT connection establishment is forbidden
//	for the end-to-end negotiation of the "root" session
// See also @LLS::OnConnectRequestAck
void CSocketItemDl::ToConcludeConnect()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv();
	BYTE *payload = GetRecvPtr(skb);

	// See also FSP_LLS$$CSocketItemEx::Connect()
	fidPair.source = pControlBlock->nearEndInfo.idALF;
	//^As by default Connect2 set the cached fiber ID in the DLL SocketItem to 0

	// Deliver the optional payload and skip the ACK_CONNECT_REQ packet
	// See also ControlBlock::InquireRecvBuf()
	context.welcome = payload;
	context.len = skb->len;

	skb->ReInitMarkDelivered();
	// but preserve the packet flag for EoT detection, etc.
	pControlBlock->SlideRecvWindowByOne();	// ACK_CONNECT_REQ, which may carry welcome
	// But // CONNECT_REQUEST does NOT consume a sequence number
	// See @LLS::OnGetConnectRequest

	ControlBlock::seq_t seq0 = pControlBlock->sendBufferNextSN;
	SetState(ESTABLISHED);
	SetNewTransaction();
	SetMutexFree();
	if(context.onAccepted != NULL && context.onAccepted(this, &context) < 0)
	{
		if(WaitUseMutex())	// in case of memory access error
			RecycLocked();
		return;
	}

	if (pControlBlock->sendBufferNextSN != seq0)
		return;
	//^it works as pControlBlock->sendBufferBlockN <= INT32_MAX
	// ACK_START implies to Commit. See also ToWelcomeMultiply:
	SetHeadPacketIfEmpty(ACK_START);
	SetState(COMMITTING2);
	Call<FSP_Send>();
}



// Given
//	FSPOperationCode the header packet's operation code
// Do
//	Set the head packet
// Return
//	The pointer to the descriptor of the original header packet, or
//	NULL if the send queue used to be empty
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
	skb->InitFlags<TransactionEnded>();
	skb->ReInitMarkComplete();
	return NULL;
}



// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	uint32_t		the fiber ID, in host byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed at the address given
DllSpec
uint32_t * FSPAPI TranslateFSPoverIPv4(PFSP_IN6_ADDR p, uint32_t dwIPv4, uint32_t fiberID)
{
	p->_6to4.prefix = PREFIX_FSP_IP6to4;
	p->_6to4.ipv4 = dwIPv4;
	p->_6to4.port = DEFAULT_FSP_UDPPORT;
	p->idALF = htobe32(fiberID);
	return & p->idHost;
}



// Given
//	FSPHANDLE	the FSP socket handle
//	octet *		the new session key assumed to have been established by ULA
//	int			the size of the key, number of octets
// Do
//	Manage to call LLS to apply the new session key
// Return
//	0 if no error
//	negative: the error number
//	(e.g. -EDOM if parameter error)
// Remark
//	By default set key life in term of octets may be sent maximumly with master key unchanged to 2^63-1
DllSpec
int FSPAPI InstallMasterKey(FSPHANDLE h, octet * key, int32_t keyBytes)
{
	if (keyBytes <= 0 || keyBytes > INT32_MAX / 8)
		return -EDOM;
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)h;
		return pSocket->InstallRawKey(key, keyBytes * 8, INT64_MAX);
	}
	catch(...)
	{
		return -EFAULT;
	}
}



// Given
//	octet *		octet stream of the key
//	int32_t		length of the key in bits, should be multiplication of 64
//	uint64_t	life of the key, maximum number of packets that may utilize the key
// Return
//	-EDEADLK	if cannot obtain the right lock
//	-EIO	if cannot trigger LLS to do the installation work through I/O
//	0		if no failure
// Remark
//	We need the mutex lock because it shall be atomic to copy in key material structure as the parameter
//	Normally only in CLOSABLE or COMMITTING2 state may a session key installed
//	however it is not checked because the function
//	might be called in the callback function before the right state migration
//	Take the snapshot of sendBufferNextSN and pass the snapshot as the parameter
//	because it is perfectly possible that installation of new session key is followed by
//	sending new data so tight that LLS has not yet excute FSP_InstallKey before the send queue changed.
//	the input key material would be truncated if it exceeds the internal command buffer capacity
int LOCALAPI CSocketItemDl::InstallRawKey(octet *key, int32_t keyBits, uint64_t keyLife)
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	CommandInstallKey objCommand(pControlBlock->sendBufferNextSN, keyLife);
	this->InitCommand<FSP_InstallKey>(objCommand);
	if (keyBits > sizeof(objCommand.ikm) * 8)
		keyBits = sizeof(objCommand.ikm) * 8;
	memcpy(objCommand.ikm, key, keyBits/8);
	pControlBlock->connectParams.keyBits = keyBits;

	SetMutexFree();
	return Call(objCommand, sizeof(objCommand)) ? 0 : -EIO;
}



// For blocking mode Connect2. See also ToConcludeConnect() and WaitEventToDispatch()
CSocketItemDl * CSocketItemDl::WaitingConnectAck()
{
	FSP_Session_State s = NON_EXISTENT;
	uint64_t t0 = GetTickCount64();
	while (WaitUseMutex() && (s = GetState()) < ESTABLISHED)
	{
		if (GetTickCount64() - t0 > TRANSIENT_STATE_TIMEOUT_ms)
		{
			context.flags = -ETIMEDOUT;
			FreeAndDisable();
			return NULL;
		}
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
	}

	if (s < ESTABLISHED)
	{
		context.flags = -ECONNRESET;
		FreeAndDisable();
		return NULL;
	}

	SetMutexFree();
	return this;
}
