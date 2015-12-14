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
	socketItem->SetState(LISTENING);
	// MUST set the state before calling LLS so that event-driven state transition may work properly
	return socketItem->CallCreate(objCommand, FSP_Listen);
}



//[API: Connect]
//	CLOSED-->{when DSRC hit}-->QUASI_ACTIVE-->[Send RESUME]{enable retry}
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
//
// UNRESOLVED!? Firstly, try to resume what is in CLOSABLE. CLOSABLE is in the work set, CLOSED is in the recyling cache
// item->InState(CLOSABLE) || item->InState(PRE_CLOSED)
////QUASI_ACTIVE-->/ACK_INIT_CONNECT/ 
////    -->[Send CONNECT_REQUEST]-->CONNECT_AFFIRMING
//pSocket = MapSocket();
//if(pSocket != NULL && pSocket->IsInUse())
//{
//	// initState
//	pSocket->AffirmConnect();
//	return;
//}
//(2)	DLL通过Disconnected Session Recycling Cache管理，尝试恢复匹配的已关闭连接
// The event handle, memory address space, was kept to be reused.
//	如果新建连接时发现有CLOSABLE或CLOSED状态的会话，会话密钥尚未过期而远端Canonical Name相同，则视为Disconnected Session Recycling Cache命中。
//	DSRC命中时，LLS首先尝试使用SCB中所保存的地址建立连接，如果超时失败，则尝试重新解析远端地址，重试建立连接，并更新SCB。
//	在关闭连接时，会话密钥可用的生命期限、关闭连接的时刻均保存在SCB的连接参数中。
//	在CLOSED的SCB，当ULA通过DLL调用新建连接命令时，如果DSRC在中被命中，则转到QUASI_ACTIVE状态，DLL将RESUME命令报文排入发送队列，调用LLS向远端发送。
//	在CLOSED状态，LLS接收进程在收到RESUME并且在命中DSRC的前提下，通知DLL回调ULA，若ULA指示“保持连接”，则DLL立即完成到ACTIVE状态的转移。
//	所要回复的PERSIST命令报文由LLS根据SCB状态，在得到DLL指令时推到空的发送队列然后发送。
//	从CLOSED状态到NON_EXISTENT，要么是由超时控制的会话密钥超时，要么是上述回调时ULA指示“拒绝”。
//	在QUASI_ACTIVE状态，当LLS收到PERSIST时立即改为ACTIVE，并通知DLL收取数据。
//	在QUASI_ACTIVE状态，当LLS按顺序收到的是COMMIT报文时立即改为PEER_COMMIT，并通知DLL收取数据。
//	在QUASI_ACTIVE状态，当LLS收到ACK_INIT_CONNECT时，视为新建连接的连接响应，完成到CONNECT_AFFIRMING状态的转变。
//	LLS此时回复以CONNECT_REQUEST报文。这种情形也是连接复活失败的一种，另一种是收到RESET，新建连接也被拒绝。
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

	CSocketItemDl * socketItem = CSocketItemDl::FindDisconnectedSession(peerName);
	if(socketItem != NULL && socketItem->Reinitialize(psp1) >= 0)
	{
		socketItem->isFlushing = CSocketItemDl::FlushingFlag::REVERT_TO_RESUME;
		socketItem->AddOneShotTimer(CONNECT_INITIATION_TIMEOUT_ms * 2);
		return socketItem->CallCreate(objCommand, FSP_Resurrect);
	}
	
	socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->u.flags = EBADF;	// E_HANDLE;
		return NULL;
	}

	socketItem->AddOneShotTimer(CONNECT_INITIATION_TIMEOUT_ms * 2);
	socketItem->SetPeerName(peerName, strlen(peerName));
	return socketItem->CallCreate(objCommand, InitConnection);
}



// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connnection request or multiplication request
void CSocketItemDl::ProcessBacklog()
{
	// TODO: set the default interface to non-zero?
	CommandNewSession objCommand;
	BackLogItem		logItem;
	CSocketItemDl * socketItem;
	// firstly, fetch the backlog item
	while(pControlBlock->backLog.Pop(& logItem) >= 0)
	{
		socketItem = PrepareToAccept(logItem, objCommand);
		if(socketItem == NULL)
		{
			TRACE_HERE("Process listening backlog: insufficient system resource?");
			this->InitCommand<FSP_Reject>(objCommand);
			this->Call(objCommand, sizeof(struct CommandToLLS));
			return;
		}
		// lost some possibility of code reuse, gain flexibility (and reliability)
		if(logItem.idParent == 0 && ! socketItem->ToWelcomeConnect(logItem)
		|| logItem.idParent != 0 && ! socketItem->ToWelcomeMultiply(logItem))
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
//	|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
void CSocketItemDl::ToConcludeConnect()
{
	if(! WaitUseMutex())
		return;

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

	SetState(ESTABLISHED);
	if(fpAccepted != NULL && fpAccepted(this, &context) < 0)
	{
		Recycle();
		return;
	}

	BeginSubSession();
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
int FSPAPI InstallAuthenticKey(FSPHANDLE h, BYTE * key, int keySize, int32_t keyLife, FlagEndOfMessage eotFlag)
{
	if(keySize < FSP_MIN_KEY_SIZE || keySize > FSP_MAX_KEY_SIZE || keySize % sizeof(uint64_t) != 0 || keyLife <= 0)
		return -EDOM;
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)h;
		return pSocket->InstallKey(key, keySize, keyLife, eotFlag);
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
// The protocol is:
//	The final responder install the new session key immediately
//	The final initiator install the new session key for send direction as soon as the COMMIT packet is transmitted
//	The final initiator install the new session key for receive direction as soon as the ACK_FLUSH packet is received
//	The final initiator is not necessarily the initial initiator.
int LOCALAPI CSocketItemDl::InstallKey(BYTE *key, int keySize, int32_t keyLife, FlagEndOfMessage eotFlag)
{
	if(! WaitUseMutex())
		return -EINTR;

	if(_InterlockedCompareExchange8(& pControlBlock->hasPendingKey, HAS_PENDING_KEY_FOR_SEND | HAS_PENDING_KEY_FOR_RECV, 0) != 0)
	{
		SetMutexFree();
		return -EAGAIN;
	}
	//
	memcpy(& pControlBlock->connectParams, key, keySize);
	pControlBlock->connectParams.keyLength = keySize;
	pControlBlock->connectParams.initialSN = keyLife;

	// It is the final initiator in key establishment
	if(eotFlag == NOT_END_ANYWAY)
	{
		SetMutexFree();
		return 0;
	}

	// It is the final responder in key establishment
	int r = Call<FSP_InstallKey>() ? 0 : -EIO;
	pControlBlock->hasPendingKey = 0;
	SetMutexFree();
	return r;
}



// The sibling functions of Connect2() for 'fast reconnect', 'session resume'
// and 'connection multiplication' (ConnectMU), is in Multiply.cpp
