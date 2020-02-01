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

 // The Translation Look-aside Buffer of the FSP socket items for ULA
CSocketDLLTLB CSocketItemDl::socketsTLB;


// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	uint32_t		the fiber ID, in no particular byte order
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
	p->idALF = fiberID;
	return & p->idHost;
}


//[API: Listen]
//	NON_EXISTENT-->LISTENING
// Given
//	const PFSP_IN6_ADDR		the pointer to the IPv6 address that the passive socket to listen at
//	PFSP_Context			the pointer to the parameter structure of the socket to create
// Return
//	NULL if it fails immediately, or else 
//  the handle of the passive FSP socket whose properties might be peek and/or set later
// Remark
//	FSP over UDP/IPv4 address SHALL be converted to 'canonical' FSP-aligned IPv6 address
//	The handle returned might be unusable, if PFSP_Context::onError() report error later
DllSpec
FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR listenOn, PFSP_Context psp1)
{ 
	psp1->passive = 1;	// override what is provided by ULA
	CommandNewSession objCommand;
	//
	CSocketItemDl *socketItem = CSocketItemDl::CreateControlBlock(listenOn, psp1, objCommand);
	if(socketItem == NULL)
		return NULL;

	if(! socketItem->AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for listen");
		socketItem->Free();
		return NULL;
	}

	socketItem->SetState(LISTENING);
	// MUST set the state before calling LLS so that event-driven state transition may work properly

	CSocketItemDl *p = socketItem->CallCreate(objCommand, FSP_Listen);
	if (p == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the LLS socket to listen");
		socketItem->Free();
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

	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->flags = -EBADF;	// -E_HANDLE ?
		return NULL;
	}

	if(! socketItem->AddOneShotTimer(TRANSIENT_STATE_TIMEOUT_ms))
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set time-out clock for connect");
		socketItem->Free();
		return NULL;
	}

	socketItem->SetPeerName(peerName, strlen(peerName));
	socketItem->SetState(CONNECT_BOOTSTRAP);

	// could be exploited by ULA to make services distinguishable
	memcpy(&socketItem->context, psp1, sizeof(FSP_SocketParameter));
	socketItem->pendingSendBuf = (octet*)psp1->welcome;
	socketItem->pendingSendSize = psp1->len;

	CSocketItemDl *p = socketItem->CallCreate(objCommand, InitConnection);
	if (p == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the LLS socket to request connection establishment");
		socketItem->Free();
	}
	else if (psp1->onAccepted == NULL)
	{
		p = socketItem->WaitingConnectAck();
	}

	return p;
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
//	CommandNewSession & [_Out_]	the command context to be filled
//	FSP_ServiceCode				the service code to be passed
// Do
//	Fill in the command context and call LLS. The service code MUST be one that creates an LLS FSP socket
// Return
//	The DLL FSP socket created if succeeded,
//	NULL if failed.
CSocketItemDl * LOCALAPI CSocketItemDl::CallCreate(CommandNewSession & objCommand, FSP_ServiceCode cmdCode)
{
	objCommand.fiberID = fidPair.source;
	objCommand.idProcess = idThisProcess;
	objCommand.opCode = cmdCode;
#ifdef TRACE
	printf("%s: fiberId = %d, fidPair.source = %d\n", CServiceCode::sof(cmdCode), objCommand.fiberID, fidPair.source);
#endif
	CopyFatMemPointo(objCommand);
	return Call(objCommand, sizeof(objCommand)) ? this : NULL;
}



// Given
//	PFSP_IN6_ADDR		const, the listening addresses of the passive FSP socket
//	PFSP_Context		the connection context of the socket, given by ULA
//	CommandNewSession & the command context of the socket,  to pass to LLS
// Return
//	NULL if it failed, or else the new allocated socket whose session control block has been initialized
CSocketItemDl * LOCALAPI CSocketItemDl::CreateControlBlock(const PFSP_IN6_ADDR nearAddr, PFSP_Context psp1, CommandNewSession & cmd)
{
	CSocketItemDl *socketItem = socketsTLB.AllocItem();
	if (socketItem == NULL)
		return NULL;

	socketItem->dwMemorySize = CSocketItemDl::AlignMemorySize(psp1);
	if (socketItem->dwMemorySize < 0 || !socketItem->InitLLSInterface(cmd))
	{
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}
	socketItem->SetConnectContext(psp1);
	socketItem->fidPair.source = nearAddr->idALF;
	//
	FSP_ADDRINFO_EX & nearEnd = socketItem->pControlBlock->nearEndInfo;
	if(nearAddr->_6to4.prefix == PREFIX_FSP_IP6to4)
	{
		nearEnd.InitUDPoverIPv4(psp1->ifDefault);
		nearEnd.idALF = nearAddr->idALF;
		nearEnd.ipi_addr = nearAddr->_6to4.ipv4;
	}
	else
	{
		nearEnd.InitNativeIPv6(psp1->ifDefault);
		*(PIN6_ADDR) & nearEnd = *(PIN6_ADDR)nearAddr;
	}
	// Application Layer Thread ID other than the first default would be set in the LLS

	return socketItem;
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



// Given
//	BackLogItem *	the fetched backlog item of the listening socket
// Do
//	create new socket, prepare the acknowledgement
//	and call LLS to send the acknowledgement to the connection request or multiplication request
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
	if((pLogItem->idParent == 0 && !socketItem->ToWelcomeConnect(*pLogItem))
	|| (pLogItem->idParent != 0 && !socketItem->ToWelcomeMultiply(*pLogItem)))
	{
		RejectRequest(pLogItem->acceptAddr.idALF, EPERM);
		socketItem->Free();
		return NULL;
	}
	//
	if (!socketItem->CallCreate(objCommand, FSP_Accept))
	{
		REPORT_ERRMSG_ON_TRACE("Process listening backlog: cannot synchronize - local IPC error");
		socketItem->Free();
		return NULL;
	}
	//
	return socketItem;
}



// Fetch each of the backlog item in the listening socket, create new socket, prepare the acknowledgement
// and call LLS to send the acknowledgement to the connection request or multiplication request
void CSocketItemDl::ProcessBacklogs()
{
	BackLogItem		*pLogItem;
	for (; (pLogItem = pControlBlock->backLog.Peek()) != NULL; pControlBlock->backLog.Pop())
	{
		ProcessOneBackLog(pLogItem);
	}
}


// Given
//	BackLogItem &		the reference to the accepting backlog item
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
#ifdef TRACE // & TRACE_SLIDEWIN)
	printf("Expected SN: %u, set to %u\n", backLog.expectedSN, pSocket->pControlBlock->recvWindowExpectedSN);
#endif
	return pSocket;
}



// LISTENING-->|--[Rcv.CONNECT_REQUEST]-->{Notify}
//	| --[Rcv.CONNECT_REQUEST]-->{Notify}
//		| -->[API:Accept]
//			-->{new context}CHALLENGING-->[Send ACK_CONNECT_REQ]
// Given
//	BackLogItem &	the reference to the accepting backlog item
// Do
//	(ACK_CONNECT_REQ, Initial SN, Expected SN, Timestamp, Receive Window[, payload])
// Return
//	true if to accept the connection
//	false if to reject
// Remark
//	As the connection context is yet to be prepared further, context.onAccepting MAYNOT read or write anything
//	Here there is not a protocol limitation but an API enforced limitation:
//	prepared welcome message MUST fit into the preallocated send buffer
//	See also PrepareToSend
//	Attention please! ULA MAY NOT send data onAccepting!
bool LOCALAPI CSocketItemDl::ToWelcomeConnect(BackLogItem & backLog)
{
	PFSP_IN6_ADDR p = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES - 1];
	//
	SetState(CHALLENGING);
	// Ask ULA whether to accept the connection
	if(context.onAccepting != NULL && context.onAccepting(this, & backLog.acceptAddr, p) < 0)
		return false;
	//
	memcpy(&pControlBlock->connectParams, &backLog, FSP_MAX_KEY_SIZE + FSP_TAG_SIZE);
	//^following fields are filled later
	//
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	if (pendingSendBuf != NULL)
	{
		register ControlBlock::PFSP_SocketBuf p = skb;
		int32_t capacity;
		void* tgt = pControlBlock->InquireSendBuf(&capacity);
		if (capacity < pendingSendSize)
			return false; // UNRESOLVED! tell to ULA that it does not conform to implement protocol?
		memcpy(tgt, pendingSendBuf, pendingSendSize);
		//
		octet cFlag = this->context.precompress ? (1 << Compressed) : 0;
		int32_t m = (pendingSendSize - 1) / MAX_BLOCK_SIZE;
		for (register int j = 0; j < m; j++)
		{
			p->version = THIS_FSP_VERSION;
			p->opCode = PURE_DATA;
			p->flags = cFlag;
			p->len = MAX_BLOCK_SIZE;
			p++;
		}
		// it might be redundant to set the opCode of the first packet, but it do little harm and is safer and quicker
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->flags = cFlag | (1 << TransactionEnded);
		p->len = pendingSendSize - MAX_BLOCK_SIZE * m;
		// unlock them in a batch
		m++;
		for (register int j = 1; j < m; j++)
		{
			(p++)->ReInitMarkComplete();
		}
		//^the header packet is still locked
		// 
		pendingSendBuf = NULL;
		pendingSendSize = 0;
		pControlBlock->sendBufferNextPos = m;
		pControlBlock->sendBufferNextSN = GetSendWindowFirstSN() + m;
	}
	else
	{
		skb->version = THIS_FSP_VERSION;
		skb->len = 0;
		skb->InitFlags<TransactionEnded>();
		// Mark the reserved head packet ready
		pControlBlock->sendBufferNextPos = 1;
		pControlBlock->sendBufferNextSN = GetSendWindowFirstSN() + 1;
	}
	skb->opCode = ACK_CONNECT_REQ;
	skb->ReInitMarkComplete();

	return true;
}



// Auxiliary function that is called when a new connection request is acknowledged by the responder
// CONNECT_AFFIRMING
//|--[Rcv.ACK_CONNECT_REQ]-->[Notify]
//   |-->{Callback return to accept}
//	  |-->{EOT}
//		 |-->{No Payload to Send}-->COMMITTING2-->[Send ACK_START]
//		 |-->{Has Payload to Send}
//			|-->{ULA-flushing}-->COMMITTING2
//				-->[Send PERSIST with EoT]
//			|-->{Not ULA-flushing}-->PEER_COMMIT-->[Send PERSIST]
//	  |-->{Not EOT}
//		 |-->{No Payload to Send}-->COMMITTING-->[Send ACK_START]
//		 |-->{Has Payload to Send}
//			|-->{ULA-flushing}-->COMMITTING
//				-->[Send PERSIST with EoT]
//			|-->{Not ULA-flushing}-->ESTABLISHED-->[Send PERSIST]
//   |-->{Callback return to reject]-->NON_EXISTENT-->[Send RESET]
// Remark
//	Unlike ToWelcomeMultiply, 0RTT connection establishment is forbidden
//	for the end-to-end negotiation of the "root" session
// See also @LLS::OnConnectRequestAck
void CSocketItemDl::ToConcludeConnect()
{
	ControlBlock::seq_t seq0 = pControlBlock->sendBufferNextSN;
	FSP_Session_State s0;
	fidPair.source = pControlBlock->nearEndInfo.idALF;
	//^As by default Connect2 set the cached fiber ID in the DLL SocketItem to 0
	// Prepare for install master session key
	peerCommitted = pControlBlock->GetFirstReceived()->GetFlag<TransactionEnded>();
	s0 = peerCommitted ? PEER_COMMIT : ESTABLISHED;
	SetState(s0);
	if (peerCommitted)
		pControlBlock->SnapshotReceiveWindowRightEdge();
	// Prepare for immediate send onAccepted
	SetNewTransaction();
	SetMutexFree();
	if(context.onAccepted != NULL && context.onAccepted(this, &context) < 0)
	{
		if(WaitUseMutex())	// in case of memory access error
			Free();
		return;
	}

	// If it has not sent anything onAccepted, send an immediate acknowledgement to ACK_CONNECT_REQ
	if (pControlBlock->sendBufferNextSN == seq0)
	{
		SetHeadPacketIfEmpty(ACK_START);
		SetState(s0 == ESTABLISHED ? COMMITTING : COMMITTING2);
	}
	//^it works as pControlBlock->sendBufferBlockN <= INT32_MAX
	// ACK_START implies to Commit. See also ToWelcomeMultiply:
	Call<FSP_Start>();
}



// Given
//	FSPOperationCode the header packet's operation code
// Do
//	Set the head packet
// Return
//	The pointer to the descriptor of the original header packet, or
//	NULL if the send queue used to be empty
ControlBlock::PFSP_SocketBuf CSocketItemDl::SetHeadPacketIfEmpty(FSPOperationCode c)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	ControlBlock::seq_t k = GetSendWindowFirstSN();
	if((ControlBlock::seq_t)_InterlockedCompareExchange((PLONG)&pControlBlock->sendBufferNextSN, k + 1, k) != k)
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
//	sending new data so tight that LLS has not yet executed FSP_InstallKey before the send queue changed.
//	the input key material would be truncated if it exceeds the internal command buffer capacity
int LOCALAPI CSocketItemDl::InstallRawKey(octet *key, int32_t keyBits, uint64_t keyLife)
{
	if (!WaitUseMutex())
		return (IsInUse() ? -EDEADLK : -EINTR);

	CommandInstallKey objCommand(pControlBlock->sendBufferNextSN, keyLife);
	this->InitCommand<FSP_InstallKey>(objCommand);
	if (keyBits > (int32_t)sizeof(objCommand.ikm) * 8)
		keyBits = sizeof(objCommand.ikm) * 8;
	memcpy(objCommand.ikm, key, keyBits/8);
	pControlBlock->connectParams.keyBits = keyBits;

	SetMutexFree();
	return Call(objCommand, sizeof(objCommand)) ? 0 : -EIO;
}



// TODO: Exploit a flag instead of internal state which might be premature because of data race between LLS and DLL
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
			Free();
			return NULL;
		}
		SetMutexFree();
		Sleep(TIMER_SLICE_ms);
	}

	if (s < ESTABLISHED)
	{
		context.flags = -ECONNRESET;
		Free();
		return NULL;
	}

	SetMutexFree();
	return this;
}



// For a prototype it does not worth the trouble to exploit hash table 
CSocketItemDl *	CSocketDLLTLB::HandleToRegisteredSocket(FSPHANDLE h)
{
	register CSocketItemDl *p = (CSocketItemDl *)h;
	for(register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		if (CSocketItemDl::socketsTLB.pSockets[i] == p)
			return ((!p->IsInUse() || p->InIllegalState()) ? NULL : p);
	}
	//
	return NULL;
}



// To obtain a free slot from the TLB. Try to allocate a new item if no slot is registered with a valid item
// Return
//	The pointer to the DLL FSP socket if allocated successfully
//	NULL if failed
CSocketItemDl * CSocketDLLTLB::AllocItem()
{
	AcquireMutex();

	CSocketItemDl * item = NULL;
	// Compress the array of pointers of allocated sockets
	if (sizeOfWorkSet >= MAX_CONNECTION_NUM)
	{
		register int n = sizeOfWorkSet;
		register int i, j, k;

		for (i = 0; i < n && pSockets[i]->inUse; i++)
			;
		if (i >= n)
			goto l_bailout;
		// 0 to i, left inclusively, right exclusively, index socket in use, compressively
		for (j = i + 1; ; j = k + 1)
		{
			for (; j < n && !pSockets[j]->inUse; j++)
				;
			// i to j, left inclusively, right exclusively, index socket free
			if (j >= n)
				break;
			//
			for (k = j + 1; k < n && pSockets[k]->inUse; k++)
				;
			// j to k, left inclusively, right exclusively, index socket in use
			memmove(pSockets + i, pSockets + j, sizeof(pSockets[0]) * (k - j));
			i += k - j;
			// on exit the loop totally at most (n - 1) items were moved 
			if (k >= n)
				break;
		}
		sizeOfWorkSet = i;
	}

	if (countAllItems < MAX_CONNECTION_NUM)
	{
		item = new CSocketItemDl();
		if (item == NULL)
			goto l_bailout;	// return NULL;
		countAllItems++;
	}
	else
	{
		item = head;
		if (item == NULL)
			goto l_bailout;	// return NULL;
		head = item->next;
		if (head != NULL)
			head->prev = NULL;
		else
			tail = NULL;
	}

	memset((octet *)item + sizeof(CSocketItem)
		, 0
		, sizeof(CSocketItemDl) - sizeof(CSocketItem));
	pSockets[sizeOfWorkSet++] = item;
	_InterlockedExchange8(& item->inUse, 1);

l_bailout:
	ReleaseMutex();
	return item;
}



// Given
//	CSocketItemDl *		the pointer to the DLL FSP socket
// Do
//	Try to put the socket in the list of the free socket items
void CSocketDLLTLB::FreeItem(CSocketItemDl *r)
{
	AcquireMutex();

	_InterlockedExchange8(& r->inUse, 0);
	r->next = NULL;
	r->prev = tail;
	if(tail == NULL)
	{
		head = tail = r;
	}
	else
	{
		tail->next = r;
		tail = r;
	}

	ReleaseMutex();
}



// Given
//	ALFID_T		the application layer fiber ID of the connection to find
// Return
//	The pointer to the FSP socket that matches the given ID
// Remark
//	The caller should check whether the returned socket is really in work by check the inUse flag
//	Performance is assumed acceptable
//	as this is a prototyped implementation which exploits linear search in a small set
CSocketItemDl * CSocketDLLTLB::operator[](ALFID_T fiberID)
{
	for(int i = 0; i < sizeOfWorkSet; i++)
	{
		if(pSockets[i]->fidPair.source == fiberID)
			return pSockets[i];
	}
	return NULL;
}
