/*
 * FSP lower-layer service program, process packets sent from the remote end
 * trigger DLL to fetch the data delivered on demand
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

#include "fsp_srv.h"
#include <assert.h>
#include <stdarg.h>


// 'Package' internal use only
struct _CookieMaterial
{
	uint32_t	salt;
	ALFID_T		idALF;
	ALFID_T		idListener;
};



#if (TRACE & (TRACE_HEARTBEAT | TRACE_OUTBAND | TRACE_SLIDEWIN)) && (TRACE & TRACE_PACKET)
#define TRACE_SOCKET()	\
	(printf_s("%s: local fiber#%u(_%X_) in state %s\n", __FUNCTION__ \
		, fidPair.source, be32toh(fidPair.source)		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpSendRecvWindowInfo())
#elif (TRACE & TRACE_SLIDEWIN)
#define TRACE_SOCKET()	\
	(printf_s("%s: local fiber#%u(_%X_) in state %s\n", __FUNCTION__ \
		, fidPair.source, be32toh(fidPair.source)		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpRecvQueueInfo())
#else
#define TRACE_SOCKET()
#endif



// The handler's main body to accept and process one particular remote packet
// See also SendPacket
// From the receiver's point of view the local fiber id was stored in the peer fiber id field of the received packet
int CLowerInterface::ProcessReceived()
{
	// From the receiver's point of view the local fiber id was stored in the peer fiber id field of the received packet
#ifdef OVER_UDP_IPv4
	countRecv -= sizeof(ALFIDPair);	// extra prefixed bytes are subtracted
	nearInfo.u.idALF = pktBuf->fidPair.peer;
#else
	pktBuf->fidPair.peer = nearInfo.u.idALF;
#endif

	FSPOperationCode opCode = (FSPOperationCode) pktBuf->hdr.hs.opCode;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("#%u(Near end's ALFID): packet %s(%d) received\n\tALFID of packet source is #%u\n"
		, nearInfo.u.idALF
		, opCodeStrings[opCode], (int)opCode, pktBuf->fidPair.source);
	printf_s("Remote address:\n");
	DumpNetworkUInt16((uint16_t *) & addrFrom, sizeof(addrFrom) / 2);
	printf_s("Near sink:\n");
	DumpNetworkUInt16((uint16_t *) & nearInfo.u, sizeof(nearInfo.u) / 2);
	printf_s("Fixed header:\n");
	DumpNetworkUInt16((uint16_t *) & pktBuf->hdr, sizeof(pktBuf->hdr) / 2);
#endif
	CSocketItemEx *pSocket = NULL;
	switch (opCode)
	{
	case INIT_CONNECT:
		OnGetInitConnect();
		break;
	case ACK_INIT_CONNECT:
		pSocket = MapSocket();
		if (pSocket == NULL || !pSocket->IsInUse())
			break;
		pSocket->OnInitConnectAck(FSP_OperationHeader<FSP_Challenge>());
		break;
	case CONNECT_REQUEST:
		OnGetConnectRequest();
		break;
	case RESET:
		pSocket = MapSocket();
		if (pSocket == NULL || !pSocket->IsInUse())
			break;
		pSocket->pktSeqNo = be32toh(pktBuf->hdr.sequenceNo);
		pSocket->headPacket = pktBuf;
		pSocket->OnGetReset(*FSP_OperationHeader<FSP_RejectConnect>());
		break;
	//
	case ACK_CONNECT_REQ:
	case NULCOMMIT:
	case PURE_DATA:
	case PERSIST:
	case ACK_FLUSH:
	case RELEASE:
	case MULTIPLY:
	case KEEP_ALIVE:
		pSocket = MapSocket();
		if (pSocket == NULL)
		{
#ifdef TRACE
			printf_s("Cannot map socket for local fiber#%u(_%X_)\ncommand: %s(%d)\n"
				, GetLocalFiberID(), be32toh(GetLocalFiberID())
				, opCodeStrings[opCode], (int)opCode);
#endif
			break;
		}
		pSocket->lenPktData = countRecv - be16toh(pktBuf->hdr.hs.offset);
		if (pSocket->lenPktData < 0 || pSocket->lenPktData > MAX_BLOCK_SIZE)
			break;
		// illegal packet is simply discarded!
		pSocket->pktSeqNo = be32toh(pktBuf->hdr.sequenceNo);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("%s[%d] packet #%u\n\tpayload length %d, to put onto the queue\n"
			, opCodeStrings[opCode], opCode, pSocket->pktSeqNo, pSocket->lenPktData);
#endif
		nearInfo.CopySinkInfTo(&pSocket->tempAddrAccept);
		// save the source address temporarily as it is not necessarily legitimate
		pSocket->sockAddrTo[MAX_PHY_INTERFACES] = addrFrom;
		pSocket->HandleFullICC(pktBuf, opCode);
		break;
		// UNRECOGNIZED packets are simply discarded
	default:
		;	// do nothing or give a warning?
	}

	return 0;
}



//LISTENING
//	|<-->[Rcv.INIT_CONNECT && {resource available}: Send ACK_INIT_CONNECT]
//	|<-->[Rcv.INIT_CONNECT && {resource unavailable}: Send RESET]
// Do
//	ACK_INIT_CONNECT, Cookie, Initiator's Check Code Reflected, Time-delta
//		or
//	RESET, Timestamp Reflected, Initiator's Check Code Reflected, Reason
// Remark
//  Usually an FSP node allocate a new ALFID randomly and respond with the new ALFID, not the listening ALFID.
//	Collision might occur o allocating the new ALFID in a high-load responder, but the possibility is low enough.
//	For a low-power IoT device the listener may accept only one connection request, and thus respond with the listening ALFID.
// TODO: there should be some connection initiation throttle control in RandALFID
// TODO: UNRESOLVED! admission-control here?
// TODO: UNRESOLVED! For FSP over IPv6, attach responder's resource reservation...
void CLowerInterface::OnGetInitConnect()
{
	// Silently discard connection request to black hole, and avoid attacks alike 'port scan'
	CSocketItemEx *pSocket = MapSocket();
	FSP_InitiateRequest* q;
	FSP_Challenge challenge;
	struct _CookieMaterial cm;
	timestamp_t t0, t1;

	if (pSocket == NULL || !pSocket->IsPassive())
		return;

	if (!pSocket->WaitUseMutex())
		return;

	// control structure, specified the local address (the Application Layer Thread ID part)
	// echo back the message at the same interface of receiving, only ALFID changed

	CtrlMsgHdr	hdrInfo;
	ALFID_T	fiberID;
	memset(&hdrInfo, 0, sizeof(CtrlMsgHdr));
	CopySinkInfTo(hdrInfo);

	fiberID = CLowerInterface::Singleton.AllocItemReserve();
	if (fiberID == 0)
	{
		SendPrematureReset(ENOENT);
		goto l_return;
	}
	if (hdrInfo.IsIPv6())
	{
		PIN6_ADDR hintAddr = (PIN6_ADDR)&hdrInfo.u;
		// by default exploit the first interface configured
		if (*(uint64_t*)hintAddr == 0)
		{
			memcpy(hintAddr, &addresses[0].sin6_addr, 12);
			*(ALFID_T*)((octet*)hintAddr + 12) = fiberID;
		}
		else if(SetEffectiveALFID(hintAddr, fiberID))
		{
			REPORT_ERROR_ON_TRACE();
			goto l_return;
		}
	}
	else
	{
		hdrInfo.u.idALF = fiberID;
	}

	// To make the FSP challenge of the responder	
	q = FSP_OperationHeader<FSP_InitiateRequest>();
	// the remote address is not changed
	t0 = be64toh(q->timeStamp);
	t1 = NowUTC();
	cm.salt = q->salt;
	cm.idALF = fiberID;
	cm.idListener = GetLocalFiberID();
	// the cookie depends on the listening fiber ID AND the responding fiber ID

	SetHeaderSignature(challenge, ACK_INIT_CONNECT);
	challenge.timeDelta = int32_t(t1 - t0);
	challenge.cookie = CalculateCookie(& cm, sizeof(cm), t1);
	challenge.initCheckCode = q->initCheckCode;

	// To support mobility to the maximum extent the effective listening addresses are enumerated on the fly
	CLowerInterface::Singleton.EnumEffectiveAddresses(challenge.params.subnets);
	SetConnectParamPrefix(challenge.params);
	challenge.params.idListener = cm.idListener;

	SetLocalFiberID(fiberID);
	SendBack((char *) & challenge, sizeof(challenge));

l_return:
	pSocket->SetMutexFree();
}



//CONNECT_BOOTSTRAP-->/ACK_INIT_CONNECT/
//	-->CONNECT_AFFIRMING-->[Send CONNECT_REQUEST]
// Do
//	Check the initiator's cookie, make the formal connection request towards the responder
// Remark
//	It does not matter whether idListener == GetRemoteFiberID()
// TODO: UNRESOLVED!? get resource reservation requirement from IPv6 extension header
void CSocketItemEx::OnInitConnectAck(FSP_Challenge* pkt)
{
	if (!WaitUseMutex())
		return;

	SConnectParam& initState = pControlBlock->connectParams;
	ALFID_T idListener = initState.idRemote;

	if (!InState(CONNECT_BOOTSTRAP))
		goto l_return;

	if (initState.initCheckCode != pkt->initCheckCode || idListener != pkt->params.idListener)
		goto l_return;
	// Remote sink info validated, to register validated remote address:
	// the officially announced IP address of the responder shall be accepted by the initiator
	memset(initState.allowedPrefixes, 0, sizeof(initState.allowedPrefixes));
	memcpy(initState.allowedPrefixes, pkt->params.subnets, sizeof(pkt->params.subnets));

	SetRemoteFiberID(initState.idRemote = CLowerInterface::Singleton.GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multi-home it is necessary even for IPv6
	SetNearEndInfo(CLowerInterface::Singleton.nearInfo);

	initState.timeDelta = pkt->timeDelta;
	initState.cookie = pkt->cookie;
	CLowerInterface::Singleton.EnumEffectiveAddresses(initState.allowedPrefixes);

	AffirmConnect(initState, idListener);

l_return:
	SetMutexFree();
}



/**
	prepare the backlog, filling in the information about the remote fiber ID, the suggested local fiber ID,
	the list of the remote address prefixes(for multi-home support) and the half-connection parameters.
	signal DLL (in the context of ULA) which polls the backlog and sets up the session context
	[into 'CHALLENGING'] (allocate state space, including data buffers, command queue, etc).
	it is tempting to acknowledge the connect request immediately to save some memory copy,
	however, it is not justified, for throughput throttling is overriding
 */
//LISTENING-->/CONNECT_REQUEST/-->[API{new context, callback}]
//	|<-->[Rcv.CONNECT_REQUEST]{&& duplication detected}
//		[Retransmit ACK_CONNECT_REQ]{at the head of the queue}
//	|-->[{return}Accept]
//		-->{new context}CHALLENGING-->[Send ACK_CONNECT_REQ]
//	|-->[{return}Reject]-->[Send RESET]{abort creating new context}
// UNRESOLVED!? Should queuing the request in case of single thread congestion because of WaitUseMutex
void CLowerInterface::OnGetConnectRequest()
{
	FSP_ConnectRequest *q = FSP_OperationHeader<FSP_ConnectRequest>();
	CSocketItemEx *pSocket = MapSocket();
	CSocketItemEx *newItem;
	const CtrlMsgHdr* pHdr;

	// UNRESOLVED!? Is this a unbeatable DoS attack to initiator if there is a 'man in the middle'?
	if(pSocket != NULL && pSocket->IsInUse())
	{
		// Check whether it is a collision
		if (pSocket->InState(CHALLENGING)
		&& pSocket->fidPair.peer == this->GetRemoteFiberID()
		&& pSocket->pControlBlock->connectParams.cookie == q->cookie)
		{
			if(! pSocket->WaitUseMutex())
				return;
			pSocket->EmitStart(); // hit
			pSocket->SetMutexFree();
		}
		// Or else it is a collision and is silently discard in case an out-of-order RESET reset a legitimate connection
		return;
	}

	// Silently discard the request onto illegal or non-listening socket
	pSocket = (*this)[q->params.idListener];	// a dialect of MapSocket
	if (pSocket == NULL || !pSocket->IsPassive())
		return;

	if (!pSocket->WaitUseMutex())
		return;

	// cf. OnInitConnectAck() and SocketItemEx::AffirmConnect()
	ALFID_T fiberID = GetLocalFiberID();
	struct _CookieMaterial cm;
	cm.salt = q->_init.salt;
	cm.idALF = fiberID;
	cm.idListener = q->params.idListener;
	// Attention please! Granularity of the time delta can be designated arbitrarily by the responder,
	// provided it is consistent between OnGetInitConnect and OnGetConnectRequest
	// UNRESOLVED! TODO: search the cookie blacklist at first
	timestamp_t tRecvInit = be64toh(q->_init.timeStamp) + q->timeDelta;
	if (q->cookie != CalculateCookie(&cm, sizeof(cm), tRecvInit))
	{
#ifdef TRACE
		printf_s("UNRESOLVED! TODO: put the cookie into the blacklist to fight against DDoS attack!?\n");
#endif
		pSocket->SetMutexFree();
		return;		// the packet has been updated and should be discarded
	}

	// Simply ignore the duplicated request
	SItemBackLog backlogItem;
	backlogItem.idRemote = GetRemoteFiberID();
	backlogItem.salt = q->_init.salt;
	if(pSocket->pControlBlock->backLog.Has(backlogItem))
		goto l_return;

	newItem = AllocItemCommit(pSocket->rootULA, GetLocalFiberID());
	if (newItem == NULL)
		goto l_return;

	newItem->lowState = NON_EXISTENT;
	newItem->ReplaceTimer(TRANSIENT_STATE_TIMEOUT_ms);

	assert(sizeof(backlogItem.allowedPrefixes) == sizeof(q->params.subnets));
	// secondly, fill in the backlog item if it is new
	pHdr = GetPacketNearInfo();
	// Note that FSP over IPv6 does NOT support NAT automatically, by design
	// However, participants of FSP MAY obtain the IPv6 network prefix
	// obtained after NAT by uPnP and fill in the subnets field with the value after translation
	backlogItem.acceptAddr.cmsg_level = pHdr->pktHdr.cmsg_level;
	if (pHdr->IsIPv6())
	{
		memcpy(backlogItem.allowedPrefixes, q->params.subnets, sizeof(TSubnets));
		pHdr->CopySinkInfTo(&backlogItem.acceptAddr);
	}
	else
	{	// FSP over UDP/IPv4
		register PFSP_IN6_ADDR fspAddr = (PFSP_IN6_ADDR) & backlogItem.acceptAddr;
		memset(backlogItem.allowedPrefixes, 0, sizeof(TSubnets));
		// For sake of NAT ignore the subnet prefixes reported by the initiator
		fspAddr->_6to4.prefix = PREFIX_FSP_IP6to4;
		//
		fspAddr->_6to4.ipv4 = *(u32*)&addrFrom.Ipv4.sin_addr;
		fspAddr->_6to4.port = addrFrom.Ipv4.sin_port;
		backlogItem.allowedPrefixes[0] = fspAddr->subnet;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("To accept connect request from address: ");
		DumpNetworkUInt16((uint16_t *)& fspAddr->subnet, sizeof(fspAddr->subnet) / 2);
#endif
		fspAddr->_6to4.ipv4 = pHdr->u.ipi_addr;
		fspAddr->_6to4.port = pHdr->u.idALF;
		fspAddr->idHost = 0;	// no for IPv4 no virtual host might be specified
		fspAddr->idALF = fiberID;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("To accept connect request at socket address: ");
		DumpNetworkUInt16((uint16_t *)& fspAddr->subnet, sizeof(fspAddr->subnet) / 2);
#endif
		backlogItem.acceptAddr.ipi6_ifindex = pHdr->u.ipi_ifindex;
	}
	// Ephemeral key materials(together with salt):
	backlogItem.initCheckCode = q->_init.initCheckCode;
	backlogItem.nboTimeStamp = q->_init.timeStamp;
	backlogItem.cookie = q->cookie;
	backlogItem.timeDelta = q->timeDelta;
	backlogItem.tDiff = NowUTC() - tRecvInit;
	//^SetFirstRTT can only be called when the connection context is fully established
	backlogItem.remoteHostID = nearInfo.IsIPv6() ? SOCKADDR_HOSTID(GetPacketSource()) : 0;
	//^See also GetRemoteFiberID()
	backlogItem.idParent = 0;
	rand_w32(& backlogItem.initialSN, 1);
	backlogItem.expectedSN = be32toh(q->initialSN);	// CONNECT_REQUEST does NOT consume a sequence number

	// lastly, put it into the backlog
	if (pSocket->pControlBlock->backLog.Put(backlogItem) < 0)
	{
#ifdef TRACE
		printf_s("Cannot put the connection request into the backlog of the listening session's control block.\n");
#endif
		newItem->RemoveTimers();
		FreeItem(newItem);
		goto l_return;
	}
	pSocket->Notify(FSP_NotifyAccepting);

l_return:
	pSocket->SetMutexFree();
}



//{CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, CHALLENGING, ACTIVE,
// COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE,
// SHUT_REQUESTED, PRE_CLOSED, CLONING}-->/RESET/
//    -->NON_EXISTENT-->[Notify]
//{NON_EXISTENT, LISTENING, CLOSED, Otherwise}<-->/RESET/{Ignore}
// UNRESOLVED! Lost of RESET is silently ignored?
// TODO: put the RESET AND other meaningful packet on the stack/queue
// The first RESET should be push onto the top. Repeated RESET should be append at the tail.
void LOCALAPI CSocketItemEx::OnGetReset(FSP_RejectConnect& reject)
{
	int32_t offset;
#ifdef TRACE
	printf_s("\nRESET got, in state %s\n\n", stateNames[lowState]);
#endif
	// No, we cannot reset a socket without validation
	if (!WaitUseMutex())
		return;

	switch (lowState)
	{
	// LISTENING state is not affected by reset signal
	case LISTENING:
		break;
	case CONNECT_BOOTSTRAP:
		if (reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
			&& reject.initCheckCode == pControlBlock->connectParams.initCheckCode)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
		break;
	case CONNECT_AFFIRMING:
		if (reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
			&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
		break;
	case CHALLENGING:
		if (reject.sn.initial == htobe32(pControlBlock->connectParams.initialSN)
			&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
		break;
	case CLONING:
		contextOfICC.snFirstRecvWithCurrKey = pktSeqNo;
		fidPair.peer = headPacket->fidPair.source;
		if (ValidateICC())
			DisposeOnReset();
		// otherwise simply ignore
		break;
	case CLOSED:
		// preserve the context for sake of connection resurrection
		break;
	default: 	// 'recoverable' states:
		offset = OffsetToRecvWinLeftEdge(be32toh(reject.sn.initial));
		if (-1 <= offset && offset < pControlBlock->recvBufferBlockN
			&& ValidateICC((FSP_NormalPacketHeader*)&reject, 0, fidPair.peer, 0))
		{
			DisposeOnReset();
		}
	}
	// ^SHUT_REQUESTED (passive shutdown) or 
	// ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED

	SetMutexFree();
}



// Given
//	PktBufferBlock *	Pointer to the buffer block that holds the remote packet received by the underling network service
//	FSPOperationCode	The code point of the remote 'operation'
// Do
//	Process the packet saved in the buffer that is assumed to have a full ICC
// Remark
//	Used to be OS-dependent. TODO: fight against single thread congestion (because of WaitUseMutex) of the socket pool
void CSocketItemEx::HandleFullICC(PktBufferBlock *pktBuf, FSPOperationCode opCode)
{
	if(! WaitUseMutex())
		return;

	// Because some service call may recycle the FSP socket in a concurrent way
	if (pControlBlock == NULL)
		goto l_return;
	SyncState();
	if (lowState <= 0 || lowState > LARGEST_FSP_STATE)
		goto l_return;

#if (TRACE & (TRACE_HEARTBEAT | TRACE_OUTBAND | TRACE_SLIDEWIN)) && (TRACE & TRACE_PACKET)
	printf_s("%s: local fiber#%u(_%X_) in state %s\n"
		"\t%s(%d) received, seq#%u\n"
		, __FUNCTION__ 
		, fidPair.source, be32toh(fidPair.source), stateNames[lowState]
		, opCodeStrings[opCode], opCode, pktSeqNo
	);
#endif
	pControlBlock->perfCounts.countPacketReceived++;
	// but not all received are legitimate, and PacketAccepted count in-band packet only.

	// MULTIPLY is semi-out-of-band COMMAND starting from a fresh new ALFID. Note that pktBuf is the received
	// In the CLONING state NULCOMMIT or PERSIST is the legitimate acknowledgement to MULTIPLY,
	// while the acknowledgement itself shall typically originate from some new ALFID.
	if (fidPair.peer != pktBuf->fidPair.source	// it should be rare
	 && opCode != MULTIPLY && (lowState != CLONING || (opCode != NULCOMMIT && opCode != PERSIST)) )
	{
		goto l_return;
	}
	//
	headPacket = pktBuf;
	switch (opCode)
	{
	case ACK_CONNECT_REQ:
		OnConnectRequestAck();
		break;
	case NULCOMMIT:
		OnGetNulCommit();
		break;
	case PURE_DATA:
		OnGetPureData();
		break;
	case PERSIST:
		OnGetPersist();
		break;
	case ACK_FLUSH:
		OnAckFlush();
		break;
	case RELEASE:
		OnGetRelease();
		break;
	case MULTIPLY:
		OnGetMultiply();
		break;
	case KEEP_ALIVE:
		OnGetKeepAlive();
	default:
		;	// Do nothing or give a warning?
	}
	//
l_return:
	SetMutexFree();
}



// Given
//	ControlBlock::seq_t &		[_out_] the accumulative acknowledgement
//	FSP_SelectiveNACK *			[_in_]  pointer to the SNACK header
// Do
//	Check whether KEEP_ALIVE or it special norm, ACK_FLUSH, is valid
// Return
//	Number of entries in the gap descriptor list (may be 0) if it is valid
//	negative if the packet is invalid
// Remark
//	DoS attack against long-term sessions by replaying KEEP_ALVIE is possible but mitigated
//	On enter the function, the SNACK header is encrypted; on leave, it has been decrypted
int CSocketItemEx::ValidateSNACK(ControlBlock::seq_t& ackSeqNo, FSP_SelectiveNACK* pSNACK)
{
	register FSP_FixedHeader* p1 = & headPacket->hdr;
	uint32_t sn = be32toh(p1->expectedSN);

	if (int32_t(sn - lastOOBSN) <= 0)
	{
#ifdef TRACE
		printf_s("%s has encountered replay attack? Sequence number:\n\tinband %u, oob %u - %u\n"
			, opCodeStrings[p1->hs.opCode], pktSeqNo, sn, lastOOBSN);
#endif
		return -EAGAIN;
	}
	
	int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
	if (d > pControlBlock->recvBufferBlockN || d < -pControlBlock->recvBufferBlockN)
	{
#ifdef TRACE
		printf_s("The packet number MUST fall in some safe window to defend against DoS attack\n"
			"Offset to left edge of the receive window = %d, window width = %d\n"
			, d, pControlBlock->recvBufferBlockN);
#endif
		return -EAGAIN;
	}

	if (lenPktData != 0)
	{
#ifdef TRACE
		printf_s("%s is out-of-band and CANNOT carry data: %d\n", opCodeStrings[p1->hs.opCode], lenPktData);
#endif
		return -EBADF;
	}

	int32_t len = be16toh(p1->hs.offset);
	// Note that extension header is encrypted as well. See also SendKeepAlive, SendAckFlush
	if (!ValidateICC(p1, len - sizeof(FSP_FixedHeader), fidPair.peer, GetSalt(*p1)))
	{
#ifdef TRACE
		printf_s("Invalid integrity check code of %s for fiber#%u!?\n"
			"Acknowledged sequence number: %u\n", opCodeStrings[p1->hs.opCode], fidPair.source, ackSeqNo);
#endif
		return -EPERM;
	}

	int n = le16toh(pSNACK->_h.length);
	// To defend against memory access (out-of-boundary) attack:
	if ((octet*)pSNACK - (octet*)p1 + n != len)
	{
		return -EFAULT;
	}
	n -= sizeof(FSP_SelectiveNACK);
	if (n < 0)
		return -EBADF;
#ifndef NDEBUG
	if (n % sizeof(FSP_SelectiveNACK::GapDescriptor) != 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("This is a malformed SNACK packet");
		return -EBADF;
	}
#endif
	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);

	ackSeqNo = le32toh(pSNACK->ackSeqNo);
#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s sequence number: %u^|^%u\n"
		"\taccumulatively acknowledged %u with %d gap(s)\n"
		, opCodeStrings[p1->hs.opCode], pktSeqNo, sn
		, ackSeqNo, n);
#endif
	if (!IsAckExpected(ackSeqNo))
		return -ENOENT;

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	// Calibrate RTT ONLY if left edge of the send window is to be advanced
	if(ackSeqNo - pControlBlock->sendWindowFirstSN > 0)
		UpdateRTT(le32toh(pSNACK->latestSN), le32toh(pSNACK->tLazyAck));

	lastOOBSN = sn;
	return n;
}



// Do
//	Check the validity of the acknowledgement to the CONNECT_REQUEST command and establish the ephemeral session key
// CONNECT_AFFIRMING
//	|--[Rcv.ACK_CONNECT_REQ]-->[Notify]
// See also @DLL::ToConcludeConnect()
void CSocketItemEx::OnConnectRequestAck()
{
	if (!InState(CONNECT_AFFIRMING))
		return;

	FSP_NormalPacketHeader& response = *(FSP_NormalPacketHeader*)& headPacket->hdr;
	if(be32toh(response.expectedSN) != pControlBlock->sendWindowFirstSN)
	{
		REPORT_ERRMSG_ON_TRACE("Get an unexpected/out-of-order ACK_CONNECT_REQ");
		return;
	}	// See also OnGetConnectRequest

	// Must prepare the receive window before allocate any receive buffer
	pControlBlock->SetRecvWindow(pktSeqNo);
	TRACE_SOCKET();
	// We change operation code of ACK_CONNECT_REQ to PERSIST because it starts a new transmit transaction
	response.hs.opCode = PERSIST;

	int r = PlacePayload();
	if (r == -EFAULT)
	{
		SignalNMI(FSP_MemoryCorruption);
		return;
	}
	if (r < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Get a wandering ACK_CONNECT_REQ");
		return;
	}
	pControlBlock->perfCounts.countPacketAccepted++;

	// Do not update RTT here, because there's undetermined delay due to backlog processing/calling back ULA
	// Suppose tLastRecv (so has tLastRecvAny) has been set (by PlacePayload)
	tSessionBegin = tMigrate = tLastRecv;
	tPreviousTimeSlot = tRecentSend;
	tPreviousLifeDetection = tSessionBegin;

	pControlBlock->peerAddr.ipFSP.fiberID = headPacket->fidPair.source;
	pControlBlock->sendWindowLimitSN
		= pControlBlock->sendWindowFirstSN + min(pControlBlock->sendBufferBlockN, response.GetRecvWS());

	TransitOnAckStart();
	if (lowState == COMMITTING)
		pControlBlock->SnapshotReceiveWindowRightEdge();

	// ephemeral session key material was ready OnInitConnectAck
	InstallEphemeralKey();
	Notify(FSP_NotifyConnected);	// The initiator may cancel data transmission, however
}



// NULCOMMIT is to commit a payload-less transmit transaction
//	{CHALLENGING, CLONING}-->/NULCOMMIT/
//			|-->{Not ULA-flushing}-->PEER_COMMIT
//			|-->{ULA-flushing}-->CLOSABLE]
//		-->[Send ACK_FLUSH]-->[Notify]
//	ESTABLISHED-->/NULCOMMIT/-->COMMITTED-->[Send ACK_FLUSH]-->[Notify]
//  COMMITTED-->/NULCOMMIT/-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	PEER_COMMIT-->/NULCOMMIT/-->{keep state}[Send ACK_FLUSH]
//	COMMITTING2-->/NULCOMMIT/-->{keep state}[Send ACK_FLUSH]
//	CLOSABLE-->/NULCOMMIT/-->{keep state}[Send ACK_FLUSH]
void CSocketItemEx::OnGetNulCommit()
{
	TRACE_SOCKET();

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	if (!isInitiativeState && lowState < ESTABLISHED)
		return;

	if (lenPktData != 0)
		return;

	FSP_NormalPacketHeader* p1 = &headPacket->hdr;
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
		// UNRESOLVED! Reflexing attack might be rendered? See also OnGetPureData:
		if (d < 0 || d >= pControlBlock->recvBufferBlockN)
		{
			EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
			return;
		}
		if (!ValidateICC())
		{
#if defined(TRACE) && (TRACE & TRACE_SLIDEWIN)
			printf_s("@%s: invalid ICC received\n", __FUNCTION__);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			return;
		}
	}
	else if (!FinalizeMultiply())	// if (lowState == CLONING)
	{
		return;
	}

	int countPlaced = PlacePayload();
	if (countPlaced == -EFAULT)
	{
		SignalNMI(FSP_MemoryCorruption);
		return;
	}
	if (countPlaced == -ENOENT)
	{
#if defined(_DEBUG) && defined(TRACE)
		printf_s("Place NULCOMMIT failed: error number = %d\n", countPlaced);
#endif
		return;
	}
	// Make acknowledgement, in case previous acknowledgement is lost
	if(countPlaced == -EEXIST)
	{
		EnableDelayAck();
		return;
	}

	pControlBlock->perfCounts.countPacketAccepted++;

	// Network RTT may not be refreshed here as there is undetermined delay caused by application processing

	// There might be unstable state transition, but it do little harm
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
	printf_s("\nTransit from %s ", stateNames[lowState]);
#endif
	if (isInitiativeState)
		TransitOnAckStart();
	AcceptSNACK(ackSeqNo, NULL, 0);
	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	if (!PeerCommitted())
		return;

	if (!TransitOnPeerCommit())
	{
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
		printf_s(" to %s\n", stateNames[lowState]);
#endif
		return;
	}
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
	printf_s(" to %s\n", stateNames[lowState]);
#endif
	// TransitOnPeerCommit has called SendAckFlush on success
	RestartKeepAlive();

	// In initiative state, as an acknowledgement to ACK_CONNECT_REQ or MULTIPLY actually,
	// the payload-less NULCOMMIT shall be skipped
	if (isInitiativeState)
	{
		pControlBlock->SlideRecvWindowByOne();
		Notify(isMultiplying ? FSP_NotifyMultiplied : FSP_NotifyAccepted);
	}
	else
	{
		NotifyDataReady(FSP_NotifyToCommit);
	}
}



//PERSIST is the acknowledgement to ACK_CONNECT_REQ or MULTIPLY, and/or start a new transmit transaction
//	{CHALLENGING, CLONING}-->/PERSIST/
//		|-->{EOT}
//			|-->{Not ULA-flushing}-->PEER_COMMIT
//			|-->{ULA-flushing}-->CLOSABLE
//		  >-->{stop keep-alive}[Send ACK_FLUSH]
//		|-->{otherwise}
//			|-->{Not ULA-flushing}-->ACTIVE
//			|-->{ULA-flushing}-->COMMITTED
//		  >-->[Send SNACK]
//	  >-->[Notify]
//	ESTABLISHED-->/PERSIST/
//		--{EOT}-->PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
//		--{otherwise}-->[Send SNACK]{keep state}
//	PEER_COMMIT-->/PERSIST/
//		--[EOT]-->[Send ACK_FLUSH]{keep state}
//			|-->{Not a new transaction}[End.]
//			|-->{A new transaction}-->[Notify]
//		--{otherwise}-->ACTIVE{restart keep-alive}
//	COMMITTING2-->/PERSIST/
//		--[EOT]-->[Send ACK_FLUSH]{keep state}
//			|-->{Not a new transaction}[End.]
//			|-->{A new transaction}-->[Notify]
//		--{otherwise}-->COMMITTING{restart keep-alive}
//	COMMITTED-->/PERSIST/
//		--{EOT}-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//		--{otherwise}-->[Send SNACK]-->{keep state}
//	CLOSABLE-->/PERSIST/
//		|--{EOT}-->{keep state}[Send ACK_FLUSH]
//			|-->{Not a new transaction}[End.]
//			|-->{A new transaction}-->[Notify]
//		|--{otherwise}-->COMMITTED{restart keep_alive}{KEEP_ALIVE}
void CSocketItemEx::OnGetPersist()
{
	TRACE_SOCKET();

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	if (!isInitiativeState && lowState < ESTABLISHED)
		return;

	FSP_NormalPacketHeader* p1 = &headPacket->hdr;
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
		// UNRESOLVED! Reflexing attack might be rendered? See also OnGetPureData:
		if (d < 0 || d >= pControlBlock->recvBufferBlockN)
		{
			EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
			return;
		}
		if (!ValidateICC())
		{
#if defined(TRACE) && (TRACE & TRACE_SLIDEWIN)
			printf_s("@%s: invalid ICC received\n", __FUNCTION__);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			return;
		}
	}
	else if (!FinalizeMultiply())	// if (lowState == CLONING)
	{
		return;
	}

	int countPlaced = PlacePayload();
	if (countPlaced == -EFAULT)
	{
		SignalNMI(FSP_MemoryCorruption);
		return;
	}
	if (countPlaced == -ENOENT)
	{
#if defined(_DEBUG) && defined(TRACE)
		printf_s("Place PERSIST failed: error number = %d\n", countPlaced);
#endif
		return;
	}
	// Make acknowledgement, in case previous acknowledgement is lost
	if (countPlaced == -ENOENT || countPlaced == -EEXIST)
	{
		EnableDelayAck();
		return;
	}

	pControlBlock->perfCounts.countPacketAccepted++;

	// There might be unstable state transition, but it do little harm
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
	printf_s("\nTransit from %s ", stateNames[lowState]);
#endif
	if (isInitiativeState)
		TransitOnAckStart();
	AcceptSNACK(ackSeqNo, NULL, 0);
	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	// The timer was already started for transient state management when Accept(), Multiply() or sending MULTIPLY
	// Network RTT may not be refreshed here as there is undetermined delay caused by application processing
	RestartKeepAlive();

	// Note that TransitOnPeerCommit may SendAckFlush which relies on correctness of tLastRecv
	if (PeerCommitted())
	{
		if (!TransitOnPeerCommit())
			return;
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
		printf_s(" to %s\n", stateNames[lowState]);
#endif
		// TransitOnPeerCommit has called SendAckFlush on success
		if (isInitiativeState)
			Notify(isMultiplying ? FSP_NotifyMultiplied : FSP_NotifyAccepted);
		else
			NotifyDataReady(FSP_NotifyToCommit);
		return;
	}

	if (lowState == PEER_COMMIT)
		SetState(ESTABLISHED);
	else if (lowState == COMMITTING2)
		SetState(COMMITTING);
	else if (lowState == CLOSABLE)
		SetState(COMMITTED);
#if ((TRACE & TRACE_PACKET) && (TRACE & TRACE_ULACALL))
	printf_s(" to %s\n", stateNames[lowState]);
#endif

	SendKeepAlive();
	if (isInitiativeState)
		Notify(isMultiplying ? FSP_NotifyMultiplied : FSP_NotifyAccepted);
	else
		NotifyDataReady();
}



// KEEP_ALIVE is out-of-band and may carry a special optional header for multi-homed mobility support
//	{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2}-->/KEEP_ALIVE/<-->{keep state}[Notify]
//	{COMMITTED, CLOSABLE}-->/KEEP_ALIVE/<-->{keep state}
//	{Update Peer's Authorized Addresses}
//	Assert: in SHUT_REQUESTED or PRE_CLOSED state it needn't care about KEEP_ALIVE
void CSocketItemEx::OnGetKeepAlive()
{
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	TRACE_SOCKET();
#endif
	bool acknowledgible = InStates(ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2);
	if (!acknowledgible && !InState(COMMITTED) && !InState(CLOSABLE))
	{
#ifdef TRACE
		printf_s("Got KEEP_ALIVE unexpectedly in state %s(%d)\n", stateNames[lowState], lowState);
#endif
		return;
	}

	FSP_KeepAlivePacket *pSNACK = (FSP_KeepAlivePacket *)&(headPacket->hdr);
	ControlBlock::seq_t ackSeqNo;
	int n = ValidateSNACK(ackSeqNo, &pSNACK->sentinel);
	if (n < 0)
	{
#ifndef NDEBUG
		printf_s("OnGetKeepAlive ValidateSNACK got (%d) returned\n", n);
#endif
		return;
	}
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Fiber#%u: SNACK packet with %d gap(s) advertised received\n", fidPair.source, n);
#endif
	tLastRecvAny = NowUTC();
	if (acknowledgible)
	{
		int r = AcceptSNACK(ackSeqNo, pSNACK->gaps, n);
		if (r > 0)
			NotifyBufferReady();
#ifndef NDEBUG
		else if (r < 0)
			printf_s("OnGetKeepAlive() AcceptSNACK unexpectedly return %d\n", r);
#endif		// UNRESOLVED?! Should log this very unexpected case
	}

	// For this FSP version the mobile parameter is mandatory in KEEP_ALIVE
	HandlePeerSubnets(&pSNACK->mp);
}



//ACTIVE-->/PURE_DATA/
//	|-->{EOT}
//		-->PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->[Send SNACK]-->[Notify]
//COMMITTING-->/PURE_DATA/
//	|-->{EOT}
//		-->COMMITTING2-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->[Send SNACK]-->[Notify]
//COMMITTED-->/PURE_DATA/
//	|-->{EOT}
//		-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->[Send SNACK]-->[Notify]
//{CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE}<-->/PURE_DATA/{just prebuffer}
// However ULA protocol designer must keep in mind that these prebuffered may be discarded
void CSocketItemEx::OnGetPureData()
{
#if (TRACE & TRACE_PACKET) || (TRACE & TRACE_SLIDEWIN)
	TRACE_SOCKET();
#endif
	int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
	if (d > pControlBlock->recvBufferBlockN)
	{
#if (TRACE & (TRACE_HEARTBEAT | TRACE_SLIDEWIN))
		printf_s("@%s: invalid sequence number: %u, distance to the receive window: %d\n"
			, __FUNCTION__, pktSeqNo, d);
#endif
		return;		// DoS attack OR a premature start of new transmit transaction
	}
	// Send SNACK if (d == pControlBlock->recvBufferBlockN) for sake of zero window probing
	// See also OnGetPersist
	if (d < 0 || d == pControlBlock->recvBufferBlockN)
	{
		EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
		return;
	}

	// Just ignore the unexpected PURE_DATA
	if (InStates(CHALLENGING, CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE))
	{
		if (d == 0)
			return;
		// else just prebuffer
	}
	else if (lowState < ESTABLISHED)
	{
#ifdef TRACE
		printf_s("In state %s data may not be accepted.\n", stateNames[lowState]);
#endif
		return;
	}

	FSP_NormalPacketHeader* p1 = &headPacket->hdr;
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	if (!ValidateICC())
	{
#if (TRACE & TRACE_SLIDEWIN)
		printf_s("@%s: invalid ICC received\n", __FUNCTION__);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return;
	}

	int r = PlacePayload();
	if (r == -EFAULT)
	{
		SignalNMI(FSP_MemoryCorruption);
		return;
	}
	if (r == -ENOENT || r == -EEXIST)
	{
		EnableDelayAck();
		return;
	}
	// If r == 0 the EoT flag MUST be set. But we put such check at DLL level
	if (r < 0)
	{
#ifndef NDEBUG
		printf_s("Fatal error when place payload, error number = %d\n", r);
#endif
		return;
	}
	pControlBlock->perfCounts.countPacketAccepted++;

	AcceptSNACK(ackSeqNo, NULL, 0);
	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	if (PeerCommitted())
	{
		if (TransitOnPeerCommit())
			NotifyDataReady(FSP_NotifyToCommit);
		return;
	}
	// PURE_DATA cannot start a transmit transaction, so in state like CLONING just prebuffer
	if (!InState(CLONING) && !InState(PEER_COMMIT) && lowState < COMMITTING2)
		EnableDelayAck();

	NotifyDataReady();
}



// Make state transition on getting NUL_COMMIT or PERSIST which is acknowledgement
// to responder's initiative of new transmit transaction
// Assume the send window has been slided on acknowledging
void CSocketItemEx::TransitOnAckStart()
{
	if (pControlBlock->GetSendQueueHead()->GetFlag<TransactionEnded>())
		SetState(COMMITTED);
	else if (pControlBlock->GetLastBuffered()->GetFlag<TransactionEnded>())
		SetState(COMMITTING);
	else
		SetState(ESTABLISHED);
}



// Make state transition on end-of-transmit-transaction got from the peer
// Side-effect: send ACK_FLUSH immediately
// Return
//	true if it needs to notify ULA for further processing
//	false if needs not to notify ULA
bool CSocketItemEx::TransitOnPeerCommit()
{
	pControlBlock->SnapshotReceiveWindowRightEdge();
	// See also OnGetRelease
	if (hasAcceptedRELEASE)
	{
		SetState(SHUT_REQUESTED);
		SendAckFlush();
		NotifyDataReady(FSP_NotifyToCommit);
		NotifyBufferReady(FSP_NotifyToFinish);
		return false;
	}
	//
	switch (lowState)
	{
	case COMMITTED:
		Adjourn();
		break;
	case ESTABLISHED:
		SetState(PEER_COMMIT);
		break;
	case COMMITTING:
		SetState(COMMITTING2);
		break;
	default:	// case PEER_COMMIT: case COMMITTING2: case CLOSABLE:	// keep state
		;
	}
	if (!delayAckPending)
		SendAckFlush();
	return true;
}



// ACK_FLUSH, now a pure out-of-band control packet. A special norm of KEEP_ALIVE
//	COMMITTING-->/ACK_FLUSH/-->COMMITTED-->[Notify]
//	COMMITTING2-->/ACK_FLUSH/-->CLOSABLE-->[Notify]
//	PRE_CLOSED-->/ACK_FLUSH/-->CLOSED-->[Notify]
void CSocketItemEx::OnAckFlush()
{
	TRACE_SOCKET();

	if (!InState(COMMITTING) && !InState(COMMITTING2) && !InState(PRE_CLOSED))
		return;

	ControlBlock::seq_t ackSeqNo;
	int n = ValidateSNACK(ackSeqNo, &((SAckFlushCache*)& headPacket->hdr)->snack);
	if (n < 0)
	{
#ifndef NDEBUG
		printf_s("OnAckFlush ValidateSNACK got (%d) returned\n", n);
#endif
		return;
	}
#ifndef NDEBUG
	if(n != 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("ACK_FLUSH should carry accumulatively positively acknowledge only");
		return;
	}
#endif
	AcceptSNACK(ackSeqNo, NULL, 0);
	tLastRecvAny = NowUTC();

	if (InState(PRE_CLOSED))
	{
		SetState(CLOSED);
		NotifyBufferReady(FSP_NotifyToFinish);
		return;
	}

	if (InState(COMMITTING2))
		Adjourn();
	else if(InState(COMMITTING))
		SetState(COMMITTED);

	NotifyBufferReady(FSP_NotifyFlushed);
}



// {COMMITTING, COMMITTED}-->/RELEASE/
//	 |--{Whole transaction not finished yet]-->{buffer it first}		
//	 |--{Whole transaction finished}
//		-->[Send ACK_FLUSH]-->SHUT_REQUESTED-->[Notify]
// {COMMITTING2, CLOSABLE}-->/RELEASE/
//	 -->[Send ACK_FLUSH]-->SHUT_REQUESTED-->[Notify]
// SHUT_REQUESTED-->/RELEASE/
//	 -->[Send ACK_FLUSH]{lazily, to defend against replay DoS attack}
// PRE_CLOSED-->/RELEASE/-->CLOSED-->[Notify]
// Remark
//	Send ACK_FLUSH: instead of SendAckFlush() instantly, call EnableDelayAck to defend against DoS attack
//	RELEASE implies NULCOMMIT
//	RELEASE implies ACK_FLUSH as well so a lost ACK_FLUSH does not prevent it shutdown gracefully
//	Work in tandem with ULA's polling arrival of data before availability of new send buffer
void CSocketItemEx::OnGetRelease()
{
	TRACE_SOCKET();

	if (InState(SHUT_REQUESTED) || InState(CLOSED))
	{
		EnableDelayAck();
		return;
	}

	if (!InStates(COMMITTING, COMMITTED, COMMITTING2, CLOSABLE, PRE_CLOSED))
		return;

	if (lenPktData != 0)
		return;

	if (pktSeqNo != pControlBlock->recvWindowNextSN)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nThe RELEASE packet to %u is valid only if it is the last expected\n"
			"\tSequence number of this packet = %u, right edge of receive window is %u\n"
			, fidPair.source
			, pktSeqNo, pControlBlock->recvWindowNextSN);
#endif
		return;
	}

	if (!ValidateICC())
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Invalid integrity check code!?");
		return;
	}

#ifndef NDEBUG
	printf_s("Fiber#%u, reactive shutdown pended in state %s[%d]\n"
		, this->fidPair.source, stateNames[lowState], lowState);
#endif

	// Place a payload-less EoT packet into the receive queue,
	// and the duplicate RELEASE packet would be rejected
	// hidden dependency: tLastRecv which is exploited in SendAckFlush is set in PlacePayload
	int r = PlacePayload();
	if (r == -EFAULT)
	{
		SignalNMI(FSP_MemoryCorruption);
		return;
	}
	if (r < 0)
	{
#ifndef NDEBUG
		printf_s("Placing payload-less shutdown packet in the receive buffer returned %d\n", r);
#endif
		return;
	}

	pControlBlock->perfCounts.countPacketAccepted++;
	AcceptSNACK(pControlBlock->sendWindowNextSN, NULL, 0);

	hasAcceptedRELEASE = 1;
	if (InState(COMMITTING))
		SetState(COMMITTED);
	if (InState(COMMITTED) && !PeerCommitted())
		return;

	SetState(InState(PRE_CLOSED) ? CLOSED : SHUT_REQUESTED);
	SendAckFlush();
	NotifyDataReady(FSP_NotifyToCommit);
	NotifyBufferReady(FSP_NotifyToFinish);
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|<-->/MULTIPLY/{duplication detected: retransmit acknowledgement}
//	|<-->/MULTIPLY/{collision detected}[Send RESET]
//	|-->/MULTIPLY/-->[API{Callback}]
// Remark
//	It is assumed that ULA/DLL implements connection multiplication throttle control
//	See also OnGetConnectRequest, OnGetKeepAlive
//	DoS attack against long-term sessions by replaying MULTIPLY is possible but mitigated
void CSocketItemEx::OnGetMultiply()
{
	TRACE_SOCKET();

	if (!InStates(ESTABLISHED, COMMITTING, COMMITTED, PEER_COMMIT, COMMITTING2, CLOSABLE))
		return;

	// The packet number MUST fall in some safe window to defend against DoS attack
	int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
	if (d > pControlBlock->recvBufferBlockN || d < -pControlBlock->recvBufferBlockN)
		return;

	// The out-of-band serial number is stored in p1->expectedSN
	// However, MULTIPLY is not necessary orderly
	FSP_FixedHeader* pFH = &headPacket->hdr;
	uint32_t sn = be32toh(pFH->expectedSN);
	if (int32_t(sn - lastOOBSN) > 0)
		lastOOBSN = sn;

	uint32_t remoteHostID = pControlBlock->connectParams.remoteHostID;
	ALFID_T idSource = headPacket->fidPair.source;
	ALFID_T idParent = this->fidPair.source;
	CMultiplyBacklogItem *newItem  = CLowerInterface::Singleton.FindByRemoteId(remoteHostID, idSource, idParent);
	if (newItem != NULL)
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Duplicate MULTIPLY received?\n"
			"\tContext for session pair (%u, %u) established already.\n", idParent, idSource);
#endif
		return;
	}

	// Make the 'salt' not so easy to guess to defend against DoS attack
	SItemBackLog backlogItem;
	memcpy(&backlogItem, &pControlBlock->connectParams, sizeof(SConnectParam));
	backlogItem.idParent = idParent;
	backlogItem.idRemote = idSource;
	backlogItem.salt = (sn ^ backlogItem.timeDelta);
	if (pControlBlock->backLog.Has(backlogItem))
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Duplicate MULTIPLY received, backlogged already.\n");
#endif
		return;
	}

	if (!ValidateICC(pFH, lenPktData, idSource, GetSalt(*pFH)))
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Invalid integrity check code of MULTIPLY\n");
#endif
		return;
	}

	newItem = (CMultiplyBacklogItem *)CLowerInterface::Singleton.AllocItem(rootULA);
	if (newItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot for multiplication");
		return;		// for security reason silently ignore the exception
	}
	SOCKADDR_HOSTID(newItem->sockAddrTo) = remoteHostID;
	// While the ALFID part which was assigned dynamically by AllocItem() is preserved
	newItem->fidPair.peer = idSource;
	newItem->idParent = idParent;
	CLowerInterface::Singleton.PutToRemoteTLB(newItem);

	newItem->tLastRecv = newItem->tLastRecvAny = tLastRecvAny = NowUTC();
	newItem->snLastRecv = pktSeqNo;

	// See also InitiateMultiply, setting of nextOOBSN
	newItem->lastOOBSN = sn;
	newItem->nextOOBSN = 0;
	// place payload into the backlog, see also PlacePayload
	newItem->CopyInPlainText((octet *)pFH + be16toh(pFH->hs.offset), lenPktData);

	ControlBlock::PFSP_SocketBuf skb = & newItem->skbRecvClone;
	skb->version = pFH->hs.major;
	skb->opCode = pFH->hs.opCode;
	skb->CopyInFlags(pFH);
	// Needn't set len or marks, see also ResponseToMultiply

	// The first packet received is in the parent's session key while
	// the first responding packet shall be sent in the derived key
	newItem->contextOfICC.snFirstRecvWithCurrKey = pktSeqNo + 1;
	rand_w32(&newItem->contextOfICC.snFirstSendWithCurrKey, 1);
	// Inherit the parent's session key:
	newItem->contextOfICC.InheritR1(contextOfICC);
	//^See also FinalizeMultiply()
	// Assume DoS attacks or replay attacks have been filtered out
	// note that the responder's key material mirrors the initiator's
	if (newItem->contextOfICC.keyLifeRemain != 0)
		newItem->DeriveKey(idSource, idParent);

	newItem->SetFirstRTT(tRoundTrip_us);

	newItem->lowState = NON_EXISTENT;
	newItem->ReplaceTimer(TRANSIENT_STATE_TIMEOUT_ms);
	// Alike in CHALLENGING, when timeout the socket is scavenged automatically.

	backlogItem.expectedSN = pktSeqNo;
	backlogItem.initialSN = newItem->contextOfICC.snFirstSendWithCurrKey;
	backlogItem.acceptAddr = pControlBlock->nearEndInfo;
	backlogItem.acceptAddr.idALF = newItem->fidPair.source;
	memcpy(backlogItem.allowedPrefixes, pControlBlock->peerAddr.ipFSP.allowedPrefixes, sizeof(uint64_t) * MAX_PHY_INTERFACES);
	//^See also CSocketItemDl::PrepareToAccept()
	// Lastly, put it into the backlog. Put it too early may cause race condition
	if (pControlBlock->backLog.Put(backlogItem) < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot put the multiplying connection request into the SCB backlog");
		CLowerInterface::Singleton.FreeItem(newItem);
		// do not 'return;' but instead urge the DLL to process the back log if the backlog was full
	}
	else
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("\nTo acknowledge MULTIPLY/send a PERSIST in LLS, ICC context:\n"
			"\tSN of MULTIPLY received = %09u\n"
			"\tALFID of peer's branch = %u, ALFID of near end's parent = %u\n"
			, backlogItem.expectedSN
			, idSource, idParent);
#endif
		pControlBlock->perfCounts.countPacketAccepted++;
	}

	Notify(FSP_NotifyAccepting);	// Not necessarily the first one in the queue
}



// Return
//	>= 0	number of bytes placed on success
//	-ENOENT if no entry available in the receive window
//	-EEXIST on packet already received
//	-EFAULT	on memory fault
int CSocketItemEx::PlacePayload()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(pktSeqNo);
	if(skb == NULL)
		return -ENOENT;

	if (!CheckMemoryBorder(skb))
		return -EFAULT;

	if (skb->IsComplete())
		return -EEXIST;

	FSP_NormalPacketHeader* pHdr = &headPacket->hdr;
	int len = lenPktData;
	if (len > 0)
	{
		octet*ubuf = GetRecvPtr(skb);
		if (ubuf == NULL)
			return -EFAULT;
		// Assume payload length has been checked
		memcpy(ubuf, (octet*)pHdr + be16toh(pHdr->hs.offset), len);
	}
	// Or else might be zero for ACK_START or MULTIPLY packet
	skb->timeRecv = tLastRecv = tLastRecvAny = NowUTC();
	snLastRecv = pktSeqNo;

	skb->version = pHdr->hs.major;
	skb->opCode = pHdr->hs.opCode;
	skb->CopyInFlags(pHdr);
	skb->len = len;
	skb->ReInitMarkComplete();

	return len;
}
