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
		OnInitConnectAck();
		break;
	case CONNECT_REQUEST:
		OnGetConnectRequest();
		break;
	case RESET:
		pSocket = MapSocket();
		if (pSocket == NULL || !pSocket->IsInUse())
			break;
		pSocket->OnGetReset(*FSP_OperationHeader<FSP_RejectConnect>());
		break;
	//
	case ACK_CONNECT_REQ:
	case ACK_START:
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
			printf_s("Cannot map socket for local fiber#%u(_%X_)\n", GetLocalFiberID(), be32toh(GetLocalFiberID()));
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
void LOCALAPI CLowerInterface::OnGetInitConnect()
{
	// Silently discard connection request to black hole, and avoid attacks alike 'port scan'
	CSocketItemEx *pSocket = MapSocket();
	FSP_InitiateRequest* q;
	FSP_Challenge challenge;
	struct _CookieMaterial cm;
	timestamp_t t0, t1;

	if (pSocket == NULL || !pSocket->IsPassive())
		return;

	if (!pSocket->LockWithActiveULA())
		return;

	// control structure, specified the local address (the Application Layer Thread ID part)
	// echo back the message at the same interface of receiving, only ALFID changed

	CtrlMsgHdr	hdrInfo;
	ALFID_T	fiberID;
	memset(&hdrInfo, 0, sizeof(CtrlMsgHdr));
	CopySinkInfTo(hdrInfo);
	if (hdrInfo.IsIPv6())
	{
		fiberID = CLowerInterface::Singleton.RandALFID((PIN6_ADDR) & hdrInfo.u);
	}
	else
	{
		fiberID = CLowerInterface::Singleton.RandALFID();
		hdrInfo.u.idALF = fiberID;
	}

	if(fiberID == 0)
	{
		SendPrematureReset(ENOENT);
		goto l_return;
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
void LOCALAPI CLowerInterface::OnInitConnectAck()
{
	//	find the socket item firstly
	FSP_Challenge *pkt = FSP_OperationHeader<FSP_Challenge>();
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL)
		return;

	if(! pSocket->LockWithActiveULA())
		return;

	SConnectParam & initState = pSocket->pControlBlock->connectParams;
	ALFID_T idListener = initState.idRemote;

	if(! pSocket->InState(CONNECT_BOOTSTRAP))
		goto l_return;

	if(initState.initCheckCode != pkt->initCheckCode || idListener != pkt->params.idListener)
		goto l_return;
	// Remote sink info validated, to regiser validated remote address:
	// the officially announced IP address of the responder shall be accepted by the initiator
	memset(initState.allowedPrefixes, 0, sizeof(initState.allowedPrefixes));
	memcpy(initState.allowedPrefixes, pkt->params.subnets, sizeof(pkt->params.subnets));

	pSocket->SetRemoteFiberID(initState.idRemote = this->GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multi-home it is necessary even for IPv6
	pSocket->SetNearEndInfo(nearInfo);

	initState.timeDelta = pkt->timeDelta;
	initState.cookie = pkt->cookie;
	EnumEffectiveAddresses(initState.allowedPrefixes);

	pSocket->AffirmConnect(initState, idListener);

l_return:
	pSocket->SetMutexFree();
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
void LOCALAPI CLowerInterface::OnGetConnectRequest()
{
	FSP_ConnectRequest *q = FSP_OperationHeader<FSP_ConnectRequest>();
	CSocketItemEx *pSocket = MapSocket();
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

	if (!pSocket->LockWithActiveULA())
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
	BackLogItem backlogItem(GetRemoteFiberID(), q->_init.salt);
	if(pSocket->pControlBlock->backLog.Has(& backlogItem))
		goto l_return;

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
	if (pSocket->pControlBlock->backLog.Put(&backlogItem) < 0)
	{
#ifdef TRACE
		printf_s("Cannot put the connection request into the backlog of the listening session's control block.\n");
#endif
		goto l_return;
	}
	pSocket->SignalFirstEvent(FSP_NotifyAccepting);

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
#ifdef TRACE
	printf_s("\nRESET got, in state %s\n\n", stateNames[lowState]);
#endif
	// No, we cannot reset a socket without validation
	if (!LockWithActiveULA())
		return;
	if (pControlBlock == NULL)
		goto l_bailout;

	if (InState(CONNECT_BOOTSTRAP))
	{
		if (reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
			&& reject.initCheckCode == pControlBlock->connectParams.initCheckCode)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if (InState(CONNECT_AFFIRMING))
	{
		if (reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
			&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if (InState(CHALLENGING))
	{
		if (reject.sn.initial == htobe32(pControlBlock->connectParams.initialSN)
			&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if (!InState(LISTENING) && !InState(CLOSED))
	{
		int32_t offset = OffsetToRecvWinLeftEdge(be32toh(reject.sn.initial));
		if (-1 <= offset && offset < pControlBlock->recvBufferBlockN
			&& ValidateICC((FSP_NormalPacketHeader*)& reject, 0, fidPair.peer, 0))
		{
			DisposeOnReset();
		}
		// otherwise simply ignore.
	}
	// ^SHUT_REQUESTED (passive shutdown) or 
	// InStates ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED, CLONING
	// besides, those states are recoverable.
	// LISTENING state is not affected by reset signal
l_bailout:
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
	// In the CLONING state ACK_START or PERSIST is the legitimate acknowledgement to MULTIPLY,
	// while the acknowledgement itself shall typically originate from some new ALFID.
	if (fidPair.peer != pktBuf->fidPair.source	// it should be rare
	 && opCode != MULTIPLY && (lowState != CLONING || (opCode != ACK_START && opCode != PERSIST)) )
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
	case ACK_START:
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
	// defined a little earlier for debug/trace purpose
#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s data length: %d, header length: %d, peer ALFID = %u\n"
		, opCodeStrings[p1->hs.opCode]
		, lenPktData
		, n
		, fidPair.peer);
	DumpNetworkUInt16((uint16_t*)((FSP_PreparedKEEP_ALIVE*)pSNACK)->gaps, n / 2);
#endif
	// To defend against memory access (out-of-boundary) attack:
	if ((octet*)pSNACK - (octet*)p1 + n != len)
	{
		return -EACCES;
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
	//

	ackSeqNo = le32toh(pSNACK->ackSeqNo);
	if (!IsAckExpected(ackSeqNo))
		return -ENOENT;

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	// Calibrate RTT ONLY if left edge of the send window is to be advanced
	if(ackSeqNo - pControlBlock->sendWindowFirstSN > 0)
		UpdateRTT(le32toh(pSNACK->latestSN), le32toh(pSNACK->tLazyAck));

	lastOOBSN = sn;
#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s sequence number: %u^|^%u\n"
		"\taccumulatively acknowledged %u with %d gap(s)\n"
		, opCodeStrings[p1->hs.opCode], pktSeqNo, sn
		, ackSeqNo, n);
#endif
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
	{
		BREAK_ON_DEBUG();
		return;
	}

	FSP_NormalPacketHeader& response = *(FSP_NormalPacketHeader*)& headPacket->hdr;
	if(be32toh(response.expectedSN) != pControlBlock->sendWindowFirstSN)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Get an unexpected/out-of-order ACK_CONNECT_REQ");
		return;
	}	// See also OnGetConnectRequest

	// Must prepare the receive window before allocate any receive buffer
	pControlBlock->SetRecvWindow(pktSeqNo);
	TRACE_SOCKET();
	// We change operation code of ACK_CONNECT_REQ to PERSIST because it starts a new transmit transaction
	response.hs.opCode = PERSIST;
	if (PlacePayload() < 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Get an unexpected/out-of-order ACK_CONNECT_REQ");
		return;
	}
	pControlBlock->perfCounts.countPacketAccepted++;

	// Do not update RTT here, because there's undetermined delay due to backlog processing/calling back ULA
	tSessionBegin = tMigrate = tLastRecv;
	tPreviousTimeSlot = tRecentSend;
	tPreviousLifeDetection = tSessionBegin;

	pControlBlock->peerAddr.ipFSP.fiberID = headPacket->fidPair.source;
	pControlBlock->sendWindowLimitSN
		= pControlBlock->sendWindowFirstSN + min(pControlBlock->sendBufferBlockN, response.GetRecvWS());

	// Here the state transition is delayed for DLL to do further management
	// ephemeral session key material was ready OnInitConnectAck
	InstallEphemeralKey();
	SignalFirstEvent(FSP_NotifyAccepted);	// The initiator may cancel data transmission, however
}



// ACK_START reuse NULCOMMIT effectively as the in-band acknowledgement to ACK_CONNECT_REQ or MULTIPLY
// when there is no immediate data to send back start,
// and it is to both start and commit the payloadless transmit transaction which SHALL be skipped
// NULCOMMIT is to commit a payloadless transmit transaction
//	CHALLENGING-->/ACK_START/-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//  CLONING-->/ACK_START/
//			|-->{Not ULA-flushing}-->PEER_COMMIT
//			|-->{ULA-flushing}-->CLOSABLE]
//		-->[Send ACK_FLUSH]-->[Notify]
//	ESTABLISHED-->/NULCOMMIT/-->COMMITTED-->[Send ACK_FLUSH]-->[Notify]
//  COMMITTED-->/NULCOMMIT/-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	PEER_COMMIT-->/ACK_START/NULCOMMIT-->{keep state}[Send ACK_FLUSH]
//	COMMITTING2-->/ACK_START/NULCOMMIT-->{keep state}[Send ACK_FLUSH]
//	CLOSABLE-->/ACK_START/NULCOMMIT-->{keep state}[Send ACK_FLUSH]
void CSocketItemEx::OnGetNulCommit()
{
	TRACE_SOCKET();

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	if (! isInitiativeState && lowState < ESTABLISHED)
		return;

	FSP_NormalPacketHeader* p1 = &headPacket->hdr;
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		// It costs much less to make lazy acknowledgement than to ValidateICC() or Notify()
		// PEER_COMMIT, COMMITTING2, CLOSABLE: retransmit ACK_FLUSH on get NULCOMMIT
		if (OffsetToRecvWinLeftEdge(pktSeqNo) < 0 || !isInitiativeState)
		{
			EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
			return;
		}
		if (isInitiativeState && pktSeqNo != pControlBlock->recvWindowExpectedSN)
		{
#if (TRACE & TRACE_SLIDEWIN)
			printf_s("ACK_START should have the very sequence number awaited to receive.\n");
#endif
			BREAK_ON_DEBUG();
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
	pControlBlock->perfCounts.countPacketAccepted++;

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	// ACK_START/NULCOMMIT has nothing to deliver to ULA, however it consumes a slot of receive queue
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(pktSeqNo);
	if (skb == NULL)
		return;
	if (isInitiativeState)
	{
		skb->ReInitMarkDelivered();
		pControlBlock->SlideRecvWindowByOne();
	}
	// Indirect dependency: tLastRecv which is exploited in SendAckFlush in TransitOnPeerCommit is set here
	skb->timeRecv = tLastRecv = NowUTC();
	snLastRecv = pktSeqNo;
	// Network RTT may not be refreshed here as there is undetermined delay caused by application processing
#if (TRACE & (TRACE_SLIDEWIN | TRACE_HEARTBEAT))
	printf_s("\nACK_START received, acknowledged SN = %u\n\tThe responder calculate RTT: %uus\n", ackSeqNo, tRoundTrip_us);
#endif

	if (!isInitiativeState)
	{
		if (HasBeenCommitted() && TransitOnPeerCommit())
			Notify(FSP_NotifyToCommit);
		return;
	}

	// ACK_START is always the accumulative acknowledgement to ACK_CONNECT_REQ or MULTIPLY
	skb = pControlBlock->GetSendQueueHead();
	skb->ReInitMarkAcked();
	pControlBlock->SlideSendWindowByOne();	// See also AcceptSNACK

	if (isMultiplying)
	{
		SetState(_InterlockedExchange8(&transactional, 0) ? CLOSABLE : PEER_COMMIT);
		SignalFirstEvent(FSP_NotifyMultiplied);
	}
	else // if (lowState == CHALLENGING)
	{
		SetState(CLOSABLE);
		SignalFirstEvent(FSP_NotifyAccepted);
	}
	SendAckFlush();
	RestartKeepAlive();
}



//PERSIST is the acknowledgement to ACK_CONNECT_REQ or MULTIPLY, and/or start a new transmit transaction
//	CHALLENGING-->/PERSIST/
//		--{EOT}-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//		--{otherwise}-->COMMITTED-->[Notify]
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
//  CLONING-->/PERSIST/
//		|-->{EOT}
//			|-->{Not ULA-flushing}-->PEER_COMMIT
//			|-->{ULA-flushing}-->CLOSABLE
//		  >-->{stop keep-alive}[Send ACK_FLUSH]
//		|-->{otherwise}
//			|-->{Not ULA-flushing}-->ACTIVE
//			|-->{ULA-flushing}-->COMMITTED
//		  >-->[Send SNACK]
//	  >-->[Notify]
void CSocketItemEx::OnGetPersist()
{
	TRACE_SOCKET();

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	if (!isInitiativeState && lowState < ESTABLISHED)
		return;

#ifdef TRACE
	printf_s("Payload length: %d\n", lenPktData);
#endif
	if (lenPktData < 0 || lenPktData > MAX_BLOCK_SIZE)
		return;

	FSP_NormalPacketHeader* p1 = &headPacket->hdr;
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		int32_t d = OffsetToRecvWinLeftEdge(pktSeqNo);
		if (d > pControlBlock->recvBufferBlockN)
		{
#if (TRACE & (TRACE_HEARTBEAT | TRACE_SLIDEWIN))
			printf_s("@%s: invalid sequence number: %u, distance to the receive window: %d\n"
				, __FUNCTION__, pktSeqNo, d);
#endif
			return;		// DoS attack OR a premature start of new transmit transaction
		}
		// See also OnGetPureData:
		if (d < 0 || d == pControlBlock->recvBufferBlockN)
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
	pControlBlock->perfCounts.countPacketAccepted++;

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	int countPlaced = PlacePayload();
	if (countPlaced == -EFAULT)
	{
		Notify(FSP_MemoryCorruption);
		return;
	}
	// Make acknowledgement, in case previous acknowledgement is lost
	if (countPlaced == -ENOENT || countPlaced == -EEXIST)
	{
		EnableDelayAck();
		return;
	}

#if defined(_DEBUG) && defined(TRACE)
	if (countPlaced < 0)
	{
		printf_s("Place PERSIST failed: error number = %d\n", countPlaced);
		return;
	}
#else
	if (countPlaced < 0)
		return;
#endif

	// PERSIST is always the accumulative acknowledgement to ACK_CONNECT_REQ or MULTIPLY
	// ULA slide the receive window, no matter whether the packet has payload
	// The timer was already started for transient state management when Accept(), Multiply() or sending MULTIPLY
	// Network RTT may not be refreshed here as there is undetermined delay caused by application processing
	if (isInitiativeState)
	{
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
		skb->ReInitMarkAcked();
		pControlBlock->SlideSendWindowByOne();	// See also AcceptSNACK
	}

	// Note that TransitOnPeerCommit may SendAckFlush which relies on correctness of tLastRecv
	if (HasBeenCommitted())
	{
		if (!TransitOnPeerCommit())
			return;
		// TransitOnPeerCommit has called SendAckFlush on success
		RestartKeepAlive();
		//
		if (isMultiplying)
			SignalFirstEvent(FSP_NotifyMultiplied);
		else if (isInitiativeState)
			SignalFirstEvent(FSP_NotifyAccepted);
		else	// countPlaced >= 0
			Notify(FSP_NotifyToCommit);
		return;
	}

	switch (lowState)
	{
	case CHALLENGING:
		SetState(COMMITTED);
		break;
	case PEER_COMMIT:
		SetState(ESTABLISHED);
		break;
	case COMMITTING2:
		SetState(COMMITTING);
		break;
	case CLOSABLE:
		SetState(COMMITTED);
		break;
	case CLONING:
		SetState(_InterlockedExchange8(&transactional, 0) ? COMMITTED : ESTABLISHED);
#if (TRACE & TRACE_OUTBAND)
		printf_s("\nTransit to %s state from CLONING\n", stateNames[lowState]);
#endif
		break;
	default:	// case ESTABLISHED: case COMMITTED:	// keep state
		;
	}
	//
	SendKeepAlive();
	RestartKeepAlive();

	if (isMultiplying)
		SignalFirstEvent(FSP_NotifyMultiplied);
	else if (isInitiativeState)
		SignalFirstEvent(FSP_NotifyAccepted);
	else if (countPlaced > 0)
		Notify(FSP_NotifyDataReady);
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

	FSP_PreparedKEEP_ALIVE* pSNACK = &((FSP_KeepAliveExtension*) & (headPacket->hdr))->snack;
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
	// By default ULA should poll the send buffer, instead to rely on soft-interrupt
	if (acknowledgible)
	{
		int r = AcceptSNACK(ackSeqNo, pSNACK->gaps, n);
		if (r > 0 && pControlBlock->CountSendBuffered() == 0)
			Notify(FSP_NotifyBufferReady);
#ifndef NDEBUG
		else if (r < 0)
			printf_s("OnGetKeepAlive() AcceptSNACK unexpectedly return %d\n", r);
#endif		// UNRESOLVED?! Should log this very unexpected case
	}

	// For this FSP version the mobile paramater is mandatory in KEEP_ALIVE
	HandlePeerSubnets(&((FSP_KeepAliveExtension*) & (headPacket->hdr))->mp);
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
	if (InStates(CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE))
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

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());
	AcceptSNACK(ackSeqNo, NULL, 0);

	int r = PlacePayload();
	if (r == -EFAULT)
	{
		Notify(FSP_MemoryCorruption);
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

	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	if (HasBeenCommitted())
	{
		if(TransitOnPeerCommit())
			Notify(FSP_NotifyToCommit);
		return;
	}
	// PURE_DATA cannot start a transmit transaction, so in state like CLONING just prebuffer
	if (!InState(CLONING) && !InState(PEER_COMMIT) && lowState < COMMITTING2)
		EnableDelayAck();

	Notify(FSP_NotifyDataReady);
}



// Make state transition on end-of-transmit-transaction got from the peer
// Side-effect: send ACK_FLUSH immediately
// Return
//	true if state is successfully migrated
//	false if ULA state has yet to be changed by NotifyToFinish
bool CSocketItemEx::TransitOnPeerCommit()
{
	pControlBlock->SnapshotReceiveWindowRightEdge();
	if (hasAcceptedRELEASE)
	{
		ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);
		Notify(FSP_NotifyToFinish);
		lowState = CLOSED;
		SendAckFlush();
		return false;
	}
	//
	switch (lowState)
	{
	case CHALLENGING:
		SetState(CLOSABLE);
		break;
	case ESTABLISHED:
		SetState(PEER_COMMIT);
		break;
	case COMMITTING:
		SetState(COMMITTING2);
		break;
	case COMMITTED:
		SetState(CLOSABLE);
		break;
	case CLONING:
		SetState(_InterlockedExchange8(&transactional, 0) ? CLOSABLE : PEER_COMMIT);
		break;
	default:	// case PEER_COMMIT: case COMMITTING2: case CLOSABLE:	// keep state
		;
	}
	//
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

	if (InState(PRE_CLOSED))
	{
		ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);
		SetState(CLOSED);
		Notify(FSP_NotifyToFinish);
		return;
	}

	if (InState(COMMITTING2))
		SetState(CLOSABLE);
	else if(InState(COMMITTING))
		SetState(COMMITTED);

	Notify(FSP_NotifyFlushed);
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
//	There's a race condition that
//	while NotifiedToFinsh immediately follows a NotifyToCommit, RELEASE may arrive before ACK_FLUSH
//	And accept RELEASE in PRE_CLOSED state because ACK_FLUSH may race with RELEASE in some scenario
void CSocketItemEx::OnGetRelease()
{
	if (InState(SHUT_REQUESTED))
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
	if (r == 0)
	{
		pControlBlock->perfCounts.countPacketAccepted++;
		AcceptSNACK(pControlBlock->sendWindowNextSN, NULL, 0);
	}

	hasAcceptedRELEASE = 1;
	if (InState(COMMITTING))
		SetState(COMMITTED);
	if (InState(COMMITTED) && !HasBeenCommitted())
		return;

	if (InState(PRE_CLOSED))
	{
		SetState(CLOSED);
	}
	else
	{
		SendAckFlush();
		SetState(SHUT_REQUESTED);
	}
	Notify(FSP_NotifyToFinish);
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

	// The out-of-band serial number is stored in p1->expectedSN
	// Check whether it is a collision OR a replay-attack
	FSP_FixedHeader* pFH = &headPacket->hdr;
	uint32_t sn = be32toh(pFH->expectedSN);
	if (int32_t(sn - lastOOBSN) <= 0)
	{
#ifdef TRACE
		printf_s("MULTIPLY has encountered replay attack? Sequence number:\n\tinband %u, oob %u - %u\n"
			, pktSeqNo, sn, lastOOBSN);
#endif
		return;
	}
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

	if (!ValidateICC(pFH, lenPktData, idSource, GetSalt(*pFH)))
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Invalid integrity check code of MULTIPLY\n");
#endif
		return;
	}

	newItem = (CMultiplyBacklogItem *)CLowerInterface::Singleton.AllocItem();
	if (newItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot for multiplication");
		return;		// for security reason silently ignore the exception
	}
	newItem->tLastRecv = NowUTC();
	newItem->snLastRecv = pktSeqNo;

	BackLogItem backlogItem(pControlBlock->connectParams);
	backlogItem.idRemote = idSource;
	if (pControlBlock->backLog.Has(&backlogItem))
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Duplicate MULTIPLY received, backlogged already.\n");
#endif
		CLowerInterface::Singleton.FreeItem(newItem);
		return;
	}
	pControlBlock->perfCounts.countPacketAccepted++;

	backlogItem.expectedSN = pktSeqNo;
	rand_w32(&backlogItem.initialSN, 1);
	// Inherit the parent's session key:
	backlogItem.idParent = idParent;
	backlogItem.acceptAddr = pControlBlock->nearEndInfo;
	backlogItem.acceptAddr.idALF = newItem->fidPair.source;
	memcpy(backlogItem.allowedPrefixes, pControlBlock->peerAddr.ipFSP.allowedPrefixes, sizeof(uint64_t)* MAX_PHY_INTERFACES);
	//^See also CSocketItemDl::PrepareToAccept()

	SOCKADDR_HOSTID(newItem->sockAddrTo) = remoteHostID;
	// While the ALFID part which was assigned dynamically by AllocItem() is preserved
	newItem->fidPair.peer = idSource;
	newItem->idParent = idParent;
	newItem->nextOOBSN = this->nextOOBSN;
	newItem->lastOOBSN = this->lastOOBSN;
	// place payload into the backlog, see also PlacePayload
	newItem->CopyInPlainText((octet *)pFH + be16toh(pFH->hs.offset), lenPktData);

	ControlBlock::PFSP_SocketBuf skb = & newItem->skbRecvClone;
	skb->version = pFH->hs.major;
	skb->opCode = pFH->hs.opCode;
	skb->CopyInFlags(pFH);
	// Needn't set len or marks, see also ResponseToMultiply

	// The first packet received is in the parent's session key while
	// the first responding packet shall be sent in the derived key
	newItem->contextOfICC.snFirstRecvWithCurrKey = backlogItem.expectedSN + 1;
	newItem->contextOfICC.InheritR1(contextOfICC, backlogItem.initialSN);
	//^See also FinalizeMultiply()
	// Assume DoS attacks or replay attacks have been filtered out
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("\nTo acknowledge MULTIPLY/send a PERSIST in LLS, ICC context:\n"
		"\tSN of MULTIPLY received = %09u\n"
		"\tALFID of peer's branch = %u, ALFID of near end's parent = %u\n"
		, backlogItem.expectedSN
		, idSource, idParent);
#endif
	// note that the responder's key material mirrors the initiator's
	if (newItem->contextOfICC.keyLifeRemain != 0)
		newItem->DeriveKey(idSource, idParent);

	newItem->SetFirstRTT(tRoundTrip_us);
	newItem->lowState = NON_EXISTENT;		// so that when timeout it is scavenged
	newItem->ReplaceTimer(TRANSIENT_STATE_TIMEOUT_ms);

	// Lastly, put it into the backlog. Put it too early may cause race condition
	if (pControlBlock->backLog.Put(&backlogItem) < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot put the multiplying connection request into the SCB backlog");
		CLowerInterface::Singleton.FreeItem(newItem);
	}
	// do not 'return;' but instead urge the DLL to process the back log if the backlog was full

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
	skb->timeRecv = tLastRecv = NowUTC();
	snLastRecv = pktSeqNo;

	skb->version = pHdr->hs.major;
	skb->opCode = pHdr->hs.opCode;
	skb->CopyInFlags(pHdr);
	skb->len = len;
	skb->ReInitMarkComplete();

	return len;
}
