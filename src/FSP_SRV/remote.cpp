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
	(printf_s(__FUNCTION__ ": local fiber#%u(_%X_) in state %s\n"	\
		, fidPair.source, be32toh(fidPair.source)		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpSendRecvWindowInfo())
#elif (TRACE & (TRACE_ULACALL | TRACE_SLIDEWIN))
#define TRACE_SOCKET()	\
	(printf_s(__FUNCTION__ ": local fiber#%u(_%X_) in state %s\n"	\
		, fidPair.source, be32toh(fidPair.source)		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpRecvQueueInfo())
#else
#define TRACE_SOCKET()
#endif



// Variadic template is not necessarily more efficient that parameter list of variable length in C
// VS2013 and above support variadic template
inline
bool CSocketItemEx::InStates(int n, ...)
{
#ifdef _DEBUG
	if(pControlBlock == NULL)
	{
		printf_s("Uninitialized Session Control Block");
		return false;
	}
#endif
	va_list allowedStates;
	va_start(allowedStates, n);
	for(register int i = 0; i < n; i++)
	{
		if(lowState == va_arg(allowedStates, FSP_Session_State))
			return true;
	}
	va_end(allowedStates);
	return false;
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
	if (pSocket == NULL || !pSocket->IsPassive())
		return;

	if (!pSocket->LockWithActiveULA())
		return;

	// control structure, specified the local address (the Application Layer Thread ID part)
	// echo back the message at the same interface of receiving, only ALFID changed

	CtrlMsgHdr	hdrInfo;
	ALFID_T	fiberID;
	memset(&hdrInfo, 0, sizeof(CtrlMsgHdr));
	memcpy(&hdrInfo, mesgInfo.Control.buf, min(mesgInfo.Control.len, sizeof(hdrInfo)));
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
	FSP_InitiateRequest *q = FSP_OperationHeader<FSP_InitiateRequest>();
	FSP_Challenge challenge;
	struct _CookieMaterial cm;
	// the remote address is not changed
	timestamp_t t0 = be64toh(q->timeStamp);
	timestamp_t t1 = NowUTC();

	challenge.initCheckCode = q->initCheckCode;
	cm.idALF = fiberID;
	cm.idListener = GetLocalFiberID();
	// the cookie depends on the listening fiber ID AND the responding fiber ID
	cm.salt = q->salt;
	challenge.cookie = CalculateCookie(& cm, sizeof(cm), t1);
	challenge.timeDelta = htobe32((u_long)(t1 - t0));
	challenge.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

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

	if(initState.initCheckCode != pkt->initCheckCode)
		goto l_return;

	pSocket->SetRemoteFiberID(initState.idRemote = this->GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multi-home it is necessary even for IPv6
	pSocket->SetNearEndInfo(nearInfo);

	initState.timeDelta = be32toh(pkt->timeDelta);
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
	cm.idListener = q->params.idListener;
	cm.idALF = fiberID;
	cm.salt = q->salt;
	// UNRESOLVED! TODO: search the cookie blacklist at first
	if(q->cookie != CalculateCookie(& cm
			, sizeof(cm)
			, be64toh(q->timeStamp) + (INT32)be32toh(q->timeDelta)) )
	{
#ifdef TRACE
		printf_s("UNRESOLVED! TODO: put the cookie into the blacklist to fight against DDoS attack!?\n");
#endif
		goto l_return;	// the packet has been updated and should be discarded
	}

#pragma warning(disable:4533)	// initialization of backlogItem is skipped by 'goto l_return'
	// Simply ignore the duplicated request
	BackLogItem backlogItem(GetRemoteFiberID(), q->salt);
	if(pSocket->pControlBlock->backLog.Has(& backlogItem))
		goto l_return;

	assert(sizeof(backlogItem.allowedPrefixes) == sizeof(q->params.subnets));
	// secondly, fill in the backlog item if it is new
	CtrlMsgHdr * const pHdr = (CtrlMsgHdr *)mesgInfo.Control.buf;
	// Note that FSP over IPv6 does NOT support NAT automatically, by design
	// However, participants of FSP MAY obtain the IPv6 network prefix
	// obtained after NAT by uPnP and fill in the subnets field with the value after translation
	backlogItem.acceptAddr.cmsg_level = pHdr->pktHdr.cmsg_level;
	if (pHdr->IsIPv6())
	{
		memcpy(backlogItem.allowedPrefixes, q->params.subnets, sizeof(TSubnets));
		memcpy(&backlogItem.acceptAddr, &pHdr->u, sizeof(FSP_SINKINF));
	}
	else
	{	// FSP over UDP/IPv4
		register PFSP_IN6_ADDR fspAddr = (PFSP_IN6_ADDR) & backlogItem.acceptAddr;
		memset(backlogItem.allowedPrefixes, 0, sizeof(TSubnets));
		// For sake of NAT ignore the subnet prefixes reported by the initiator
		fspAddr->_6to4.prefix = PREFIX_FSP_IP6to4;
		//
		fspAddr->_6to4.ipv4 = addrFrom.Ipv4.sin_addr.S_un.S_addr;
		fspAddr->_6to4.port = addrFrom.Ipv4.sin_port;
		backlogItem.allowedPrefixes[0] = fspAddr->subnet;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("To accept connect request from address: ");
		DumpNetworkUInt16((uint16_t *)& fspAddr->subnet, sizeof(fspAddr->subnet) / 2);
#endif
		fspAddr->_6to4.ipv4 = pHdr->u.ipi_addr;
		fspAddr->_6to4.port = DEFAULT_FSP_UDPPORT;
		fspAddr->idHost = 0;	// no for IPv4 no virtual host might be specified
		fspAddr->idALF = fiberID;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("To accept connect request at socket address: ");
		DumpNetworkUInt16((uint16_t *)& fspAddr->subnet, sizeof(fspAddr->subnet) / 2);
#endif
		backlogItem.acceptAddr.ipi6_ifindex = pHdr->u.ipi_ifindex;
	}
	// Ephemeral key materials(together with salt):
	backlogItem.initCheckCode = q->initCheckCode;
	backlogItem.cookie = q->cookie;
	backlogItem.timeDelta = be32toh(q->timeDelta);
	backlogItem.nboTimeStamp = q->timeStamp;
	//
	backlogItem.remoteHostID = nearInfo.IsIPv6() ? SOCKADDR_HOSTID(mesgInfo.name) : 0;
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
// PRE_CLOSED, CLONING}-->/RESET/
//    -->NON_EXISTENT-->[Notify]
//{NON_EXISTENT, LISTENING, CLOSED, Otherwise}<-->/RESET/{Ignore}
// UNRESOLVED! Lost of RESET is silently ignored?
// TODO: put the RESET AND other meaningful packet on the stack/queue
// The first RESET should be push onto the top. Repeated RESET should be append at the tail.
void LOCALAPI CSocketItemEx::OnGetReset(FSP_RejectConnect & reject)
{
#ifdef TRACE
	printf_s("\nRESET got, in state %s\n\n", stateNames[lowState]);
#endif
	// No, we cannot reset a socket without validation
	if (!WaitUseMutex())
		return;
	if (pControlBlock == NULL)
		goto l_bailout;

	if(InState(CONNECT_BOOTSTRAP))
	{
		if(reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
		&& reject.initCheckCode == pControlBlock->connectParams.initCheckCode)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if(InState(CONNECT_AFFIRMING))
	{
		if(reject.timeStamp == pControlBlock->connectParams.nboTimeStamp
		&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if(InState(CHALLENGING))
	{
		if(reject.sn.initial == htobe32(pControlBlock->connectParams.initialSN)
		&& reject.cookie == pControlBlock->connectParams.cookie)
		{
			DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if(! InState(LISTENING) && ! InState(CLOSED))
	{
		int32_t offset = OffsetToRecvWinLeftEdge(be32toh(reject.sn.initial));
		if(-1 <= offset && offset < pControlBlock->recvBufferBlockN
		&& ValidateICC((FSP_NormalPacketHeader *)& reject, 0, fidPair.peer, 0))
		{
			DisposeOnReset();
		}
		// otherwise simply ignore.
	}
	// InStates ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED, CLONING
	// besides, those states are recoverable.
	// LISTENING state is not affected by reset signal
l_bailout:
	SetMutexFree();
}



// Given
//	ControlBlock::seq_t &		the accumulative acknowledgement
//	GapDescriptor * &			[_out_] the gap descriptor list
//	int &						[_out_] number of gap descriptors in the list
// Do
//	Check whether KEEP_ALIVE or it special norm, ACK_FLUSH, is valid and output the gap descriptor list
// Return
//	true if the header packet, which is assumed to be KEEP_ALIVE or ACK_FLUSH packet, is valid
//	false if it is not
// Remark
//	DoS attack against long-term sessions by replaying KEEP_ALVIE is possible but mitigated
// Side Effect Existed!
//	If it is valid the gap descriptors are transformed to the host byte order
bool LOCALAPI CSocketItemEx::ValidateSNACK(ControlBlock::seq_t & ackSeqNo, FSP_SelectiveNACK::GapDescriptor * & gaps, int & n)
{
	register FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();	// defined a little earlier for debug/trace purpose
	if (headPacket->lenData != 0)
	{
#ifdef TRACE
		printf_s("%s is out-of-band and CANNOT carry data: %d\n", opCodeStrings[p1->hs.opCode], headPacket->lenData);
#endif
		return false;
	}

	// Get the offset of payload against the start of the FSP header
	int32_t offset = be16toh(p1->hs.hsp);
	FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)((uint8_t *)p1 + offset - sizeof(FSP_SelectiveNACK));
	uint32_t salt = pSNACK->serialNo;
	uint32_t sn = be32toh(salt);

	if (int32_t(sn - lastOOBSN) <= 0)
	{
#ifdef TRACE
		printf_s("%s has encountered replay attack? Sequence number:\n\tinband %u, oob %u - %u\n"
			, opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo, sn, lastOOBSN);
#endif
		return false;
	}
	lastOOBSN = sn;

#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s data length: %d, header length: %d, peer ALFID = %u\n"
		, opCodeStrings[p1->hs.opCode]
		, headPacket->lenData
		, offset
		, fidPair.peer);
	DumpNetworkUInt16((uint16_t *)p1, offset / 2);
#endif

	ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return false;

	if(! ValidateICC(p1, 0, fidPair.peer, salt))	// No! Extension header is not encrypted!
	{
#ifdef TRACE
		printf_s("Invalid integrity check code of %s for fiber#%u!?\n"
				 "Acknowledged sequence number: %u\n" , opCodeStrings[p1->hs.opCode], fidPair.source, ackSeqNo);
#endif
		return false;
	}

	n = offset - be16toh(pSNACK->hs.hsp) - sizeof(FSP_SelectiveNACK);
	if (n < 0 || n % sizeof(FSP_SelectiveNACK::GapDescriptor) != 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("This is a malformed SNACK packet");
		return false;
	}

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *)pSNACK - n);
	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s sequence number: %u^|^%u\n"
		"\taccumulatively acknowledged %u with %d gap(s)\n"
		, opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo, sn
		, ackSeqNo, n);
#endif
	return true;
}



// Given
//	PktBufferBlock *	the packet buffer that holds ACK_CONNECT_REQ which might carry payload
//	int					the content length of the packet buffer, which holds both the header and the optional payload
// Do
//	Check the validity of the acknowledgement to the CONNECT_REQUEST command and establish the ephemeral session key
// CONNECT_AFFIRMING
//	|--[Rcv.ACK_CONNECT_REQ]-->[Notify]
// See also @DLL::ToConcludeConnect()
void CSocketItemEx::OnConnectRequestAck(PktBufferBlock *pktBuf, int lenData)
{
	if (!LockWithActiveULA())
		return;

	if(! InState(CONNECT_AFFIRMING))
	{
#ifdef TRACE
		printf_s("\nFiber#%u, Get wandering ACK_CONNECT_REQ in non CONNECT_AFFIRMING state", fidPair.source);
#endif
		goto l_return;
	}

	lenData -= sizeof(FSP_AckConnectRequest);
	if (lenData < 0 || lenData > MAX_BLOCK_SIZE)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("TODO: debug memory corruption error");
		goto l_return;
	}

	FSP_AckConnectRequest & response = *(FSP_AckConnectRequest *)& pktBuf->hdr;
	if(be32toh(response.expectedSN) != pControlBlock->sendWindowFirstSN)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Get an unexpected/out-of-order ACK_CONNECT_REQ");
		goto l_return;
	}	// See also OnGetConnectRequest

	ControlBlock::seq_t pktSeqNo = be32toh(response.sequenceNo);
	pControlBlock->SetRecvWindow(pktSeqNo);
	TRACE_SOCKET();

	// Must prepare the receive window before allocate any receive buffer
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(pktSeqNo);
	if(skb == NULL)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("What? Cannot allocate the payload buffer for ACK_CONNECT_REQ?");
		goto l_return;
	}

	// ACK_CONNECT_REQ was not pushed into the queue so head packet was not set
	// Put the payload (which might be empty) as if PlacePayload were called
	BYTE *ubuf;
	if (skb == NULL || !CheckMemoryBorder(skb) || (ubuf = GetRecvPtr(skb)) == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("TODO: debug memory corruption error");
		// Used to be HandleMemoryCorruption() or Recycle(); Reject(EFAULT); but don't bother to now
		AbortLLS();
		goto l_return;
	}

	// Now the packet can be legitimately accepted

	// Ignore granularity of OS time-slice here, which may slightly affect calculation of RTT
	tSessionBegin = tMigrate = tLastRecv = NowUTC();
	lowState = CHALLENGING;	// Disable retransmission of head packet in the send queue
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, (tRoundTrip_us + (tSessionBegin - tRecentSend) + 1) >> 1);

	// Attention Please! ACK_CONNECT_REQ may carry payload and thus consume the packet sequence space
	skb->len = lenData;
	if(lenData > 0)
		memcpy(ubuf, (BYTE *) & response + sizeof(response), lenData);
	// Built-in rule: ACK_CONNECT_REQ is always a singleton transmit transaction
	skb->InitFlags<TransactionEnded>();	// See also PlacePayload()
	skb->ReInitMarkComplete();

	// the officially announced IP address of the responder shall be accepted by the initiator
	// assert(response.params.subnets >= sizeof(sizeof(par->allowedPrefixes));
	SConnectParam * par = &pControlBlock->connectParams;
	memset(par->allowedPrefixes, 0, sizeof(par->allowedPrefixes));
	memcpy(par->allowedPrefixes, response.subnets, sizeof(response.subnets));

	pControlBlock->peerAddr.ipFSP.fiberID = pktBuf->fidPair.source;
	// persistent session key material from the remote end might be ready
	// as ACK_CONNECT_REQ composes a singleton transmit transaction
	pControlBlock->SnapshotReceiveWindowRightEdge();
	pControlBlock->sendWindowLimitSN
		= pControlBlock->sendWindowFirstSN + min(pControlBlock->sendBufferBlockN, response.GetRecvWS());

	// ephemeral session key material was ready OnInitConnectAck
	InstallEphemeralKey();
	SignalFirstEvent(FSP_NotifyAccepted);	// The initiator may cancel data transmission, however

l_return:
	SetMutexFree();
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

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		// Although it lets ill-behaviored peer take advantage by sending ill-formed ACK_START
		// it costs much less than to ValidateICC() or Notify()
		// PEER_COMMIT, COMMITTING2, CLOSABLE: retransmit ACK_FLUSH on get ACK_START
		if (OffsetToRecvWinLeftEdge(headPacket->pktSeqNo) < 0 || !isInitiativeState)
		{
			EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
			return;
		}
		if (isInitiativeState && headPacket->pktSeqNo != pControlBlock->recvWindowExpectedSN)
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

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	if (skb == NULL)
		return;

	// ACK_START has nothing to deliver to ULA
	if (isInitiativeState)
	{
		skb->ReInitMarkAcked();
		pControlBlock->SlideRecvWindowByOne();
	}
	// Indirect dependency: tLastRecv which is exploited in SendAckFlush in TransitOnPeerCommit is set here
	tLastRecv = NowUTC();
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, tLastRecv - tRecentSend);
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
	if (!isInitiativeState  && lowState < ESTABLISHED)
		return;

#ifdef TRACE
	printf_s("Payload length: %d\n", headPacket->lenData);
#endif
	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
		return;

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!IsAckExpected(ackSeqNo))
		return;

	bool isMultiplying = InState(CLONING);
	if (!isMultiplying)	// the normality
	{
		int32_t d = OffsetToRecvWinLeftEdge(headPacket->pktSeqNo);
		if (d >= pControlBlock->recvBufferBlockN)
		{
#if (TRACE & (TRACE_HEARTBEAT | TRACE_SLIDEWIN))
			printf_s("@%s: invalid sequence number: %u, distance to the receive window: %d\n"
				, __FUNCTION__, headPacket->pktSeqNo, d);
#endif
			return;		// DoS attack OR a premature start of new transmit transaction
		}
		if (d < 0)
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

	pControlBlock->ResizeSendWindow(ackSeqNo, p1->GetRecvWS());

	int countPlaced = PlacePayload();
	if (countPlaced == -EFAULT)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("how on earth no buffer in the receive window?!");
		Notify(FSP_NotifyOverflow);
		return;
	}
	// Make acknowledgement, in case previous acknowledgement is lost
	if (countPlaced == -ENOENT || countPlaced == -EEXIST)
	{
		EnableDelayAck();
		return;
	}

#if defined(_DEBUG) && defined(TRACE)
	if(countPlaced < 0)
	{
		printf_s("Place PERSIST failed: error number = %d\n", countPlaced);
		return;
	}
#else
	if(countPlaced < 0)
		return;
#endif

	// PERSIST is always the accumulative acknowledgement to ACK_CONNECT_REQ or MULTIPLY
	// ULA slide the receive window, no matter whether the packet has payload
	// The timer was already started for transient state management when Accept(), Multiply() or sending MULTIPLY
	if (isInitiativeState)
	{
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
		skb->ReInitMarkAcked();
		pControlBlock->SlideSendWindowByOne();	// See also AcceptSNACK
		tRoundTrip_us = (uint32_t)min(UINT32_MAX, tLastRecv - tRecentSend);
#if (TRACE & (TRACE_SLIDEWIN | TRACE_HEARTBEAT))
		printf_s("\nPERSIST received, acknowledged SN = %u\n\tThe responder calculate RTT: %uus\n", ackSeqNo, tRoundTrip_us);
#endif
	}

	// Note that TransitOnPeerCommit may SendAckFlush which relies on correctness of tLastRecv
	if (HasBeenCommitted())
	{
		if (TransitOnPeerCommit())
		{
			Notify(FSP_NotifyToCommit);
			RestartKeepAlive();
		}
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
		// default:	// case ESTABLISHED: case COMMITTED:	// keep state
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
//	{COMMITTED, CLOSABLE, PRE_CLOSED}-->/KEEP_ALIVE/<-->{keep state}{Update Peer's Authorized Addresses}
void CSocketItemEx::OnGetKeepAlive()
{
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	TRACE_SOCKET();
#endif
	bool acknowledgible = InStates(4, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2);
	if (!acknowledgible && !InState(COMMITTED) && !InState(CLOSABLE) && !InState(PRE_CLOSED))
	{
#ifdef TRACE
		printf_s("Got KEEP_ALIVE unexpectedly in state %s(%d)\n", stateNames[lowState], lowState);
#endif
		return;
	}

	FSP_SelectiveNACK::GapDescriptor *gaps;
	int n;
	ControlBlock::seq_t ackSeqNo;
	if(!ValidateSNACK(ackSeqNo, gaps, n))
		return;
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Fiber#%u: SNACK packet with %d gap(s) advertised received\n", fidPair.source, n);
#endif
	// By default ULA should poll the send buffer, instead to rely on soft-interrupt
	if (acknowledgible)
	{
		ControlBlock::seq_t seq0 = pControlBlock->sendWindowFirstSN;
		int r = AcceptSNACK(ackSeqNo, gaps, n);
		if (r > 0 && pControlBlock->CountSendBuffered() == 0)
			Notify(FSP_NotifyBufferReady);
#ifndef NDEBUG
		else if (r < 0)
			printf_s(__FUNCDNAME__ "AcceptSNACK unexpectedly return %d\n", r);
#endif		// UNRESOLVED?! Should log this very unexpected case
	}

	PFSP_HeaderSignature phs = headPacket->GetHeaderFSP()->PHeaderNextTo<FSP_SelectiveNACK>(& gaps[n]);
	if(phs != NULL)
		HandlePeerSubnets(phs);
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
	int32_t d = OffsetToRecvWinLeftEdge(headPacket->pktSeqNo);
	if (d >= pControlBlock->recvBufferBlockN)
	{
#if (TRACE & (TRACE_HEARTBEAT | TRACE_SLIDEWIN))
		printf_s("@%s: invalid sequence number: %u, distance to the receive window: %d\n"
			, __FUNCTION__, headPacket->pktSeqNo, d);
#endif
		return;		// DoS attack OR a premature start of new transmit transaction
	}
	if (d < 0)
	{
		EnableDelayAck();	// It costs much less than to ValidateICC() or Notify()
		return;
	}

	// Just ignore the unexpected PURE_DATA
	if (InStates(4, CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE))
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

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
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

	int r = PlacePayload();
	if (r == -EFAULT)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("No buffer when the receive window is not closed?");
		Notify(FSP_NotifyOverflow);
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

	// Did not exploit ControlBlock::CountDeliverable because of multi-thread shared memory synchronization problem
	// Normally the ULA work in polling mode. Urge it to process the receive buffer if the buffer is full
	if (int32_t(pControlBlock->recvWindowExpectedSN - GetRecvWindowFirstSN()) >= pControlBlock->recvBufferBlockN)
		Notify(FSP_NotifyDataReady);
	// See also OnGetPersist()
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
		// default:	// case PEER_COMMIT: case COMMITTING2: case CLOSABLE:	// keep state
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

	FSP_SelectiveNACK::GapDescriptor *gaps;
	int n;
	ControlBlock::seq_t ackSeqNo;
	if(!ValidateSNACK(ackSeqNo, gaps, n))
		return;
#ifndef NDEBUG
	if(n != 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("ACK_FLUSH should carry accumulatively positively acknowledge only");
		return;
	}
#endif
	AcceptSNACK(ackSeqNo, gaps, 0);

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
//	 |--{Whole transaction finished}-->[Send ACK_FLUSH]
//		|-->[Notify]-->CLOSED
// {COMMITTING2, CLOSABLE}-->/RELEASE-->[Send ACK_FLUSH]
//	 -->[Notify]-->CLOSED
// PRE_CLOSED-->/RELEASE/-->CLOSED-->[Notify]
// Remark
//	RELEASE implies NULCOMMIT
//	RELEASE implies ACK_FLUSH as well so a lost ACK_FLUSH does not prevent it to shutdown gracefully
//	There's a race condition that
//	while NotifiedToFinsh immediately follows a NotifyToCommit, RELEASE may arrive before ACK_FLUSH
//	And accept RELEASE in PRE_CLOSED state because ACK_FLUSH may race with RELEASE in some scenario
void CSocketItemEx::OnGetRelease()
{
	if (!InStates(5, COMMITTING, COMMITTED, COMMITTING2, CLOSABLE, PRE_CLOSED))
		return;

	if (headPacket->lenData != 0)
		return;

	if (headPacket->pktSeqNo != pControlBlock->recvWindowNextSN)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nThe RELEASE packet to %u is valid only if it is the last expected\n"
			"\tSequence number of this packet = %u, right edge of receive window is %u\n"
			, fidPair.source
			, headPacket->pktSeqNo, pControlBlock->recvWindowNextSN);
#endif
		return;
	}

	if (!ValidateICC())
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Invalid integrity check code!?");
		return;
	}

	// Place a payloadless EoT packet into the receive queue,
	// and the duplicate RELEASE packet would be rejected
	// hidden dependency: tLastRecv which is exploited in SendAckFlush is set in PlacePayload
	PlacePayload();
	AcceptSNACK(pControlBlock->sendWindowNextSN, NULL, 0);

	hasAcceptedRELEASE = 1;
	if (InState(COMMITTING))
		SetState(COMMITTED);
	if (InState(COMMITTED) && !HasBeenCommitted())
		return;

	if (!InState(PRE_CLOSED))
		SendAckFlush();
	ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);
	lowState = CLOSED;
	Notify(FSP_NotifyToFinish);
	//^Just to make internal recycling work. Let ULA do further state transition
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

	if (!InStates(6, ESTABLISHED, COMMITTING, COMMITTED, PEER_COMMIT, COMMITTING2, CLOSABLE))
		return;

	// The out-of-band serial number is stored in p1->expectedSN
	// Check whether it is a collision OR a replay-attack
	PFSP_InternalFixedHeader pFH = headPacket->GetHeaderFSP();
	uint32_t salt = _InterlockedExchange((LONG *) & pFH->expectedSN, 0);
	uint32_t sn = be32toh(salt);
	if (int32_t(sn - lastOOBSN) <= 0)
	{
#ifdef TRACE
		printf_s("MULTIPLY has encountered replay attack? Sequence number:\n\tinband %u, oob %u - %u\n"
			, headPacket->pktSeqNo, sn, lastOOBSN);
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

	if (!ValidateICC(pFH, headPacket->lenData, idSource, salt))
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Invalid integrity check code of MULTIPLY\n"
				 "  might be in the race condition that MULTIPLY received before ULA installed new key\n");
#endif
		return;
	}

	newItem = (CMultiplyBacklogItem *)CLowerInterface::Singleton.AllocItem();
	if (newItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot for multiplication");
		return;		// for security reason silently ignore the exception
	}

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

	backlogItem.expectedSN = headPacket->pktSeqNo;
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
	newItem->CopyInPlainText((BYTE *)pFH + be16toh(pFH->hs.hsp), headPacket->lenData);

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
		"\tSN of MULTIPLY received = %09u, salt = %09u\n"
		"\tALFID of peer's branch = %u, ALFID of near end's parent = %u\n"
		, backlogItem.expectedSN, salt
		, idSource, idParent);
#endif
	// note that the responder's key material mirrors the initiator's
	if (newItem->contextOfICC.keyLifeRemain != 0)
		newItem->DeriveKey(idSource, idParent);

	newItem->tLastRecv = tLastRecv;	// inherit the time when the MULTIPLY packet was received
	newItem->tRoundTrip_us = tRoundTrip_us;	// inherit the value of the parent as the initial
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
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	if(skb == NULL)
		return -ENOENT;

	if (!CheckMemoryBorder(skb))
		return -EFAULT;

	if (skb->IsComplete())
		return -EEXIST;

	FSP_NormalPacketHeader *pHdr = headPacket->GetHeaderFSP();
	int len = headPacket->lenData;
	if (len > 0)
	{
		BYTE *ubuf = GetRecvPtr(skb);
		if (ubuf == NULL)
			return -EFAULT;
		// Right align the payload part of the first packet of the receive buffer of a new transmit transaction
		// Assume payload length has been checked
		if (pHdr->hs.opCode == PERSIST)
			ubuf += MAX_BLOCK_SIZE - len;
		memcpy(ubuf, (BYTE *)pHdr + be16toh(pHdr->hs.hsp), len);
	}
	// Or else might be zero for ACK_START or MULTIPLY packet
	skb->timeRecv = tLastRecv = NowUTC();

	skb->version = pHdr->hs.major;
	skb->opCode = pHdr->hs.opCode;
	skb->CopyInFlags(pHdr);
	skb->len = len;
	skb->ReInitMarkComplete();

	return len;
}
