/*
 * FSP lower-layer service program, do processing triggered by packets sent from far-end peer,
 * deliver them to the upper layer application on demand
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

#pragma intrinsic(_InterlockedCompareExchange16)

#ifdef TRACE
#define TRACE_SOCKET()	\
	(printf_s("%s local fiber#%u in state %s\n", __FUNCTION__	\
		, fidPair.source		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpSendRecvWindowInfo())
#else
#define TRACE_SOCKET()
#endif


// Allas! it would be very concise in the Swift language
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



bool LOCALAPI CSocketItemEx::Notify(FSP_ServiceCode n)
{
	int r = pControlBlock->notices.Put(n);
	if(r < 0)
	{
#ifdef TRACE
		printf_s("\nSession #%u, cannot put soft interrupt %s(%d) into the queue.\n", fidPair.source, noticeNames[n], n);
#endif
		return false;
	}
	//
	if(r > 0)
	{
#ifdef TRACE
		printf_s("\nSession #%u, duplicate soft interrupt %s(%d) eliminated.\n", fidPair.source, noticeNames[n], n);
#endif
		return true;
	}
	//
	SignalEvent();
#ifdef TRACE
	printf_s("\nSession #%u raise soft interrupt %s(%d)\n", fidPair.source, noticeNames[n], n);
#endif
	return true;
}



//LISTENING
//	|<-->[Rcv.INIT_CONNECT && {resource available}: Send ACK_INIT_CONNECT]
//	|<-->[Rcv.INIT_CONNECT && {resource unavailable}: Send RESET]
// Do
//  Allocate a new Session ID randomly there might be collision in a high-load responder
//	ACK_INIT_CONNECT, Cookie, initiator's check code echo, time difference
//		or
//	RESET, Timestamp echo, initiator's check code echo, reason
void LOCALAPI CLowerInterface::OnGetInitConnect()
{
	TRACE_HERE("called");

	// Silently discard connection request to blackhole, and avoid attacks alike 'port scan'
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL || ! pSocket->IsPassive() || ! pSocket->IsInUse())
		return;

	// control structure, specified the local address (the Application Layer Thread ID part)
	// echo back the message at the same interface of receiving, only ALFID changed

	CtrlMsgHdr	hdrInfo;
	ALFID_T	fiberID;
	memset(&hdrInfo, 0, sizeof(CtrlMsgHdr));
	memcpy(&hdrInfo, mesgInfo.Control.buf, min(mesgInfo.Control.len, sizeof(hdrInfo)));
	if (hdrInfo.IsIPv6())
	{
		fiberID = CLowerInterface::Singleton()->RandALFID((PIN6_ADDR) & hdrInfo.u);
	}
	else
	{
		fiberID = CLowerInterface::Singleton()->RandALFID();
		hdrInfo.u.idALF = fiberID;
	}

	// TODO: there should be some connection initiation throttle control in RandALFID
	// TODO: UNRESOLVED! admission-control here?
	// TODO: UNRESOLVED! For FSP over IPv6, attach responder's resource reservation...
	if(fiberID == 0)
	{
		SendPrematureReset(ENOENT);
		return;
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
	challenge.cookie = CalculateCookie((BYTE *) & cm, sizeof(cm), t1);
	challenge.timeDelta = htobe32((u_long)(t1 - t0));
	challenge.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	SetLocalFiberID(fiberID);
	SendBack((char *) & challenge, sizeof(challenge));
}



//CONNECT_BOOTSTRAP-->/ACK_INIT_CONNECT/
//	-->CONNECT_AFFIRMING-->[Send CONNECT_REQUEST]
//QUASI_ACTIVE-->/ACK_INIT_CONNECT/
//	-->CONNECT_AFFIRMING-->[Send CONNECT_REQUEST]
// Do
//	Check the inititiator's cookie, make the formal connection request towards the responder
void LOCALAPI CLowerInterface::OnInitConnectAck()
{
	TRACE_HERE("called");

	//	find the socket item firstly
	FSP_Challenge *pkt = FSP_OperationHeader<FSP_Challenge>();
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL)
		return;

	if(! pSocket->TestAndLockReady())
	{
		TRACE_HERE("lost ACK_INIT_CONNECT due to lack of locks");
		return;
	}

	SConnectParam & initState = pSocket->pControlBlock->connectParams;
	ALFID_T idListener = initState.idRemote;

	if(! pSocket->InState(CONNECT_BOOTSTRAP) && ! pSocket->InState(QUASI_ACTIVE))
		goto l_return;

	if(initState.initCheckCode != pkt->initCheckCode)
		goto l_return;

	// TODO: UNRESOLVED!? get resource reservation requirement from IPv6 extension header
	pSocket->SetRemoteFiberID(initState.idRemote = this->GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multihome it is necessary even for IPv6
	initState.timeDelta = be32toh(pkt->timeDelta);
	initState.cookie = pkt->cookie;
	EnumEffectiveAddresses(initState.allowedPrefixes);

	pSocket->AffirmConnect(initState, idListener);

l_return:
	pSocket->SetReady();
}


/**
	prepare the backlog, filling in the information about the remote fiber ID, the suggested local fiber ID,
	the list of the remote address prefixes(for multihome support) and the half-connection parameters.
	signal DLL (in the context of ULA) which polls the backlog and sets up the session context
	[into 'CHALLENGING'] (allocate state space, including data buffers, command queue, etc).
	it is tempting to acknowledge the connect request immediately to save some memory copy,
	however, it is not justified, for throughput throttling is overriding
 */
//LISTENING-->/CONNECT_REQUEST/-->[API{new context, callback}]
//	|-->[{return}Accept]
//		-->{new context}CHALLENGING-->[Send ACK_CONNECT_REQ]
//	|-->[{return}Commit{new context}]
//		-->{new context}COMMITTING-->[Send COMMIT]{enable retry}
//	|-->[{return}Reject]-->[Send RESET]{abort creating new context}
//CLOSED-->/CONNECT_REQUEST/-->[API{callback}]
//	|-->[{return}Accept]-->CHALLENGING-->[Send ACK_CONNECT_REQ]
//	|-->[{return}Commit]-->COMMITTING-->[Send COMMIT]{enable retry}
//	|-->[{return}Reject]-->NON_EXISTENT-->[Send RESET]
void LOCALAPI CLowerInterface::OnGetConnectRequest()
{
	TRACE_HERE("called");

	FSP_ConnectRequest *q = FSP_OperationHeader<FSP_ConnectRequest>();
	CSocketItemEx *pSocket = MapSocket();

	// Check whether it is a collision
	if(pSocket != NULL && pSocket->IsInUse())
	{
		if (pSocket->InState(CHALLENGING)
		&& pSocket->fidPair.peer == this->GetRemoteFiberID()
		&& pSocket->pControlBlock->connectParams.cookie == q->cookie)
		{
			pSocket->EmitStart();
			return;	// hitted
		}
		// 
		// Or else it is a collision and is silently discard in case an out-of-order RESET reset a legitimate connection
		// UNRESOLVED! Is this a unbeatable DoS attack to initiator if there is a 'man in the middle'?
		if (! pSocket->InState(CLOSED))
			return;
	}

	// Silently discard the request onto illegal or non-listening socket 
	if (pSocket == NULL || ! pSocket->IsInUse())
	{
		pSocket = (*this)[q->params.listenerID];	// a dialect of MapSocket
		if (pSocket == NULL || !pSocket->IsPassive())
			return;
	}

	if (! pSocket->TestAndLockReady())
	{
		TRACE_HERE("lost of CONNECT_REQUEST due to lack of locks");
		return;
	}

	// cf. OnInitConnectAck() and SocketItemEx::AffirmConnect()
	ALFID_T fiberID = GetLocalFiberID();
	struct _CookieMaterial cm;

	cm.idListener = q->params.listenerID;
	cm.idALF = fiberID;
	cm.salt = q->salt;
	// UNRESOLVED! TODO: search the cookie blacklist at first
	if(q->cookie != CalculateCookie((BYTE *) & cm
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

	// secondly, fill in the backlog item if it is new
	CtrlMsgHdr * const pHdr = (CtrlMsgHdr *)mesgInfo.Control.buf;
	if (pHdr->IsIPv6())
	{
		memcpy(&backlogItem.acceptAddr, &pHdr->u, sizeof(FSP_PKTINFO));
	}
	else
	{	// FSP over UDP/IPv4
		register PFSP_IN6_ADDR fspAddr = (PFSP_IN6_ADDR) & backlogItem.acceptAddr;
		fspAddr->u.st.prefix = PREFIX_FSP_IP6to4;
		fspAddr->u.st.ipv4 = pHdr->u.ipi_addr;
		fspAddr->u.st.port = DEFAULT_FSP_UDPPORT;
		fspAddr->idHost = 0;	// no for IPv4 no virtual host might be specified
		fspAddr->idALF = fiberID;
		backlogItem.acceptAddr.ipi6_ifindex = pHdr->u.ipi_ifindex;
	}
	// Ephemeral key materials(together with salt):
	backlogItem.initCheckCode = q->initCheckCode;
	backlogItem.cookie = q->cookie;
	backlogItem.timeDelta = be32toh(q->timeDelta);
	backlogItem.nboTimeStamp = q->timeStamp;
	//
	backlogItem.remoteHostID = nearInfo.IsIPv6() ? SOCKADDR_HOST_ID(mesgInfo.name) : 0;
	//^See also GetRemoteFiberID()
	backlogItem.idParent = 0;
	rand_w32(& backlogItem.initialSN, 1);
	backlogItem.expectedSN = be32toh(q->initialSN);	// CONNECT_REQUEST does NOT consume a sequence number

	assert(sizeof(backlogItem.allowedPrefixes) == sizeof(q->params.subnets));
	memcpy(backlogItem.allowedPrefixes, q->params.subnets, sizeof(uint64_t) * MAX_PHY_INTERFACES);

	// lastly, put it into the backlog
	pSocket->pControlBlock->backLog.Put(& backlogItem);
	// TODO: handling resurrection failure -- just reuse?
	// if (pSocket->InState(CLOSED)) //;
	pSocket->SignalReturned();

l_return:
	pSocket->SetReady();
}



//{CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, CHALLENGING, ACTIVE,
// COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE,
// PRE_CLOSED, CLONING, RESUMING, QUASI_ACTIVE}-->/RESET/
//    -->NON_EXISTENT-->[Notify]
//{NON_EXISTENT, LISTENING, CLOSED, Otherwise}<-->/RESET/{Ignore}
void LOCALAPI CLowerInterface::OnGetResetSignal()
{
	TRACE_HERE("called");

	FSP_RejectConnect & reject = *FSP_OperationHeader<FSP_RejectConnect>();
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL || ! pSocket->IsInUse())	// RESET is never locked out
		return;

#ifdef TRACE
	printf_s("\nRESET got, in state %s\n\n", stateNames[pSocket->lowState]);
#endif

	if(pSocket->InState(CONNECT_BOOTSTRAP))
	{
		if(reject.u.timeStamp == pSocket->pControlBlock->connectParams.nboTimeStamp
		&& reject.u2.initCheckCode == pSocket->pControlBlock->connectParams.initCheckCode)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InState(CONNECT_AFFIRMING))
	{
		if(reject.u.timeStamp == pSocket->pControlBlock->connectParams.nboTimeStamp
		&& reject.u2.cookie == pSocket->pControlBlock->connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InState(CHALLENGING))
	{
		if(reject.u.sn.initial == htobe32(pSocket->pControlBlock->connectParams.initialSN)
		&& reject.u2.cookie == pSocket->pControlBlock->connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InStates(10, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE
		, PRE_CLOSED, CLONING, RESUMING, QUASI_ACTIVE))
	{
		// besides, those states are recoverable.
		if(pSocket->IsValidSequence(be32toh(reject.u.sn.initial))
		&& pSocket->ValidateICC((FSP_NormalPacketHeader *) & reject))
		{
			pSocket->DisposeOnReset();
		}
	}
	// LISTENING state is not affected by reset signal
	// And a CLOSED session responds to RESUME only
}



// Check wether KEEP_ALIVE or it special norm, ACK_FLUSH, is valid
// Side effect: if it is valid the gap descriptors are transformed to host byte order
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
	//
	if (int(headPacket->pktSeqNo - pControlBlock->recvWindowFirstSN) >= pControlBlock->recvBufferBlockN)
	{
#ifdef TRACE
		printf_s("%s has invalid sequence number:\t %u\n", opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo);
#endif
		return false;
	}


#ifdef TRACE_HEARTBEAT
	if(seqLastAck == 0)
		DebugBreak();
#endif
	if(int(headPacket->pktSeqNo - seqLastAck) < 0)
	{
#if defined(TRACE_PACKET) || defined(TRACE_HEARTBEAT)
		printf_s("%s has encountered stale packet attack? sequence number:\t %u\n", opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo);
#endif
		return false;
	}

	int32_t offset = be16toh(p1->hs.hsp);	// For the KEEP_ALIVE/ACK_FLUSH/SNACK packet it is the packet length as well
	FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)((uint8_t *)p1 + offset - sizeof(FSP_SelectiveNACK));
	uint32_t salt = pSNACK->serialNo;
	uint32_t sn = be32toh(salt);
	if(int(headPacket->pktSeqNo - seqLastAck) == 0 && int(sn - lastNAckSN) <= 0)
	{
#ifdef TRACE_PACKET
		printf_s("%s has encountered replay attack? sequence number: %u\t%u\n", opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo, sn);
#endif
		return false;
	}
	lastNAckSN = sn;

#ifdef TRACE_PACKET
	printf_s("%s data length: %d, header length: %d, peer ALFID = %u\n"
		, opCodeStrings[p1->hs.opCode]
		, headPacket->lenData
		, offset
		, fidPair.peer);
	DumpNetworkUInt16((uint16_t *)p1, offset / 2);
#endif

	if(! ValidateICC(p1, 0, salt))
	{
#ifdef TRACE
		printf_s("Invalid intergrity check code of %s!? Acknowledged sequence number: %u\n", opCodeStrings[p1->hs.opCode], ackSeqNo);
#endif
		return false;
	}

	ackSeqNo = be32toh(p1->expectedSN);
	if (!ResizeSendWindow(ackSeqNo, p1->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("Cannot adjust the send window on %s!? Acknowledged sequence number: %u\n", opCodeStrings[p1->hs.opCode], ackSeqNo);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return false;
	}

	n = offset - be16toh(pSNACK->hs.hsp) - sizeof(FSP_SelectiveNACK);
	if (n < 0 || n % sizeof(FSP_SelectiveNACK::GapDescriptor) != 0)
	{
		TRACE_HERE("This is a malformed SNACK packet");
		return false;
	}

	seqLastAck = headPacket->pktSeqNo;

	gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *)pSNACK - n);
	if(n == 0)
		return true;

	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
#ifdef TRACE
	printf_s("%s has %d gap(s), sequence number: %u\t%u\n", opCodeStrings[p1->hs.opCode], n, headPacket->pktSeqNo, sn);
#endif
	return true;
}



// Remark
//	CONNECT_AFFIRMING-->/ACK_CONNECT_REQ/-->[API{callback}]
//		|-->{Return Accept}-->ACTIVE-->[Send PERSIST]{start keep-alive}
//		|-->{Return Commit}-->COMMITTING-->[Send COMMIT]{enable retry}
//		|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
// See also {FSP_DLL}CSocketItemDl::ToConcludeConnect()
void LOCALAPI CSocketItemEx::OnConnectRequestAck(FSP_AckConnectRequest & response, int lenData)
{
	TRACE_SOCKET();
	if(! InState(CONNECT_AFFIRMING))
	{
		TRACE_HERE("Get wandering ACK_CONNECT_REQ in non CONNECT_AFFIRMING state");
		return;
	}

	if(be32toh(response.expectedSN) != pControlBlock->sendWindowFirstSN)	// See also onGetConnectRequest
	{
		TRACE_HERE("Get an unexpected/out-of-order ACK_CONNECT_REQ");
		return;
	}

	if(lenData < 0 || lenData > MAX_BLOCK_SIZE)
	{
		TRACE_HERE("TODO: debug memory corruption error");
		HandleMemoryCorruption();
		return;
	}

	tSessionBegin = tLastRecv = NowUTC();	// The packet was accepted

	// the officially annouced IP address of the responder shall be accepted by the initiator
	// assert(response.params.subnets >= sizeof(sizeof(par->allowedPrefixes));
	SConnectParam * par = & pControlBlock->connectParams;
	memset(par->allowedPrefixes, 0, sizeof(par->allowedPrefixes));
	memcpy(par->allowedPrefixes, response.params.subnets, sizeof(response.params.subnets));

	ControlBlock::seq_t pktSeqNo = be32toh(response.sequenceNo);
	pControlBlock->SetRecvWindowHead(pktSeqNo);
	pControlBlock->SetSendWindowSize(response.GetRecvWS());

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(pktSeqNo);
	if(skb == NULL)
	{
		TRACE_HERE("What? Cannot allocate the payload buffer for ACK_CONNECT_REQ?");
		return;
	}

	// ACK_CONNECT_REQ was not pushed into the queue so headpacket was not set
	// Put the payload (which might be empty) as if PlacePayload were called
	BYTE *ubuf;
	if (skb == NULL || !CheckMemoryBorder(skb) || (ubuf = GetRecvPtr(skb)) == NULL)
	{
		TRACE_HERE("TODO: debug memory corruption error");
		HandleMemoryCorruption();
		return;
	}

	// Attention Please! ACK_CONNECT_REQ may carry payload and thus consume the packet sequence space
	skb->len = lenData;
	if(lenData > 0)
		memcpy(ubuf, (BYTE *) & response + sizeof(response), lenData);
	skb->SetFlag<IS_FULFILLED>();	// See also PlacePayload()

	// ephemeral session key material was ready OnInitConnectAck
	InstallEphemeralKey();

	SignalReturned();
	TRACE_HERE("finally the connection request is accepted");

#ifdef TRACE
	TRACE_HERE("the initiator recalculate RTT");
	DumpTimerInfo(tLastRecv);
#endif
	// OS time-slice, if any, might somewhat affect calculating of RTT. But it can be igored for large BDP pipe
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, (tRoundTrip_us + (tSessionBegin - tRecentSend) + 1) >> 1);
	tKeepAlive_ms = tRoundTrip_us >> 8; // Would be put into effect on sending PERSIST or COMMIT
	// New keep_alive tempo is enabled on state transition. See FSP_Start

	seqLastAck = pktSeqNo - 1;
	//^Because the sequence number of ACK_CONNECT_REQUEST might be reused to acknowledge PERSIST or COMMIT 
}



// PERSIST is the acknowledgement to ACK_CONNECT_REQ, RESUME or MULTIPLY
//	{CHALLENING, CLONING}-->/PERSIST/-->ACTIVE{start keep-alive}-->[Notify]
//	{RESUMING, QUASI_ACTIVE}-->/PERSIST/-->ACTIVE{restart keep-alive}-->[Notify]
// Remark
//	PERSIST is instantly acknowledged to avoid possible dead-lock. See also KeepAlive()
void CSocketItemEx::OnGetPersist()
{
	TRACE_SOCKET();
	if (!InStates(5, CHALLENGING, ESTABLISHED, RESUMING, CLONING, QUASI_ACTIVE))
		return;

	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
	{
#ifdef TRACE
		printf_s("Invalid payload length: %d\n", headPacket->lenData);
#endif
		return;
	}

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("Invalid sequence number: %u\n", headPacket->pktSeqNo);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return;
	}

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	if (InState(ESTABLISHED))
	{
		SendSNACK(KEEP_ALIVE);
		return;
	}

	ControlBlock::seq_t ackSeqNo = be32toh(headPacket->GetHeaderFSP()->expectedSN);
	if (!ResizeSendWindow(ackSeqNo, headPacket->GetHeaderFSP()->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("Cannot resize send window. Acknowledged sequence number: %u\n", ackSeqNo);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return;
	}

	if (InState(CHALLENGING))
		tSessionBegin = tRecentSend;
	//^ session of a responsing socket start at the time ACK_CONNECT_REQ was sent
	// while the start time of resuming or resurrecting the session
	// remain the original for sake of key life-cycle management.

	SetState(ESTABLISHED);	// only after timer recalibrated may it transit
#ifdef TRACE
	TRACE_HERE("the responder calculate RTT");
#endif
	CalibrateKeepAlive();

	// PERSIST is always the accumulative acknowledgement to ACK_CONNECT_REQ, MULTIPLY or RESUME
#ifdef TRACE
	printf_s("\nPERSIST received. Acknowledged SN\t = %u\n", ackSeqNo);
#endif
	pControlBlock->SlideSendWindowByOne();	// See also RespondToSNACK

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	if(skb == NULL)
	{
		TRACE_HERE("how on earth no buffer in the receive window?!");
		Notify(FSP_NotifyOverflow);
		return;
	}
	int countPlaced = PlacePayload(skb);
	if (countPlaced == -EFAULT)
	{
#ifdef TRACE
		printf_s("Internal panic! Cannot place optional payload in PERSIST, error code = %d\n", countPlaced);
#endif
		return;
	}

	// It might be redundant, but make the protocol robust
	SendSNACK(CheckPeerCommit() ? ACK_FLUSH : KEEP_ALIVE);

	if (countPlaced == -EEXIST)
		return;

#ifdef TRACE
	if (countPlaced > 0)
		printf_s("There is optional payload in the PERSIST packet, payload length = %d\n", countPlaced);
#endif
	// The ULA slide the receive window, whether it is payload-less
	Notify(FSP_NotifyAccepted);
}



// KEEP_ALIVE is out-of-band and carrying some special optional headers for mobility support
//	{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2}-->/KEEP_ALIVE/
//		<-->{keep state}[Retransmit selectively]
void CSocketItemEx::OnGetKeepAlive()
{
#if defined(TRACE_HEARTBEAT) || defined(TRACE_PACKET)
	TRACE_SOCKET();
#endif
	if (!InStates(4, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2))
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
#ifdef TRACE_HEARTBEAT
	printf_s("Fiber#%u: SNACK packet with %d gap(s) advertised received\n", fidPair.source, n);
#endif
	if(RespondToSNACK(ackSeqNo, gaps, n) > 0)
		Notify(FSP_NotifyBufferReady);
	//
	// connection parameter may determine whether the payload is encrypted, however, let ULA handle it...
	PFSP_HeaderSignature phs = headPacket->GetHeaderFSP()->PHeaderNextTo<FSP_SelectiveNACK>(& gaps[n]);
	if(phs != NULL)
		HandleMobileParam(phs);
}



//ACTIVE-->/PURE_DATA/
//	|-->{if the receive queue is closable}
//		-->{stop keep-alive}PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//COMMITTING-->/PURE_DATA/
//	|-->{if the receive queue is closable}
//		-->COMMITTING2-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//COMMITTED-->/PURE_DATA/
//	|-->{if the receive queue is closable}
//		-->{stop keep-alive}CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//{CLONING, RESUMING}<-->/PURE_DATA/{just prebuffer}
void CSocketItemEx::OnGetPureData()
{
#ifdef TRACE_PACKET
	TRACE_SOCKET();
#endif
	// It's OK to prebuffer received data in CLONING or RESUMING state (but NOT in QUASI_ACTIVE state)
	// However ULA protocol designer must keep in mind that these prebuffered may be discarded
	if (!InStates(5, ESTABLISHED, COMMITTING, COMMITTED, CLONING, RESUMING))
	{
#ifdef TRACE
		printf_s("In state %s data may not be accepted.\n", stateNames[lowState]);
#endif
		return;
	}

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	if (skb == NULL)
	{
#ifdef TRACE
		printf_s("Invalid sequence number:\t %u\n", headPacket->pktSeqNo);
#endif
		return;
	}

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
#ifdef TRACE_PACKET
		printf_s("PURE_DATA header length: %d, Data length: %d, peer ALFID = %u\n", (int)be16toh(headPacket->hdr.hs.hsp), headPacket->lenData, fidPair.peer);
		DumpNetworkUInt16((uint16_t *) & headPacket->hdr, be16toh(headPacket->hdr.hs.hsp) / 2);
#endif
		return;
	}

	if (!ResizeSendWindow(be32toh(headPacket->GetHeaderFSP()->expectedSN), headPacket->GetHeaderFSP()->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("An out of order acknowledgement? seq#%u\n", be32toh(headPacket->GetHeaderFSP()->expectedSN));
#endif
		return;
	}

	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	// It is less efficient than signaling an 'interrupt' only when the head packet of a gap in the receive window is received
	// However, we may safely assume that out-of-order packets are of low ratior and it does not make too much overload
	// It is definitely less efficient than polling for 'very' high throughput network application
	int r = PlacePayload(skb);
	if(r <= 0)
	{
#ifdef TRACE
		printf_s("Either a PURE_DATA does not carry payload or the payload it is not stored safely: %d\n", r);
#endif
		return;
	}

	tLastRecv = NowUTC();

	// UNRESOLVED! Lazy acknowledgement might enhance efficiency
	// See also OnGetPersist()
	SendSNACK(CheckPeerCommit() ? ACK_FLUSH : KEEP_ALIVE);
	//
	Notify(FSP_NotifyDataReady);
}


//ACTIVE-->/COMMIT/
//	|-->{if the receive queue is closable}
//		-->{stop keep-alive}PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Notify]
//COMMITTING-->/COMMIT/
//	|-->{if the receive queue is closable}
//		-->COMMITTING2-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Notify]
//COMMITTED-->/COMMIT/
//	|-->{if the receive queue is closable}
//		-->{stop keep-alive}CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Notify]
//PRE_CLOSED<-->/COMMIT/[Retransmit RELEASE early]
//{PEER_COMMIT, COMMITTING2, CLOSABLE}<-->/COMMIT/[Send ACK_FLUSH]
//{CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE}<-->/COMMIT/{if the receive queue is closable}
//		-->{stop keep-alive}PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
// UNRESOLVED! fairness of adjourn? Anti-DoS-Attack?
void CSocketItemEx::OnGetCommit()
{
	TRACE_SOCKET();

	if (!InStates(11, CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE
		, ESTABLISHED, COMMITTING, COMMITTED, PEER_COMMIT, COMMITTING2, CLOSABLE, PRE_CLOSED))
	{
		return;
	}

	// As calculate ICC may consume CPU resource intensively we are relunctant to send RESET

	// check the ICC at first, silently discard the packet if ICC check failed
	// preliminary check of sequence numbers [they are IV on calculating ICC]
	// UNRESOLVED!? Taking the risk of DoS attack by replayed COMMIT...
	// TODO: throttle the rate of processing COMMIT by 'early dropping'
	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("Invalid sequence number:\t %u\n", headPacket->pktSeqNo);
#endif
		return;
	}

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	// Unlike PURE_DATA, a retransmitted COMMIT cannot be silent discarded
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);

	// Connection close is asymmetric in the sense that one side may unilaterally terminate the session without accept all of its peer's packets
	// The near end migrated from the COMMITTTED state to the PRE_CLOSED state by ULA's Shutdown, sending a RELEASE packet to its peer
	// But if the peer happens to have sent a COMMIT packet before received the RELEASE packet?
	// The near end should have migrated from the COMMITTED state to the CLOSABLE state
	// if the COMMIT packet were received before ULA's Shutdown, so the near end should migrate to the CLOSED state
	if(InState(PRE_CLOSED))
	{
		if(pControlBlock->HasBeenCommitted() <= 0)
			return;	// just prebuffer; but the payload would be ignored in PRE_CLOSED state!
		//
		StopKeepAlive();
		SetState(CLOSED);
		SendPacket<RELEASE>();
		Notify(FSP_NotifyFinish);
		return;	// Note the retransmitted RELEASE packet is to assure the peer that the session is deliberately terminated.
	}

	// Just retransmit ACK_FLUSH on duplicated COMMIT command
	if (skb == NULL)	// InStates(3, PEER_COMMIT, COMMITTING2, CLOSABLE)
	{
#ifdef TRACE
		printf_s("Duplicate COMMIT received in %s state\n", stateNames[lowState]);
#endif
		SendSNACK();
		return;
	}

	// but it is well known if PlayPayload return < 0 it is either -EFAULT or -EEXIST
	int r = PlacePayload(skb);
	if (r == -EFAULT)	// r < 0 && r != -EEXIST
	{
		TRACE_HERE("cannot place optional payload in the COMMIT packet");
		return;
	}
	// See also OnGetPersist()
#ifdef TRACE
	TRACE_HERE("the responder calculate RTT");
#endif
	CalibrateKeepAlive();

	// Transactional COMMIT packet carries accumulative acknowledgment
	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING) || InState(RESUMING) || InState(QUASI_ACTIVE);
	if(CheckPeerCommit())
	{
		if(isInitiativeState)
			pControlBlock->SlideSendWindowByOne();
		// MUST slide the send window BEFORE SendSNACK or else the sequence number of ACK_FLUSH or KEEP_ALIVE is wrong
		SendSNACK();
		//
		if(isInitiativeState)
		{
			Notify(FSP_NotifyAccepted);
			return;
		}
	}

	// But the data might be undeliverable, if there is some gap. However it do little harm
	if (r > 0)	// if r == -EEXIST it should have already notify
		Notify(FSP_NotifyDataReady);
}



// ACK_FLUSH, now a pure out-of-band control packet. A special norm of KEEP_ALIVE
//	COMMITTING-->/ACK_FLUSH/-->COMMITTED-->[Notify]
//	COMMITTING2-->/ACK_FLUSH/-->{stop keep-alive}CLOSABLE-->[Notify]
//	RESUMING-->/ACK_FLUSH/-->{keep state}[Notify]
//	PRE_CLOSED-->/ACK_FLUSH/-->CLOSED
void CSocketItemEx::OnAckFlush()
{
	// As ACK_FLUSH is rare we trace every appearance
	TRACE_SOCKET();

	// It's perfectly OK to receive an ACK_FLUSH in the RESUMING state which mean previous committed message was wholely acknowledged
	if (!InState(COMMITTING) && !InState(COMMITTING2) && !InState(RESUMING) && !InState(PRE_CLOSED))
		return;

	FSP_SelectiveNACK::GapDescriptor *gaps;
	int n;
	ControlBlock::seq_t ackSeqNo;
	if(!ValidateSNACK(ackSeqNo, gaps, n))
		return;
#ifndef NDEBUG
	if(n != 0)
	{
		TRACE_HERE("ACK_FLUSH shall carryaccumulatively positively acknowledge only");
		return;
	}
#endif

	tLastRecv = NowUTC();

	if(InState(PRE_CLOSED))
	{
		CloseToNotify();
		return;
	}

	if (InState(COMMITTING2))
	{
		StopKeepAlive();
		SetState(CLOSABLE);
	}
	else if(InState(COMMITTING))
	{
		SetState(COMMITTED);
	}

	// On ACK_FLUSH the new session key for the receive direction is ready. See also EmitICC() and InstallSessionKey()
	if(_InterlockedCompareExchange8(& pControlBlock->hasPendingKey, 0, HAS_PENDING_KEY_FOR_RECV) == HAS_PENDING_KEY_FOR_RECV)
		contextOfICC.firstRecvSNewKey = headPacket->pktSeqNo + 1;

	// For ACK_FLUSH just accumulatively positively acknowledge
	RespondToSNACK(ackSeqNo, NULL, 0);
	Notify(FSP_NotifyFlushed);
}



// RESUME may resume or resurrect a closable/closed connection
// UNRESOLVED! If the socket itself has been free...
// See OnResume() and OnResurrect()
void CSocketItemEx::OnGetResume()
{
	TRACE_SOCKET();
	FSP_NormalPacketHeader *pHdr = headPacket->GetHeaderFSP();

	// A CLOSED connnection may be resurrected, provide the session key is not out of life
	// A replayed/redundant RESUME would be eventually acknowedged by a legitimate PERSIST
	// Or COMMIT. See also OnAckFlush()
	if (!InStates(5, PEER_COMMIT, COMMITTING2, CLOSABLE, PRE_CLOSED, CLOSED))
		return;

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		return;

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	if(! ResizeSendWindow(be32toh(pHdr->expectedSN), pHdr->GetRecvWS()))
		return;

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	// UNRESOLVED! Should send window to be recalibrated?
	// TODO: UNRESOLVED! if it return -EEXIST, should ULA be re-alerted?
	if(skb == NULL)
	{
		// UNRESOLVED!? Just retransmit the acknowledgement...
		return;
	}

	HandleMobileParam(pHdr->PFirstExtHeader());
	// no more extension header expected for RESUME

	if(InState(PRE_CLOSED) || InState(CLOSED))
		OnResurrect();
	else
		OnResume();

	int r = PlacePayload(skb);
	if (r == -EFAULT)
	{
		TRACE_HERE("cannot place optional payload in the RESUME packet");
		return;
	}

	tLastRecv = NowUTC();	// tLastRecv should not be modified? UNRESOLVED!

	// UNRESOLVED! should signal to resume the connection...
	SignalEvent();
}



// RELEASE, no payload but consuming sequence space to fight back play - back DoS attack(via ValidateICC())
//	tLastRecv is not modified
// CLOSABLE-->/RELEASE/-->CLOSED-->[Notify]
// CLOSED-->/RELEASE/-->[Send ACK_FLUSH]
// PEER_COMMIT-->/RELEASE/ [Send ACK_FLUSH]-->CLOSED-->[Notify]
// {COMMITTING2, PRE_CLOSED}-->/RELEASE/
//    -->{stop keep-alive}CLOSED-->[Send ACK_FLUSH]-->[Notify]
void CSocketItemEx::OnGetRelease()
{
	TRACE_SOCKET();
	if (!InStates(5, PEER_COMMIT, COMMITTING2, CLOSABLE, PRE_CLOSED, CLOSED))
		return;

	if (headPacket->lenData != 0)
		return;

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		return;

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	if(InState(CLOSED))
	{
		SendSNACK();
		return;
	}

	if(InState(COMMITTING2) || InState(PRE_CLOSED))
		StopKeepAlive();

	if(! InState(CLOSABLE)) //  InState(PEER_COMMIT, COMMITTING2, PRE_CLOSED)
		SendSNACK();

	SetState(CLOSED);
	Notify(FSP_NotifyFinish);
	(CLowerInterface::Singleton())->FreeItem(this);
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|<-->/MULTIPLY/{duplication detected: retransmit acknowledgement}
//	|<-->/MULTIPLY/{collision detected}[Send RESET]
//	|-->/MULTIPLY/-->[API{Callback}]
//	{COMMITTING, RESUMING, CLOSABLE}<-->/MULTIPLY/[Send RESET]
// Remark
//	It is assumed that ULA/DLL implements connection multiplication throttle control
void CSocketItemEx::OnGetMultiply()
{
	TRACE_SOCKET();

	if (!InStates(6, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE))
		return;

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		return;

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

//连接复制（！）的应答方每收到一个MULTIPLY报文，即应检查其连接复用报头中所传递的复用发起方新连接Session ID，
//如果和与相同主机所建立的任何连接的远端Session ID相同，则认为是重复的MULTIPLY报文，
//这时应在新连接的上下文中，根据新连接的当前状态，重传PERSIST或COMMIT报文；否则即认为是新一次的连接复用请求。
//实现上可使用针对远端Session ID与local root Session ID联立的hash table来排查重复的MULTIPLY请求，
//也可以使用树结构来串接“相同主机”的连接上下文方式。
//原始侦听者不是树根，而是森林种子。每次Accept时新建的连接的本地Session ID，才是上述local root Session ID。
	// ControlBlock::seq_t ackSeqNo = be32toh(pkt.expectedSN);
	// if(! pSocket->IsValidExpectedSN(ackSeqNo)) return;
	// pSocket->pControlBlock->sendWindowSize
	//	= min(pSocket->pControlBlock->sendBufferBlockN, be16toh(pkt.recvWS));
	// See also OnConnectRequest()
	// TODO: UNRESOLVED! if it return -EEXIST, should ULA be re-alerted?
	// MULTIPLY is ALWAYS an out-of-band control packet !?

	// it is possible that new local fiber ID collided with some other session, but it does not matter (?)

	// TODO: parse the multiplication optional header
	HandleMobileParam(headPacket->GetHeaderFSP()->PFirstExtHeader());
	// no more extension header expected for MULTIPLY

	OnMultiply();	// tLastRecv = NowUTC()?
	SignalEvent();
}


// Given
//	ControlBlock::PFSP_SocketBuf	the descriptor of the buffer block to hold the payload
// Return
//	>= 0	number of bytes placed on success
//	-EEXIST on packet already received
//	-EFAULT	on memory fault
int LOCALAPI CSocketItemEx::PlacePayload(ControlBlock::PFSP_SocketBuf skb)
{
#ifdef TRACE_PACKET
	printf_s("Place %d payload bytes to 0x%08X (duplicated: %d)\n"
		, headPacket->lenData
		, (LONG)skb
		, skb == 0 ? 0 : (int)skb->GetFlag<IS_DELIVERED>());
#endif
	//UNRESOLVE!? TODO: warning the system administrator that possibly there is network intrusion?
	if (!CheckMemoryBorder(skb))
		return -EFAULT;

	if(skb->GetFlag<IS_FULFILLED>())
		return -EEXIST;

	FSP_NormalPacketHeader *pHdr = headPacket->GetHeaderFSP();
	if(headPacket->lenData > 0)
	{
		BYTE *ubuf = GetRecvPtr(skb);
		if(ubuf == NULL)
		{
			HandleMemoryCorruption();
			return -EFAULT;
		}
		memcpy(ubuf, (BYTE *)pHdr + be16toh(pHdr->hs.hsp), headPacket->lenData);
		skb->SetFlag<TO_BE_CONTINUED>((pHdr->GetFlag<ToBeContinued>() != 0) && (skb->opCode != COMMIT));
	}
	skb->version = pHdr->hs.version;
	skb->opCode = pHdr->hs.opCode;
	skb->len = headPacket->lenData;
	skb->SetFlag<IS_FULFILLED>();

	return headPacket->lenData;
}
