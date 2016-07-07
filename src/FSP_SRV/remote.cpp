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


// 'Package' internal use only
struct _CookieMaterial
{
	uint32_t	salt;
	ALFID_T	idALF;
	ALFID_T	idListener;
};



#if defined(TRACE) && (TRACE & TRACE_HEARTBEAT) && (TRACE & TRACE_PACKET)
#define TRACE_SOCKET()	\
	(printf_s("%s local fiber#0x%X in state %s\n", __FUNCTION__	\
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



bool CSocketItemEx::Notify(FSP_ServiceCode n)
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
		if(r == FSP_MAX_NUM_NOTICE)
			printf_s("\nSession #%u, duplicate soft interrupt %s(%d) eliminated.\n", fidPair.source, noticeNames[n], n);
		else
			printf_s("\nSession #%u append soft interrupt %s(%d)\n", fidPair.source, noticeNames[n], n);
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

	if(! pSocket->InState(CONNECT_BOOTSTRAP))
		goto l_return;

	if(initState.initCheckCode != pkt->initCheckCode)
		goto l_return;

	// TODO: UNRESOLVED!? get resource reservation requirement from IPv6 extension header
	pSocket->SetRemoteFiberID(initState.idRemote = this->GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multihome it is necessary even for IPv6
	pSocket->SetNearEndInfo(nearInfo);
	// UNRESOLVED!? To check: the remote peer should register its own interface that made the connection in the backlog

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
//	|-->[{return}Reject]-->[Send RESET]{abort creating new context}
//CLOSED-->/CONNECT_REQUEST/-->[API{callback}]
//	|-->[{return}Accept]-->CHALLENGING-->[Send ACK_CONNECT_REQ]
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
		memcpy(&backlogItem.acceptAddr, &pHdr->u, sizeof(FSP_SINKINF));
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
	backlogItem.remoteHostID = nearInfo.IsIPv6() ? SOCKADDR_HOSTID(mesgInfo.name) : 0;
	//^See also GetRemoteFiberID()
	backlogItem.idParent = 0;
	rand_w32(& backlogItem.initialSN, 1);
	backlogItem.expectedSN = be32toh(q->initialSN);	// CONNECT_REQUEST does NOT consume a sequence number

	assert(sizeof(backlogItem.allowedPrefixes) == sizeof(q->params.subnets));
	memcpy(backlogItem.allowedPrefixes, q->params.subnets, sizeof(uint64_t) * MAX_PHY_INTERFACES);

	// lastly, put it into the backlog
	if (pSocket->pControlBlock->backLog.Put(&backlogItem) < 0)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("Cannot put the multiplying connection request into the SCB backlog.\n");
#endif
		goto l_return;
	}
	pSocket->SignalAccepting();

l_return:
	pSocket->SetReady();
}



//{CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, CHALLENGING, ACTIVE,
// COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE,
// PRE_CLOSED, CLONING}-->/RESET/
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
		// otherwise simply ignore
	}
	else if(pSocket->InState(CONNECT_AFFIRMING))
	{
		if(reject.u.timeStamp == pSocket->pControlBlock->connectParams.nboTimeStamp
		&& reject.u2.cookie == pSocket->pControlBlock->connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if(pSocket->InState(CHALLENGING))
	{
		if(reject.u.sn.initial == htobe32(pSocket->pControlBlock->connectParams.initialSN)
		&& reject.u2.cookie == pSocket->pControlBlock->connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
		// otherwise simply ignore
	}
	else if(! pSocket->InState(LISTENING) && ! pSocket->InState(CLOSED))
	{
		if(pSocket->IsValidSequence(be32toh(reject.u.sn.initial))
		&& pSocket->ValidateICC((FSP_NormalPacketHeader *) & reject))
		{
			pSocket->DisposeOnReset();
		}
		// otherwise simply ignore.
	}
	// InStates ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED, CLONING
	// besides, those states are recoverable.
	// LISTENING state is not affected by reset signal
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
	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("%s has encountered attack? sequence number: %u\n\tshould in: [%u %u]\n"
			, opCodeStrings[p1->hs.opCode]
			, headPacket->pktSeqNo
			, pControlBlock->recvWindowFirstSN
			, pControlBlock->recvWindowFirstSN +  pControlBlock->recvBufferBlockN
			);
		DebugBreak();
#endif
		return false;
	}

	int32_t offset = be16toh(p1->hs.hsp);	// For the KEEP_ALIVE/ACK_FLUSH it is the packet length as well
	FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)((uint8_t *)p1 + offset - sizeof(FSP_SelectiveNACK));
	uint32_t salt = pSNACK->serialNo;
	uint32_t sn = be32toh(salt);

	if(int(sn - lastOOBSN) <= 0)
	{
#ifdef TRACE
		printf_s("%s has encountered replay attack? sequence number: %u\t%u\n", opCodeStrings[p1->hs.opCode], headPacket->pktSeqNo, sn);
#endif
		return false;
	}
	lastOOBSN = sn;

#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s data length: %d, header length: %d, peer ALFID = 0x%X\n"
		, opCodeStrings[p1->hs.opCode]
		, headPacket->lenData
		, offset
		, fidPair.peer);
	DumpNetworkUInt16((uint16_t *)p1, offset / 2);
#endif

	//if(! ValidateICC(p1, offset - sizeof(FSP_NormalPacketHeader), salt))	// No! Extension header is not encrypted!
	if(! ValidateICC(p1, 0, salt))	// No! Extension header is not encrypted!
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

	gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *)pSNACK - n);
	if(n == 0)
		return true;

	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
#if defined(TRACE) && (TRACE & (TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("%s has %d gap(s), sequence number: %u\t%u\n", opCodeStrings[p1->hs.opCode], n, headPacket->pktSeqNo, sn);
#endif
	return true;
}



// Remark
//	CONNECT_AFFIRMING-->/ACK_CONNECT_REQ/-->[API{callback}]
//		|-->{Return Accept}-->PEER_COMMIT-->[Send PERSIST]{start keep-alive}
//		|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
// See also {FSP_DLL}CSocketItemDl::ToConcludeConnect()
void CSocketItemEx::OnConnectRequestAck(FSP_AckConnectRequest & response, int lenData)
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

#if defined(TRACE) && (TRACE & TRACE_HEARTBEAT)
	TRACE_HERE("the initiator recalculate RTT");
	//DumpTimerInfo(tLastRecv);
#endif
	// OS time-slice, if any, might somewhat affect calculating of RTT. But it can be igored for large BDP pipe
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, (tRoundTrip_us + (tSessionBegin - tRecentSend) + 1) >> 1);
	tKeepAlive_ms = KEEP_ALIVE_TIMEOUT_ms;	// instead of CONNECT_INITIATION_TIMEOUT_ms

	SignalAccepted();	// The initiator may cancel data transmission, however
	TRACE_HERE("finally the connection request is accepted by the remote end");
}



//PERSIST is the acknowledgement to ACK_CONNECT_REQ or MULTIPLY, and/or start a new transmit transaction
//	CHALLENGING-->/PERSIST/-->COMMITTED{start keep-alive}-->[Notify]
//	ESTABLISHED-->/PERSIST/-->{KEEP_ALIVE}{keep state}
//	PEER_COMMIT-->/PERSIST/-->ACTIVE{restart keep-alive}
//	COMMITTING2-->/PERSIST/-->COMMITTING
//	COMMITTED-->/PERSIST/-->{KEEP_ALIVE}
//	CLOSABLE-->/PERSIST/-->COMMITTED{restart keep_alive}{KEEP_ALIVE}
//  CLONING-->/PERSIST/-->ACTIVE-->{KEEP_ALIVE}
// Remark
//	PERSIST is instantly acknowledged to avoid possible dead-lock. See also KeepAlive()
void CSocketItemEx::OnGetPersist()
{
	TRACE_SOCKET();
	if (!InStates(8, CHALLENGING, ESTABLISHED, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, CLONING))
		return;

	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
	{
#ifdef TRACE
		printf_s("Invalid payload length: %d\n", headPacket->lenData);
#endif
		return;
	}

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	if (lowState != CLONING)	// the normality
	{
		if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		{
#ifdef TRACE
			printf_s("@%s: Invalid sequence number:\t %u\n", __FUNCTION__, headPacket->pktSeqNo);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			return;
		}
		//
		if (!ValidateICC())
		{
			TRACE_HERE("Invalid intergrity check code!?");
			return;
		}
	}
	else if(! FinalizeMultiply())	// if (lowState == CLONING)
	{
		TRACE_HERE("Invalid intergrity check code of COMMIT to MULTIPLY!?");
		return;
	}

	// A duplicated, normally resent, PERSIST should be acknowledged instantly
	if (InState(ESTABLISHED))
	{
		SendKeepAlive();
		return;
	}

	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!ResizeSendWindow(ackSeqNo, p1->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("Cannot resize send window. Acknowledged sequence number: %u\n", ackSeqNo);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return;
	}

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	// PERSIST is always the accumulative acknowledgement to ACK_CONNECT_REQ or MULTIPLY
	// ULA slide the receive window, no matter whether the packet has payload
	if(isInitiativeState)
	{
		tSessionBegin = tRecentSend;
#ifdef TRACE
		printf_s("\nPERSIST received. Acknowledged SN\t = %u\n", ackSeqNo);
#endif
		pControlBlock->SlideSendWindowByOne();	// See also RespondToSNACK, OnGetCommit
	}

#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	TRACE_HERE("the responder calculate RTT");
#endif
	CalibrateRTT();

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

	if(pControlBlock->HasBeenCommitted() > 0)
	{
		if (lowState == CHALLENGING)
		{
			SetState(CLOSABLE);
		}
		else if (lowState == COMMITTING)
		{
			SetState(COMMITTING2);
		}
		else if (lowState == COMMITTED)
		{
			StopKeepAlive();
			SetState(CLOSABLE);
		}
		else // if (InStates(CLONING))
		{
			StopKeepAlive();
			SetState(PEER_COMMIT);
		}
		SendAckFlush();
	}
	else
	{
		if (lowState == CHALLENGING)
		{
			SetState(COMMITTED);
			RestartKeepAlive();
		}
		else if (lowState == PEER_COMMIT)
		{
			SetState(ESTABLISHED);
			RestartKeepAlive();
		}
		else if (lowState == COMMITTING2)
		{
			SetState(COMMITTING);
		}
		else if (lowState == CLOSABLE)
		{
			SetState(COMMITTED);
			RestartKeepAlive();
		}
		else // if (InStates(CLONING))
		{
			SetState(ESTABLISHED);
		}
		// It might be redundant, but make the protocol robust
		AddLazyAckTimer();
	}

	if (countPlaced == -EEXIST)
		return;

#if defined(TRACE) && (TRACE & TRACE_PACKET)
	if (countPlaced > 0)
		printf_s("There is optional payload in the PERSIST packet, payload length = %d\n", countPlaced);
#endif
	if (isInitiativeState)
		SignalAccepted();
}



// KEEP_ALIVE is out-of-band and may carry a special optional header for multi-homed mobility support
//	{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2}-->/KEEP_ALIVE/
//		<-->{keep state}[Retransmit selectively]
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
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Fiber#0x%X: SNACK packet with %d gap(s) advertised received\n", fidPair.source, n);
#endif
	if(acknowledgible && RespondToSNACK(ackSeqNo, gaps, n) > 0)
		Notify(FSP_NotifyBufferReady);
	
	PFSP_HeaderSignature phs = headPacket->GetHeaderFSP()->PHeaderNextTo<FSP_SelectiveNACK>(& gaps[n]);
	if(phs != NULL)
		HandlePeerSubnets(phs);
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
//CLONING<-->/PURE_DATA/{just prebuffer}
// However ULA protocol designer must keep in mind that these prebuffered may be discarded
void CSocketItemEx::OnGetPureData()
{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	TRACE_SOCKET();
#endif
	if (!InStates(4, ESTABLISHED, COMMITTING, COMMITTED, CLONING))
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
		printf_s("@%s: Invalid sequence number:\t %u\n", __FUNCTION__, headPacket->pktSeqNo);
#endif
		return;
	}

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);	
	if (!ResizeSendWindow(ackSeqNo, p1->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("An out of order acknowledgement? seq#%u\n",ackSeqNo);
#endif
		return;
	}

	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	// It is less efficient than signaling an 'interrupt' only when the head packet of a gap in the receive window is received
	// However, we may safely assume that out-of-order packets are of low ratior and it does not make too much overload
	// It is definitely less efficient than polling for 'very' high throughput network application
	int r = PlacePayload(skb);
#if defined(_DEBUG) && defined(TRACE)
	if(r == 0)
	{
		printf_s("Either a PURE_DATA does not carry payload or the payload it is not stored safely\n");
		return;
	}
	if(r == -EEXIST)
	{
		printf_s("A retransmitted PURE_DATA is simply ignored.\n");
		return;
	}
	if(r < 0)
	{
		printf_s("Fatal error when place payload, error number = %d\n", r);
		return;
	}
#else
	if(r <= 0)
		return;
#endif

	tLastRecv = NowUTC();

	if(pControlBlock->HasBeenCommitted() > 0)
	{
		if (lowState == COMMITTING)
		{
			SetState(COMMITTING2);
		}
		else if (lowState == COMMITTED)
		{
			StopKeepAlive();
			SetState(CLOSABLE);
		}
		else // if (InStates(ESTABLISHED, CLONING))
		{
			StopKeepAlive();
			SetState(PEER_COMMIT);
		}
		SendAckFlush();
	}
	else
	{
		AddLazyAckTimer();
	}
	// See also OnGetPersist()

	Notify(FSP_NotifyDataReady);
}


//CHALLENGING-->/COMMIT/
//	|-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
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
//PRE_CLOSED<-->/COMMIT/[Retransmit ACK_FLUSH, as in the CLOSABLE state]
//{PEER_COMMIT, COMMITTING2, CLOSABLE}<-->/COMMIT/[Send ACK_FLUSH]
//CLONING<-->/COMMIT/{if the receive queue is closable}
//		-->{stop keep-alive}PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
// UNRESOLVED! fairness of adjourn? Anti-DoS-Attack?
void CSocketItemEx::OnGetCommit()
{
	TRACE_SOCKET();

	if (!InStates(9, CHALLENGING, CLONING
		, ESTABLISHED, COMMITTING, COMMITTED, PEER_COMMIT, COMMITTING2, CLOSABLE, PRE_CLOSED))
	{
		return;
	}

	// As calculate ICC may consume CPU resource intensively we are relunctant to send RESET

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	// check the ICC at first, silently discard the packet if ICC check failed
	// preliminary check of sequence numbers [they are IV on calculating ICC]
	// UNRESOLVED!? Taking the risk of DoS attack by replayed COMMIT...
	// TODO: throttle the rate of processing COMMIT by 'early dropping'
	if (lowState != CLONING)	// the normality
	{
		if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		{
#ifdef TRACE
			printf_s("@%s: Invalid sequence number:\t %u\n", __FUNCTION__, headPacket->pktSeqNo);
			//printf_s("IsRetriableStale check sequence number:\t %u\n", headPacket->pktSeqNo);
#endif
			return;
		}
		if (!ValidateICC())
		{
			TRACE_HERE("Invalid intergrity check code!?");
			return;
		}
	}
	else if(! FinalizeMultiply())	// if (lowState == CLONING)
	{
		TRACE_HERE("Invalid intergrity check code of COMMIT to MULTIPLY!?");
		return;
	}

	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	if (!ResizeSendWindow(ackSeqNo, p1->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("An out of order acknowledgement on COMMIT? seq#%u\n", ackSeqNo);
		pControlBlock->DumpSendRecvWindowInfo();
#endif
		return;
	}

	// figure out whether it was in any initiative state before migration
	// See also OnGetPersist()
	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	if (isInitiativeState)
		tSessionBegin = tRecentSend;	// but only slide the send window when it is a singleton commit as well

#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	TRACE_HERE("the responder calculate RTT");
#endif
	CalibrateRTT();

	// Unlike PURE_DATA, a retransmitted COMMIT cannot be silent discarded
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(headPacket->pktSeqNo);
	// Just retransmit ACK_FLUSH on duplicated COMMIT command
	if (skb == NULL || InStates(4, PEER_COMMIT, COMMITTING2, CLOSABLE, PRE_CLOSED))
	{
#ifdef TRACE
		printf_s("Duplicate COMMIT received in %s state\n", stateNames[lowState]);
#endif
		SendAckFlush();
		return;
	}
	// but it is well known if PlayPayload return < 0 it is either -EFAULT or -EEXIST
	int r = PlacePayload(skb);
	if (r == -EFAULT)	// r < 0 && r != -EEXIST
	{
		TRACE_HERE("cannot place optional payload in the COMMIT packet");
		return;
	}

	if(pControlBlock->HasBeenCommitted() > 0)
	{
		if (lowState == CHALLENGING)
		{
			SetState(CLOSABLE);
		}
		else if (lowState == COMMITTING)
		{
			SetState(COMMITTING2);
		}
		else if (lowState == COMMITTED)
		{
			StopKeepAlive();
			SetState(CLOSABLE);
		}
		else // if (InStates(ESTABLISHED, CLONING))
		{
			StopKeepAlive();
			SetState(PEER_COMMIT);
		}
		//
		if(isInitiativeState)
		{
#ifdef TRACE
			printf_s("\nCOMMIT received. Acknowledged SN\t = %u\n", ackSeqNo);
#endif
			pControlBlock->SlideSendWindowByOne();
		}
		// MUST slide the send window BEFORE SendSNACK or else the sequence number of ACK_FLUSH or KEEP_ALIVE is wrong
		SendAckFlush();
		//
		if(isInitiativeState)
		{
			SignalAccepted();
			return;
		}
	}

	Notify(FSP_NotifyToCommit);
}



// ACK_FLUSH, now a pure out-of-band control packet. A special norm of KEEP_ALIVE
//	COMMITTING-->/ACK_FLUSH/-->COMMITTED-->[Notify]
//	COMMITTING2-->/ACK_FLUSH/-->{stop keep-alive}CLOSABLE-->[Notify]
void CSocketItemEx::OnAckFlush()
{
	// As ACK_FLUSH is rare we trace every appearance
	TRACE_SOCKET();

	if (!InState(COMMITTING) && !InState(COMMITTING2))
		return;

	FSP_SelectiveNACK::GapDescriptor *gaps;
	int n;
	ControlBlock::seq_t ackSeqNo;
	if(!ValidateSNACK(ackSeqNo, gaps, n))
		return;
#ifndef NDEBUG
	if(n != 0)
	{
		TRACE_HERE("ACK_FLUSH should carry accumulatively positively acknowledge only");
		return;
	}
#endif

	tLastRecv = NowUTC();

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



// RELEASE, no payload but consuming sequence space to fight back play - back DoS attack(via ValidateICC())
//	tLastRecv is not modified
// CLOSABLE-->/RELEASE/-->CLOSED-->[Send RELEASE]-->[Notify]
// {COMMITTING2, PRE_CLOSED}-->/RELEASE/
//    -->{stop keep-alive}CLOSED-->[Send RELEASE]-->[Notify]
// Because duplicate RELEASE might be received AFTER the control block has been released already, do not TRACE_PACKET before check state
void CSocketItemEx::OnGetRelease()
{
	if (!InState(COMMITTING2) && !InState(CLOSABLE) && !InState(PRE_CLOSED))
		return;
	TRACE_SOCKET();

	if (headPacket->lenData != 0)
		return;

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		return;

	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	RespondToSNACK(ackSeqNo, NULL, 0);

	if(InState(COMMITTING2))
		StopKeepAlive();

	// There used to be 'connection resurrection'; might send redundant RELEASE, but it makes robustness
	_InterlockedExchange8((char *)& pControlBlock->state, CLOSED);
	SendPacket<RELEASE>();
	Notify(FSP_NotifyToFinish);

	Destroy();	// LLS 
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED, CLOSED}
//	|<-->/MULTIPLY/{duplication detected: retransmit acknowledgement}
//	|<-->/MULTIPLY/{collision detected}[Send RESET]
//	|-->/MULTIPLY/-->[API{Callback}]
//	{COMMITTING, CLOSABLE}<-->/MULTIPLY/[Send RESET]
// Remark
//	It is assumed that ULA/DLL implements connection multiplication throttle control
//	See also OnGetConnectRequest()
void CSocketItemEx::OnGetMultiply()
{
	TRACE_SOCKET();

	if (!InStates(8, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, PRE_CLOSED, CLOSED))
		return;

	if (pControlBlock->IsRetriableStale(headPacket->pktSeqNo))
		return;

	FSP_NormalPacketHeader *pFH = (FSP_NormalPacketHeader *)headPacket->GetHeaderFSP();	// the fixed header
	ALFID_T idSource = headPacket->idPair.source;
	// The out-of-band serial number is stored in p1->expectedSN
	if (!ValidateICC(pFH, headPacket->lenData, idSource, pFH->expectedSN))
	{
		TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	// The request is already put into the multiplication backlog
	if (CMultiplyBacklog::Find(fidPair.source, idSource) != NULL)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("Duplicate connection multiplication request.\n");
#endif
		return;
	}

	// Check whether it is a collision!?
	CSocketItemEx *pSocket = CLowerInterface::Singleton()->FindSocket(pControlBlock->connectParams.remoteHostID, idSource, fidPair.source);
	if (pSocket != NULL && pSocket->IsInUse())
	{
		if (pSocket->lowState == COMMITTING || pSocket->lowState == ESTABLISHED)
			pSocket->EmitStart();
		//
		return;
	}

	// See also CLowerInterface::OnGetInitConnect
	CSocketItemEx * newSlot = CLowerInterface::Singleton()->AllocItem();
	if(newSlot == NULL)
	{
		TRACE_HERE("Cannot allocate new socket slot for multiplication");
		return;		// for security reason silently the exception
	}

	BackLogItem backlogItem;	// Inherit the session key of its parent
	(SConnectParam &)backlogItem = pControlBlock->connectParams;
	backlogItem.idRemote = idSource;
	rand_w32(&backlogItem.initialSN, 1);
	if (pSocket->pControlBlock->backLog.Has(&backlogItem))
	{
		TRACE_HERE("Duplicate MULTIPLY backlogged already");
l_bailout:
		CLowerInterface::Singleton()->FreeItem(newSlot);
		return;
	}

	CMultiplyBacklogItem *pMItem = CMultiplyBacklog::Alloc(fidPair.source, idSource, headPacket->pktSeqNo, pFH->expectedSN);
	if (pMItem == NULL)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("Cannot put the connection multiplication request into the system backlog.\n");
#endif

		goto l_bailout;
	}

	backlogItem.expectedSN = headPacket->pktSeqNo;
	backlogItem.idParent = fidPair.source;
	backlogItem.acceptAddr = pControlBlock->nearEndInfo;
	backlogItem.acceptAddr.idALF = newSlot->fidPair.source;

	// lastly, put it into the backlog
	if (pSocket->pControlBlock->backLog.Put(&backlogItem) < 0)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("Cannot put the multiplying connection request into the SCB backlog.\n");
#endif
		CMultiplyBacklog::Free(pMItem);
		goto l_bailout;
	}

	// place payload into the backlog, see also placepayload
	pMItem->lenData = headPacket->lenData;
	if (headPacket->lenData > 0)
	{
		memcpy(pMItem->plainText, (BYTE *)pFH + be16toh(pFH->hs.hsp), headPacket->lenData);
		pMItem->isEOM = (pFH->GetFlag<ToBeContinued>() != 0);
	}

	newSlot->contextOfICC = contextOfICC;
	newSlot->tKeepAlive_ms = TRASIENT_STATE_TIMEOUT_ms;
	newSlot->lowState = NON_EXISTENT;	// so that when timeout it is scavenged
	newSlot->AddTimer();

	SignalAccepting();
}


// Given
//	ControlBlock::PFSP_SocketBuf	the descriptor of the buffer block to hold the payload
// Return
//	>= 0	number of bytes placed on success
//	-EEXIST on packet already received
//	-EFAULT	on memory fault
int LOCALAPI CSocketItemEx::PlacePayload(ControlBlock::PFSP_SocketBuf skb)
{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Place %d payload bytes to 0x%08X (duplicated: %d)\n"
		, headPacket->lenData
		, (LONG)(UINT_PTR)skb
		, skb == NULL ? 0 : (int)skb->GetFlag<IS_DELIVERED>());
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
