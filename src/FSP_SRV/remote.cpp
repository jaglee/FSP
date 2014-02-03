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
	printf_s("%s session#%u in state %s\n"	\
		"\tSend head - tail = %d - %d, recv head - tail = %d - %d\n"	\
		, __FUNCTION__	\
		, pairSessionID.source		\
		, stateNames[lowState]				\
		, pControlBlock->sendWindowHeadPos	\
		, pControlBlock->sendBufferNextPos	\
		, pControlBlock->recvWindowHeadPos	\
		, pControlBlock->recvWindowNextPos)
#else
#define TRACE_SOCKET()
#endif

static const char READY_FOR_USE[2] = { 1, 1 };
static const char NOT_READY_USE[2] = { 1, 0 };


inline
bool CSocketItemEx::InStates(int n, ...)
{
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



// It is assumed that inUse and isReady are stored compactly (octet by octet)
inline
bool CSocketItemEx::TestAndLockReady()
{
	return _InterlockedCompareExchange16((SHORT *) & inUse
		, *(SHORT *)NOT_READY_USE
		, *(SHORT *)READY_FOR_USE) == *(SHORT *)READY_FOR_USE; 
}



inline
bool LOCALAPI CSocketItemEx::IsValidSequence(ControlBlock::seq_t seq1)
{
	int d = int(seq1 - pControlBlock->recvWindowFirstSN);
	// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
	return (0 <= d) && (d < pControlBlock->recvBufferBlockN);
}



inline
bool CSocketItemEx::Notify(FSP_ServiceCode n)
{
	int r = pControlBlock->PushNotice(n);
	if(r == 0)
	{
		SignalEvent();
#ifdef TRACE
		printf_s("\nSession #%u raise soft interrupt %d\n", pairSessionID.source, n);
#endif
	}
	return (r >= 0);
}



// Do
//  Allocate a new Session ID randomly there might be collision in a high-load responder
//	ACK_INIT_CONNECT, Cookie, initiator's check code echo, time difference
//		or
//	RESET, Timestamp echo, initiator's check code echo, reason
// Remark
//	LISTENING
//	|<-->[Rcv: INIT_CONNECT && {resource available}: Snd ACK_INIT_CONNECT]
//	|<-->[Rcv: INIT_CONNECT && {resource unavailable}: Snd RESET]
void LOCALAPI CLowerInterface::OnGetInitConnect()
{
	TRACE_HERE("called");

	// Silently discard connection request to blackhole, and avoid attacks alike 'port scan'
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL || ! pSocket->IsPassive() || ! pSocket->IsInUse())
		return;

	// control structure, specified the local address (the Application Layer Thread ID part)
	// echo back the message at the same interface of receiving, only ALT_ID changed

	ALT_ID_T	idSession;
	CtrlMsgHdr	hdrInfo;
	memset(&hdrInfo, 0, sizeof(CtrlMsgHdr));
	memcpy(&hdrInfo, sinkInfo.Control.buf, min(sinkInfo.Control.len, sizeof(hdrInfo)));
	if (hdrInfo.IsIPv6())
	{
		idSession = CLowerInterface::Singleton()->RandALT_ID((PIN6_ADDR) & hdrInfo.u);
	}
	else
	{
		idSession = CLowerInterface::Singleton()->RandALT_ID();
		hdrInfo.u.idALT = idSession;
	}

	// TODO: there should be some connection initiation throttle control in RandALT_ID
	// TODO: UNRESOLVED! admission-control here?
	if(idSession == 0)
	{
		SendPrematureReset(ENOENT);
		return;
	}

	// To make the FSP challenge of the responder	
	FSP_InitiateRequest & initRequest = *FSP_OperationHeader<FSP_InitiateRequest>();
	FSP_Challenge challenge;
	// the remote address is not changed
	timestamp_t t0 = ntohll(initRequest.timeStamp);
	timestamp_t t1 = NowUTC();
	struct _CookieMaterial cm;
	challenge.initCheckCode = initRequest.initCheckCode;
	cm.idALT = idSession;
	cm.idListener = GetLocalSessionID();
	// the cookie depends on the listening session ID AND the responding session ID
	cm.salt = initRequest.salt;
	challenge.cookie = CalculateCookie((BYTE *) & cm, sizeof(cm), t1);
	challenge.timeDelta = htonl((u_long)(t1 - t0));
	challenge.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	SetLocalSessionID(idSession);
	SendBack((char *) & challenge, sizeof(challenge));
}



// Do
//	Check the inititiator's cookie, make the formal connection request towards the responder
// Remark
//	CONNECT_BOOTSTRAP-->CONNECT_AFFIRMING
void LOCALAPI CLowerInterface::OnInitConnectAck()
{
	TRACE_HERE("called");

	//	find the socket item firstly
	FSP_Challenge & response = *FSP_OperationHeader<FSP_Challenge>();
	CSocketItemEx *pSocket = MapSocket();
	if(pSocket == NULL || ! pSocket->TestAndLockReady())
		return;

	SConnectParam & initState = pSocket->pControlBlock->u.connectParams;
	ALT_ID_T idListener = initState.idRemote;

	if(! pSocket->InState(CONNECT_BOOTSTRAP))
		goto l_return;

	if(initState.initCheckCode != response.initCheckCode)
		goto l_return;

	// TODO: UNRESOLVED!? get resource reservation requirement from IPv6 extension header
	pSocket->SetRemoteSessionID(initState.idRemote = GetRemoteSessionID());
	//^ set to new peer session ID: to support multihome it is necessary even for IPv6
	initState.timeDelta = ntohl(response.timeDelta);
	initState.cookie = response.cookie;
	EnumEffectiveAddresses(initState.allowedPrefixes);

	pSocket->AffirmConnect(initState, idListener);

l_return:
	pSocket->SetReady();
}



// prepare the backlog, fill in information of the remote session ID, the suggested local session ID
// list of remote address prefixes(for multihome support) and half-connection parameters
// the upper layer application will poll the backlog and setup the session context
// [into 'CHALLENGING'] (allocate state space, including data buffers, command queue, etc)
// it is tempting to acknowledge the connect request immediately to save some memory copy
// however, it is not justified, for throughput throttling is overriding
void LOCALAPI CLowerInterface::OnGetConnectRequest()
{
	TRACE_HERE("called");

	FSP_ConnectRequest & request = *FSP_OperationHeader<FSP_ConnectRequest>();
	CSocketItemEx *pSocket = MapSocket();

	// Check whether it is a collision
	if(pSocket != NULL && pSocket->IsInUse())
	{
		if(pSocket->pairSessionID.peer == this->GetRemoteSessionID()
		&& pSocket->pControlBlock->u.connectParams.cookie == request.cookie)
		{
			// retransmit ACK_CONNECT_REQUEST at the head of the send queue
			pSocket->Retransmit1();
			return;	// hitted
		}
		// Or else it is a collision and is silently discard in case an out-of-order RESET reset a legitimate connection
		// UNRESOLVED! Is this a unbeatable DoS attack to initiator if there is a 'man in the middle'?
		return;
	}

	// Silently discard the request onto illegal or non-listening socket 
	pSocket = (*this)[request.params.listenerID];	// a dialect of MapSocket
	if(pSocket == NULL || ! pSocket->TestAndLockReady())
		return;

	if(! pSocket->IsPassive())
		goto l_return;

	// cf. OnInitConnectAck() and SocketItemEx::AffirmConnect()
	ALT_ID_T idSession = GetLocalSessionID();
	struct _CookieMaterial cm;
	cm.idALT = idSession;
	cm.idListener = request.params.listenerID;
	cm.salt = request.salt;
	// UNRESOLVED! TODO: search the cookie blacklist at first
	if(request.cookie != CalculateCookie((BYTE *) & cm
			, sizeof(cm)
			, ntohll(request.timeStamp) + ntohl(request.timeDelta)) )
	{
		// UNRESOLVED! TODO: put the cookie into the blacklist to fight against DDoS attack
		goto l_return;	// the packet has been updated and should be discarded
	}

	// secondly, fill in the backlog item if it is new
	CtrlMsgHdr * const pHdr = (CtrlMsgHdr *)sinkInfo.Control.buf;
	BackLogItem backlogItem;
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
		fspAddr->idALT = idSession;
		backlogItem.acceptAddr.ipi6_ifindex = pHdr->u.ipi_ifindex;
	}
	backlogItem.salt = request.salt;
	backlogItem.remoteHostID = nearInfo.IsIPv6() ? SOCKADDR_HOST_ID(sinkInfo.name) : 0;
	//^See also GetRemoteSessionID()
	backlogItem.idRemote = GetRemoteSessionID();
	backlogItem.idParent = 0;
	backlogItem.cookie = request.cookie;
	// Simply ignore the duplicated request
	if(pSocket->pControlBlock->HasBacklog(& backlogItem))
		goto l_return;

	// Save public key of the remote end in the bootKey field of backlog temporarily
	// Thought the field will be overwritten
	memcpy(backlogItem.bootKey, request.public_n, FSP_PUBLIC_KEY_LEN);
	rand_w32(& backlogItem.initialSN, 1);
	backlogItem.delayLimit = ntohl(request.params.delayLimit);
	backlogItem.expectedSN = ntohl(request.params.initialSN);	// CONNECT_REQUEST does NOT consume a sequence number

	assert(sizeof(backlogItem.allowedPrefixes) == sizeof(request.params.subnets));
	memcpy(backlogItem.allowedPrefixes, request.params.subnets, sizeof(UINT64) * MAX_PHY_INTERFACES);

	// lastly, put it into the backlog
	pSocket->pControlBlock->PushBacklog(& backlogItem);
	pSocket->SignalEvent();

l_return:
	pSocket->SetReady();
}



// Remark
//	{CONNECT_BOOTSTRAP, CHALLENGING, CONNECT_AFFIRMING, QUASI_ACTIVE,
//	 CLONING, ACTIVE, PAUSING, RESUMING, CLOSABLE}-->NON_EXISTENT
//	{NON_EXISTENT, CLOSED, Otherwise}<-->{Ignore}
//	Doesn't actually reset the state to NON_EXISTENT in LLS
//	let DLL handle it so that ULA may know the reason of disconnection
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
		if(reject.u.timeStamp == htonll(pSocket->pControlBlock->u.connectParams.timeStamp)
		&& reject.u2.initCheckCode == pSocket->pControlBlock->u.connectParams.initCheckCode)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InState(CONNECT_AFFIRMING))
	{
		if(reject.u.timeStamp == htonll(pSocket->pControlBlock->u.connectParams.timeStamp)
		&& reject.u2.cookie == pSocket->pControlBlock->u.connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InState(CHALLENGING))
	{
		if(reject.u.sn.initial == htonl(pSocket->pControlBlock->u.connectParams.initialSN)
		&& reject.u2.cookie == pSocket->pControlBlock->u.connectParams.cookie)
		{
			pSocket->DisposeOnReset();
		}
	}
	else if(pSocket->InStates(6, ESTABLISHED, PAUSING, RESUMING, CLONING, QUASI_ACTIVE, CLOSABLE))
	{
		// besides, those states are recoverable.
		if(pSocket->IsValidSequence(ntohl(reject.u.sn.initial))
		&& pSocket->ValidateICC((FSP_NormalPacketHeader *) & reject))
		{
			pSocket->DisposeOnReset();
		}
	}
	// LISTENING state is not affected by reset signal
}



// Given
//	CSocketItemEx *	the pointer to the premature socket (default NULL)
//	UINT32			reason code flags of reset (default zero)
// Do
//	Send back the echoed reset at the same interface of receiving
//	in CHALLENGING, CONNECT_AFFIRMING, unresumable CLOSABLE and unrecoverable CLOSED state,
//	and of course, throttled LISTENING state
void LOCALAPI CLowerInterface::SendPrematureReset(UINT32 reasons, CSocketItemEx *pSocket)
{
	TRACE_HERE("called");

	struct FSP_RejectConnect reject;
	reject.reasons = reasons;
	reject.hs.Set<FSP_RejectConnect, RESET>();
	if(pSocket)
	{
		// In CHALLENGING, CONNECT_AFFIRMING where the peer address is known
		reject.u.timeStamp = htonll(NowUTC());
		// See also CSocketItemEx::Emit() and SetIntegrityCheckCode():
		reject.u2.sidPair = pSocket->pairSessionID;
		pSocket->wsaBuf[1].buf = (CHAR *) & reject;
		pSocket->wsaBuf[1].len = (ULONG)(sizeof(reject));
		pSocket->SendPacket(1);
	}
	else
	{
		BYTE *p = nearInfo.IsIPv6() ? HeaderFSP().headerContent : HeaderFSPoverUDP().headerContent;
		memcpy(& reject, p, sizeof(reject.u) + sizeof(reject.u2));
		SendBack((char *) & reject, sizeof(reject));
	}
}



void LOCALAPI CSocketItemEx::OnConnectRequestAck(FSP_AckConnectRequest & response, int lenData)
{
	TRACE_SOCKET();

	if(! InState(CONNECT_AFFIRMING))
		return;

	if(ntohl(response.expectedSN) != pControlBlock->sendWindowFirstSN)	// See also onGetConnectRequest
		return;

	// As we store the encrypted public key in the user memory space we must make sure there is enough memory
	if(lenData < 0 || lenData > MAX_BLOCK_SIZE - FSP_PUBLIC_KEY_LEN)
	{
		TRACE_HERE("TODO: debug memory corruption error");
		HandleMemoryCorruption();
		return;
	}

	tSessionBegin = tLastRecv = NowUTC();	// The packet was accepted

	// the officially annouced IP address of the responder shall be accepted by the initiator
	SConnectParam & rIPS = pControlBlock->u.connectParams;
	FSP_ConnectParam & varParams = response.params;

	memset(rIPS.allowedPrefixes, 0, sizeof(rIPS.allowedPrefixes));
	// assert(sizeof(rIPS.allowedPrefixes) >= sizeof(pVarParams->subnets));
	memcpy(rIPS.allowedPrefixes, varParams.subnets, sizeof(varParams.subnets));

	ControlBlock::seq_t pktSeqNo = ntohl(response.sequenceNo);
	pControlBlock->receiveMaxExpected	// would be increased on AllocRecvBuf()
		= pControlBlock->recvWindowFirstSN = pktSeqNo;
	pControlBlock->sendWindowSize
		= min(pControlBlock->sendBufferBlockN, response.GetRecvWS());

	// Put the payload (which might be empty) TOGETHER with the encrypted session key in the receive queue
	ControlBlock::PFSP_SocketBuf skb = AllocRecvBuf(pktSeqNo);
	BYTE *ubuf;
	if(skb == NULL || (ubuf = GetRecvPtr(skb)) == NULL)
	{
		TRACE_HERE("TODO: debug memory corruption error");
		HandleMemoryCorruption();
		return;
	}

	skb->len = lenData;
	if(lenData > 0)
		memcpy(ubuf, (BYTE *) & response + sizeof(response), lenData);
	memcpy(ubuf + lenData, response.encrypted, sizeof(response.encrypted));

	SignalEvent();
	TRACE_HERE("Trigger soft interrupt");

	// For calculating of RTT it is safely assume that internal processing takes orders of magnitude less time than network transmission
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, (tRoundTrip_us + (tSessionBegin - tRecentSend) + 1) >> 1);
	RemoveTimer();
	//^initiate the timer again only when PERSIST to be sent
}



// PERSIST is the acknowledgement to ACK_CONNECT_REQUEST, RESTORE or MULTIPLY
void CSocketItemEx::OnGetPersist()
{
	TRACE_SOCKET();
	FSP_Header_Manager hdrManager(& headPacket->pkt);

	if(! InStates(3, CHALLENGING, RESUMING, QUASI_ACTIVE))
		return;

	if (!IsValidSequence(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("Invalid sequence number: %u, expected: %u - %u\n"
			, headPacket->pktSeqNo
			, pControlBlock->recvWindowFirstSN
			, pControlBlock->recvWindowFirstSN + pControlBlock->recvBufferBlockN - 1);
#endif
		return;
	}
	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
	{
#ifdef TRACE
		printf_s("Invalid payload length: %d\n", headPacket->lenData);
#endif
		return;
	}

	if (!ValidateICC())
	{
#ifdef TRACE
		printf_s("Invalid intergrity check code!?\n");
#endif
		return;
	}

	// UNRESOLVED! TODO: split ResizeSendWindow? Merge it with 'Acknowledgement'?
	ControlBlock::seq_t ackSeqNo = ntohl(headPacket->pkt->expectedSN);
	if (! ResizeSendWindow(ackSeqNo, headPacket->pkt->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("Acknowledged sequence number: %u (expected: %u), should be in range %u - %u\n"
			, ackSeqNo
			, pControlBlock->sendWindowExpectedSN
			, pControlBlock->sendWindowFirstSN
			, pControlBlock->sendWindowNextSN);
#endif
		return;
	}

	int countPlaced = PlacePayload();
	if(countPlaced == -ENOMEM && headPacket->lenData > 0 || countPlaced == -EFAULT)
		return;

	// connection parameter may determine whether the payload is encrypted, however, let ULA handle it...
	PFSP_HeaderSignature optHdr = hdrManager.PopExtHeader<FSP_HeaderSignature>();

	//TODO: synchronization of ULA-triggered session key installation
	if(optHdr != NULL && optHdr->opCode == CONNECT_PARAM)
	{
		// the synchronization option header...
	}

#ifdef TRACE
	printf_s("To let ULA migrate from state %s to ESTABLISHED\n", stateNames[lowState]);
#endif
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, NowUTC() - tRecentSend);
	if (InState(CHALLENGING))
		tSessionBegin = tRecentSend;
	//^ session of a responsing socket start at the time ACK_CONNECT_REQUEST was sent
	// while the start time a resuming or resurrecting session remain the original (for sake of key life-cycle management)
	InitiateKeepAlive();
	if(countPlaced > 0)
	{
#ifdef TRACE
		printf_s("There is optional payload in the PERSIST packet, payload length = %d\n", countPlaced);
#endif
		pControlBlock->PushNotice(FSP_NotifyDataReady);
	}
	SignalEvent();
	return;
}



// KEEP_ALIVE is usually out-of-band and carrying some special optional headers
void CSocketItemEx::OnGetKeepAlive()
{
	TRACE_SOCKET();
	FSP_Header_Manager hdrManager(& headPacket->pkt);

	if(lowState != ESTABLISHED && lowState != PAUSING)
		return;

	// UNRESOLVED!? Taking the risk of DoS attack by replayed KEEP_ALIVE...
	if (!IsValidSequence(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("Invalid sequence number: %u, expected: %u - %u\n"
			, headPacket->pktSeqNo
			, pControlBlock->recvWindowFirstSN
			, pControlBlock->recvWindowFirstSN + pControlBlock->recvBufferBlockN - 1);
#endif
		return;
	}
	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
	{
#ifdef TRACE
		printf_s("Invalid payload length: %d\n", headPacket->lenData);
#endif
		return;
	}

	if (!ValidateICC())
	{
#ifdef TRACE
		printf_s("Invalid intergrity check code!?\n");
#endif
		return;
	}

	// UNRESOLVED! TODO: split ResizeSendWindow? Merge it with 'Acknowledgement'?
	ControlBlock::seq_t ackSeqNo = ntohl(headPacket->pkt->expectedSN);
	if (! ResizeSendWindow(ackSeqNo, headPacket->pkt->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("Acknowledged sequence number: %u (expected: %u), should be in range %u - %u\n"
			, ackSeqNo
			, pControlBlock->sendWindowExpectedSN
			, pControlBlock->sendWindowFirstSN
			, pControlBlock->sendWindowNextSN);
#endif
		return;
	}

	int countPlaced = PlacePayload();
	if(countPlaced == -ENOMEM && headPacket->lenData > 0 || countPlaced == -EFAULT)
		return;

	// connection parameter may determine whether the payload is encrypted, however, let ULA handle it...
	PFSP_HeaderSignature optHdr = hdrManager.PopExtHeader<FSP_HeaderSignature>();

	//TODO: synchronization of ULA-triggered session key installation
	if(optHdr != NULL && optHdr->opCode == CONNECT_PARAM)
	{
		// the synchronization option header...
	}

	// UNRESOLVED!? TODO: check expected SN BEFORE Validate ICC??
	// TODO: testability: output the SNACK structure
	if(optHdr != NULL && optHdr->opCode == SELECTIVE_NACK)
	{
		FSP_SelectiveNACK::GapDescriptor *gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *) & headPacket->pkt + ntohs(optHdr->hsp));
		FSP_SelectiveNACK *pHdr = (FSP_SelectiveNACK *)((BYTE *)optHdr + sizeof(*optHdr) - sizeof(*pHdr));
		int n = int((BYTE *)gaps - (BYTE *)pHdr);
		if(n < 0)
			return;		// this is a malformed packet. UNRESOLVED! Just silently discard it?

		n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
		if(pHdr->lastGap != 0)
			n++;
		for(register int i = n - 1; i >= 0; i--)
		{
			gaps[i].gapWidth = ntohs(gaps[i].gapWidth);
			gaps[i].dataLength = ntohs(gaps[i].dataLength);
		}
		if(RespondSNACK(ackSeqNo, gaps, n) < 0)
			return;
		optHdr = hdrManager.PopExtHeader<FSP_HeaderSignature>();
	}
	else
	{
		RespondSNACK(ackSeqNo, NULL, 0);	// in this case it is idempotent
	}

	if(countPlaced > 0)
	{
#ifdef TRACE
		printf_s("There is optional payload in the KEEP_ALIVE packet, payload length = %d\n", countPlaced);
#endif
		pControlBlock->PushNotice(FSP_NotifyDataReady);
	}
	//UNRESOLVED! TODO! only if there're really some
	Notify(FSP_NotifyBufferReady);

	EmitQ();
	// Send/resend further simultaneously

	// Resend: for FSP only on getting SNACK
	const ControlBlock::seq_t seqHead = pControlBlock->sendWindowFirstSN;
	const int32_t iHead = pControlBlock->sendWindowHeadPos;
	const int32_t capacity = pControlBlock->sendBufferBlockN;
	ControlBlock::PFSP_SocketBuf skb;
	for(register int i = retransHead; retransTail - i > 0; i++)
	{
		register int k = retransBackLog[i] - seqHead + iHead;
		skb = pControlBlock->HeadSend() + (k >= capacity ? k - capacity : k);
		Emit(skb, retransBackLog[i]);	// At most MAX_RETRANSMISSION futile retransmissions
	}
}



// PURE_DATA
void CSocketItemEx::OnGetPureData()
{
	TRACE_SOCKET();
	// It's OK to prebuffer received data in CLONING or RESUMING state (but NOT in QUASI_ACTIVE state)
	// However ULA protocol designer must keep in mind that these prebuffered may be discarded
	// It's impossible for ULA to accept data in the PAUSING state
	if(! InStates(3, ESTABLISHED, CLONING, RESUMING))
	{
#ifdef TRACE
		printf_s("In state %s data may not be accepted.\n", stateNames[lowState]);
#endif
		return;
	}

	if(! IsValidSequence(headPacket->pktSeqNo))
	{
#ifdef TRACE
		printf_s("Invalid sequence number: %u, expected: %u - %u\n"
			, headPacket->pktSeqNo
			, pControlBlock->recvWindowFirstSN
			, pControlBlock->recvWindowFirstSN + pControlBlock->recvBufferBlockN - 1);
#endif
		return;
	}

	if(! ValidateICC())
	{
#ifdef TRACE
		printf_s("Invalid intergrity check code!?\n");
#endif
		return;
	}

	if(! ResizeSendWindow(ntohl(headPacket->pkt->expectedSN), headPacket->pkt->GetRecvWS()))
	{
#ifdef TRACE
		printf_s("An out of order acknowledgement? seq#%u\n", ntohl(headPacket->pkt->expectedSN));
#endif
		return;
	}

	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	// It is less efficient than signaling an 'interrupt' only when the head packet of a gap in the receive window is received
	// However, we may safely assume that out-of-order packets are of low ratior and it does not make too much overload
	// It is definitely less efficient than polling for 'very' high throughput network application
	// TODO! lazy acknowledgement
	if(PlacePayload() > 0)
	{
		ChangeKeepAliveClock();
		//KeepAlive();	// make active acknowledgement
		Notify(FSP_NotifyDataReady);
	}
}



// ADJOURN
//	ACTIVE-->[{if no gap}Snd ACK_FLUSH]-->CLOSABLE-->[Notify]
//	RESUMING-->[{if no gap}Snd ACK_FLUSH]-->CLOSABLE-->[Notify]
//	CLONING-->[{if no gap}Snd ACK_FLUSH]-->CLOSABLE-->[Notify]
//	CLOSABLE<-->[Snd{retransmit} ACK_FLUSH][Processed already]
//	PAUSING-->[{if no gap}Snd ACK_FLUSH]-->CLOSABLE [Simultaneous Adjourn]-->[Notify]
// Remark
//	State transition form ACTIVE, RESUMING or CLONING is handled in KeepAlive()
//	ADJOURN might be out-of-band, and may carry piggybacked payload, but not any optional header
void CSocketItemEx::OnGetAdjourn()
{
	TRACE_SOCKET();
	if(! InStates(5, ESTABLISHED, PAUSING, CLONING, RESUMING, CLOSABLE))
		return;

	// As calculate ICC may consume CPU resource intensively we are relunctant to send RESET

	// check the ICC at first, silently discard the packet if ICC check failed
	// preliminary check of sequence numbers [they are IV on calculating ICC]
	// UNRESOLVED!? Taking the risk of DoS attack by replayed ADJOURN...
	// TODO: throttle the rate of processing ADJOURN by 'early dropping'
	if(! IsValidSequence<ADJOURN>(headPacket->pktSeqNo))
		return;

	if(! ValidateICC())
		return;

	// TODO: UNRESOLVED!? as ADJOURN pause the session the send window shall be shrinked to the minimum
	// See also OnResume()

	// Unlike PURE_DATA, a retransmitted ADJOURN cannot be silent discarded
	if(InState(PAUSING))	// In the PAUSING state ULA is not expecting further data
	{
		ReplaceTimer(SCAVENGE_THRESHOLD_ms);
		SendPacket<ACK_FLUSH>();
		SetState(CLOSABLE);
		Notify(FSP_NotifyFlushed);	// Notify(FSP_NotifyAdjourn);
		return;
	}

	if(InState(CLOSABLE))	// Just retransmit ACK_FLUSH on duplicated ADJOURN command
	{
		SendPacket<ACK_FLUSH>();
		return;
	}

	// In the CLONING or RESUMING state payload may be piggybacked as well as in the ESTABLISHED state
	if(PlacePayload() > 0)
		Notify(FSP_NotifyDataReady);

	// TO BE TESTED: an ADJOURN says that all data sent shall be acknowledged!
	RespondSNACK(ntohl(headPacket->pkt->expectedSN), NULL, 0);
	// Unlike receive a normal data packet make active acknowledgement to ADJOURN instantly
	KeepAlive();
	if(InState(CLOSABLE))	// if it has migrated to CLOSABLE state from other state
		Notify(FSP_NotifyFlushed);	// Notify(FSP_NotifyAdjourn);
}



// ACK_FLUSH, not actually consume sequence space
//	PAUSING-->[Notify]-->CLOSABLE
void CSocketItemEx::OnAdjournAck()
{
	TRACE_SOCKET();
	if(! InState(PAUSING))
		return;

	if(! IsValidSequence(headPacket->pktSeqNo))
		return;

	if(headPacket->lenData != 0)
		return;

	if(! ValidateICC())
		return;

	tLastRecv = NowUTC();
#ifdef TRACE
	printf_s("Last time receive ADJOURN_ACK: 0x%016llX\n", tLastRecv);
#endif
	RespondSNACK(ntohl(headPacket->pkt->expectedSN), NULL, 0);
	Notify(FSP_NotifyFlushed);
}



// RESTORE may resume or resurrect a closable/closed connection
// tLastRecv is not modified
// UNRESOLVED! If the socket itself has been free...
void CSocketItemEx::OnGetRestore()
{
	FSP_Header_Manager hdrManager(& headPacket->pkt);

	// A CLOSED connnection may be resurrected, provide the session key is not out of life
	// A replayed/redundant RESTORE would be eventually acknowedged by a legitimate PERSIST
	if(! InStates(3, CLOSED, CLOSABLE, PAUSING))
		return;

	if(! IsValidSequence(headPacket->pktSeqNo))
		return;

	if(! ValidateICC())
		return;

	if(! ResizeSendWindow(ntohl(headPacket->pkt->expectedSN), headPacket->pkt->GetRecvWS()))
		return;

	// TODO: synchronization of ULA-triggered session key installation
	PFSP_HeaderSignature optHdr = hdrManager.PopExtHeader<FSP_HeaderSignature>();
	if(optHdr != NULL && optHdr->opCode == CONNECT_PARAM)
	{
		// the synchronization option header...
	}
	// UNRESOLVED! Should send window to be recalibrated?
	// TODO: UNRESOLVED! if it return -EEXIST, should ULA be re-alerted?
	if(PlacePayload() < 0)
		return;

	if(InState(CLOSED))
		OnResurrect();
	else
		OnResume();

	SignalEvent();
}



// FINISH, not actually consume sequence space
//	PAUSING-->CLOSED-->[Notify]
//	CLOSABLE-->CLOSED-->[Notify]
//	tLastRecv is not modified
void CSocketItemEx::OnGetFinish()
{
	TRACE_SOCKET();
	if(! InState(PAUSING) && ! InState(CLOSABLE))
		return;

	if(! IsValidSequence(headPacket->pktSeqNo))
		return;

	if(headPacket->lenData != 0)
		return;

	if(! ValidateICC())
		return;

	ReplaceTimer(SCAVENGE_THRESHOLD_ms);
	SetState(CLOSED);
	Notify(FSP_NotifyDataReady);	// Just urge DLL to deliver data to ULA

	TRACE_HERE("To urge DLL to ProcessReceiveBuffer");
}



// MULTIPLY
// Remark
//	It is assumed that ULA/DLL implements connection multiplication throttle control
void CSocketItemEx::OnGetMultiply()
{
	FSP_Header_Manager hdrManager(& headPacket->pkt);

	if(! InState(ESTABLISHED))
		return;

	if(! IsValidSequence(headPacket->pktSeqNo))
		return;

	if(! ValidateICC())
		return;

//���Ӹ��ƣ�������Ӧ��ÿ�յ�һ��MULTIPLY���ģ���Ӧ��������Ӹ��ñ�ͷ�������ݵĸ��÷���������Session ID��
//���������ͬ�������������κ����ӵ�Զ��Session ID��ͬ������Ϊ���ظ���MULTIPLY���ģ�
//��ʱӦ�������ӵ��������У����������ӵĵ�ǰ״̬���ش�PERSIST��ADJOURN���ģ�������Ϊ����һ�ε����Ӹ�������
//ʵ���Ͽ�ʹ�����Զ��Session ID��local root Session ID������hash table���Ų��ظ���MULTIPLY����
//Ҳ����ʹ�����ṹ�����ӡ���ͬ�����������������ķ�ʽ��
//ԭʼ�����߲�������������ɭ�����ӡ�ÿ��Acceptʱ�½������ӵı���Session ID����������local root Session ID��
	// ControlBlock::seq_t ackSeqNo = ntohl(pkt.expectedSN);
	// if(! pSocket->IsValidExpectedSN(ackSeqNo)) return;
	// pSocket->pControlBlock->sendWindowSize
	//	= min(pSocket->pControlBlock->sendBufferBlockN, ntohs(pkt.recvWS));
	// See also OnConnectRequest()
	// TODO: UNRESOLVED! if it return -EEXIST, should ULA be re-alerted?
	if (PlacePayload() < 0)
		return;

	// it is possible that new local session ID collided with some other session, but it does not matter (?)
	// TODO: parse the multiplication optional header
	PFSP_HeaderSignature optHdr = hdrManager.PopExtHeader<FSP_HeaderSignature>();
	if(optHdr != NULL && optHdr->opCode == CONNECT_PARAM)
	{
		//
	}

	OnMultiply();
	SignalEvent();
}



// Return
//	>= 0	number of bytes placed on success
//	-ENOMEM	on buffer exhausted
//	-EEXIST on packet already received
//	-EFAULT	on memory fault
int CSocketItemEx::PlacePayload()
{
	ControlBlock::PFSP_SocketBuf skb = AllocRecvBuf(headPacket->pktSeqNo);
#ifdef TRACE
	printf_s("Place %d payload bytes to 0x%08X (duplicated: %d)\n"
		, headPacket->lenData
		, (LONG)skb
		, skb == 0 ? 0 : (int)skb->GetFlag<IS_DELIVERED>());
#endif
	if(skb == NULL)
		return -ENOMEM;
	if(skb->GetFlag<IS_DELIVERED>())
		return -EEXIST;

	tLastRecv = NowUTC();
	if(headPacket->lenData > 0)
	{
		BYTE *ubuf = GetRecvPtr(skb);
		if(ubuf == NULL)
		{
			HandleMemoryCorruption();
			return -EFAULT;
		}
		memcpy(ubuf, (BYTE *)headPacket->pkt + ntohs(headPacket->pkt->hs.hsp), headPacket->lenData);
		skb->SetFlag<TO_BE_CONTINUED>((headPacket->pkt->GetFlag<ToBeContinued>() != 0) && (skb->opCode != ADJOURN));
	}
	skb->version = headPacket->pkt->hs.version;
	skb->opCode = headPacket->pkt->hs.opCode;
	skb->len = headPacket->lenData;
	skb->SetFlag<IS_COMPLETED>();

	return headPacket->lenData;
}
