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



#if defined(TRACE) && (TRACE & TRACE_HEARTBEAT) && (TRACE & TRACE_PACKET)
#define TRACE_SOCKET()	\
	(printf_s(__FUNCTION__ ": local fiber#%u(_%X_) in state %s\n"	\
		, fidPair.source, be32toh(fidPair.source)		\
		, stateNames[lowState])	\
	&& pControlBlock->DumpSendRecvWindowInfo())
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



// Given
//	FSP_ServiceCode		the code of the notification to alert DLL
// Do
//	Put the notification code into the notice queue
// Return
//	true if the notification was put into the queue successfully
//	false if it failed
// Remark
//	Successive notifications of the same code are automatically merged
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
//	ACK_INIT_CONNECT, Cookie, initiator's check code echo, time difference
//		or
//	RESET, Timestamp echo, initiator's check code echo, reason
// Remark
//  Usually an FSP node allocate a new ALFID randomly and respond with the new ALFID, not the listening ALFID.
//	Collision might occur o allocating the new ALFID in a high-load responder, but the possibility is low enough.
//	For a low-power IoT device the listener may accept only one connection request, and thus respond with the listening ALFID.
// TODO: there should be some connection initiation throttle control in RandALFID
// TODO: UNRESOLVED! admission-control here?
// TODO: UNRESOLVED! For FSP over IPv6, attach responder's resource reservation...
void LOCALAPI CLowerInterface::OnGetInitConnect()
{
	// Silently discard connection request to blackhole, and avoid attacks alike 'port scan'
	CSocketItemEx *pSocket = MapSocket();
	if (pSocket == NULL || !pSocket->IsPassive())
	{
		BREAK_ON_DEBUG();
		return;
	}

	// In case ULA is manipulating the socket
	if (!pSocket->WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\nFiber#%u, lost INIT_CONNECT due to lack of locks\n", GetLocalFiberID());
#endif
		return;
	}
	// In case ULA has terminated
	if (!pSocket->IsProcessAlive())
	{
		pSocket->AbortLLS();
		goto l_return;
	}

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
//	Check the inititiator's cookie, make the formal connection request towards the responder
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

	// In case DLL is manipulating the socket
	if(! pSocket->WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\nFiber#%u, lost ACK_INIT_CONNECT due to lack of locks\n", GetLocalFiberID());
#endif
		return;
	}
	// In case ULA has terminated
	if (!pSocket->IsProcessAlive())
	{
		pSocket->AbortLLS();
		goto l_return;
	}

	SConnectParam & initState = pSocket->pControlBlock->connectParams;
	ALFID_T idListener = initState.idRemote;

	if(! pSocket->InState(CONNECT_BOOTSTRAP))
		goto l_return;

	if(initState.initCheckCode != pkt->initCheckCode)
		goto l_return;

	pSocket->SetRemoteFiberID(initState.idRemote = this->GetRemoteFiberID());
	//^ set to new peer fiber ID: to support multihome it is necessary even for IPv6
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
			pSocket->EmitStart();	// hitted
		}
		// Or else it is a collision and is silently discard in case an out-of-order RESET reset a legitimate connection
		return;
	}

	// Silently discard the request onto illegal or non-listening socket
	pSocket = (*this)[q->params.idListener];	// a dialect of MapSocket
	if (pSocket == NULL || !pSocket->IsPassive())
		return;

	if (!pSocket->WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\nFiber#%u, lost of CONNECT_REQUEST due to lack of locks\n", pSocket->fidPair.source);
#endif
		return;
	}
	//
	if (!pSocket->IsProcessAlive())
	{
		pSocket->AbortLLS();
		goto l_return;
	}

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
		memcpy(&backlogItem.acceptAddr, &pHdr->u, sizeof(FSP_SINKINF));
		memcpy(backlogItem.allowedPrefixes, q->params.subnets, sizeof(uint64_t) * MAX_PHY_INTERFACES);
	}
	else
	{	// FSP over UDP/IPv4
		register PFSP_IN6_ADDR fspAddr = (PFSP_IN6_ADDR) & backlogItem.acceptAddr;
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
		//
		memset(& backlogItem.allowedPrefixes[1], 0, sizeof(uint64_t) * (MAX_PHY_INTERFACES - 1));
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
// UNRESOLVED! Lost of RESET is siliently ignored?
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
	if (!IsInUse() || pControlBlock == NULL)
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
		int32_t offset = IsOutOfWindow(be32toh(reject.sn.initial));
		if ( (offset == 0 || offset == -1)	// RESET is out-of-band
		&& ValidateICC((FSP_NormalPacketHeader *) & reject, 0, fidPair.peer, 0))
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
//	Check wether KEEP_ALIVE or it special norm, ACK_FLUSH, is valid and output the gap descriptor list
// Return
//	true if the header packet, which is assumed to be KEEP_ALIVE or ACK_FLUSH packet, is valid
//	false if it is not
// Remark
//	A KEEP_ALIVE or ACK_FLUSH packet may carry an out-of-band End-Of-transmit-Transaction flag. The flag is treated here
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

	int32_t offset = IsOutOfWindow(headPacket->pktSeqNo);
	if (offset > 0 || offset < -1)
	{
#ifdef TRACE
		printf_s("%s has encountered attack? sequence number: %u\n\tshould in: [%u %u]\n"
			, opCodeStrings[p1->hs.opCode]
			, headPacket->pktSeqNo
			, pControlBlock->recvWindowFirstSN
			, pControlBlock->recvWindowFirstSN +  pControlBlock->recvBufferBlockN
			);
		BREAK_ON_DEBUG();
#endif
		return false;
	}
	
	offset = be16toh(p1->hs.hsp);	// For the KEEP_ALIVE/ACK_FLUSH it is the packet length as well
	//^now it is the offset of payload against the start of the FSP header
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
	printf_s("%s data length: %d, header length: %d, peer ALFID = %u\n"
		, opCodeStrings[p1->hs.opCode]
		, headPacket->lenData
		, offset
		, fidPair.peer);
	DumpNetworkUInt16((uint16_t *)p1, offset / 2);
#endif

	if(! ValidateICC(p1, 0, fidPair.peer, salt))	// No! Extension header is not encrypted!
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

	if(p1->GetFlag<TransactionEnded>())
		OnGetEOT();

	n = offset - be16toh(pSNACK->hs.hsp) - sizeof(FSP_SelectiveNACK);
	if (n < 0 || n % sizeof(FSP_SelectiveNACK::GapDescriptor) != 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("This is a malformed SNACK packet");
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



// Given
//	PktBufferBlock *	the packet buffer that holds ACK_CONNECT_REQ which might carry payload
//	int					the content length of the packet buffer, which holds both the header and the optional payload
// Do
//	Check the validity of the ackowledgement to the CONNECT_REQUEST command and establish the ephemeral session key
// Remark
//	CONNECT_AFFIRMING-->/ACK_CONNECT_REQ/-->[API{callback}]
//		|-->{Return Accept}-->PEER_COMMIT-->[Send PERSIST]{start keep-alive}
//		|-->{Return Reject}-->NON_EXISTENT-->[Send RESET]
// See also {FSP_DLL}CSocketItemDl::ToConcludeConnect()
void CSocketItemEx::OnConnectRequestAck(PktBufferBlock *pktBuf, int lenData)
{
	TRACE_SOCKET();
	if (!WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\nFiber#%u, lost ACK_CONNECT_REQ due to lack of locks\n", fidPair.source);
#endif
		return;
	}
	//
	if (!IsProcessAlive())
	{
		AbortLLS();
		goto l_return;
	}

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
	// Must prepare the receive window before allocate any receive buffer
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->AllocRecvBuf(pktSeqNo);
	if(skb == NULL)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("What? Cannot allocate the payload buffer for ACK_CONNECT_REQ?");
		goto l_return;
	}

	// ACK_CONNECT_REQ was not pushed into the queue so headpacket was not set
	// Put the payload (which might be empty) as if PlacePayload were called
	BYTE *ubuf;
	if (skb == NULL || !CheckMemoryBorder(skb) || (ubuf = GetRecvPtr(skb)) == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("TODO: debug memory corruption error");
		Recycle();			// Used to be HandleMemoryCorruption();
		goto l_return;
	}

	// Now the packet can be legitimately accepted
	tSessionBegin = tLastRecv = NowUTC();
	// Enable the time-out mechanism
	lowState = PRE_CLOSED;
	// OS time-slice, if any, might somewhat affect calculating of RTT. But it can be igored for large BDP pipe
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, (tRoundTrip_us + (tSessionBegin - tRecentSend) + 1) >> 1);

	// Attention Please! ACK_CONNECT_REQ may carry payload and thus consume the packet sequence space
	skb->len = lenData;
	if(lenData > 0)
		memcpy(ubuf, (BYTE *) & response + sizeof(response), lenData);
	skb->SetFlag<IS_FULFILLED>();	// See also PlacePayload()

	// the officially annouced IP address of the responder shall be accepted by the initiator
	// assert(response.params.subnets >= sizeof(sizeof(par->allowedPrefixes));
	SConnectParam * par = &pControlBlock->connectParams;
	memset(par->allowedPrefixes, 0, sizeof(par->allowedPrefixes));
	memcpy(par->allowedPrefixes, response.params.subnets, sizeof(response.params.subnets));

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



//PERSIST is the acknowledgement to ACK_CONNECT_REQ or MULTIPLY, and/or start a new transmit transaction
//	CHALLENGING-->/PERSIST/
//		--{EOT}-->CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//		--{otherwise}-->COMMITTED{start keep-alive}-->[Notify]
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
	if (!InStates(8, CHALLENGING, ESTABLISHED, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, CLONING))
		return;

	bool isInitiativeState = InState(CHALLENGING) || InState(CLONING);
	bool isMultiplying = InState(CLONING);

	if (headPacket->lenData < 0 || headPacket->lenData > MAX_BLOCK_SIZE)
	{
#ifdef TRACE
		printf_s("Invalid payload length: %d\n", headPacket->lenData);
#endif
		return;
	}

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	if (! isMultiplying)	// the normality
	{		
		if(! ICCSeqValid())
		{
#ifdef TRACE
			printf_s("@%s: Invalid sequence number: %u or invalid ICC\n", __FUNCTION__, headPacket->pktSeqNo);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			return;
		}
	}
	else if(! FinalizeMultiply())	// if (lowState == CLONING)
	{
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
		SendKeepAlive();	// AddLazyAckTimer();	// PERSIST needs an instant response to enhance efficiency
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

	bool committed = HasBeenCommitted();
	if(committed)
	{
		TransitOnPeerCommit();
	}
	else
	{
		switch(lowState)
		{
		case CHALLENGING:
			SetState(COMMITTED);
			RestartKeepAlive();
			break;
		case PEER_COMMIT:
			SetState(ESTABLISHED);
			RestartKeepAlive();
			break;
		case COMMITTING2:
			SetState(COMMITTING);
			break;
		case CLOSABLE:
			SetState(COMMITTED);
			RestartKeepAlive();
			break;
		case CLONING:
			SetState(_InterlockedExchange8(&shouldAppendCommit, 0) ? COMMITTED : ESTABLISHED);
#ifdef TRACE
			printf_s("\nTransit to %s state from CLONING\n", stateNames[lowState]);
#endif
			break;
		// default:	// case ESTABLISHED: case COMMITTED:	// keep state
		}
		//
		SendKeepAlive();
	}

	// PERSIST is always the accumulative acknowledgement to ACK_CONNECT_REQ or MULTIPLY
	// ULA slide the receive window, no matter whether the packet has payload
	if (isInitiativeState)
	{
#ifdef TRACE
		printf_s("\nPERSIST received. \tAcknowledged SN = %u\n\tThe responder calculate RTT\t", ackSeqNo);
#endif
		pControlBlock->SlideSendWindowByOne();	// See also RespondToSNACK
		CalibrateRTT();
	}

#if defined(TRACE) && (TRACE & TRACE_PACKET)
	if (countPlaced > 0)
		printf_s("There is optional payload in the PERSIST packet, payload length = %d\n", countPlaced);
#endif
	if (isMultiplying)
		SignalFirstEvent(FSP_NotifyMultiplied);
	else if (isInitiativeState)
		SignalFirstEvent(FSP_NotifyAccepted);
	else if (committed)
		Notify(FSP_NotifyToCommit);
	else if (countPlaced > 0)
		Notify(FSP_NotifyDataReady);
}



// KEEP_ALIVE is out-of-band and may carry a special optional header for multi-homed mobility support
//	{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2}-->/KEEP_ALIVE/<-->{keep state}[Notify]
//	{COMMITTED, CLOSABLE, PRE_CLOSED}-->/KEEP_ALIVE/<-->{keep state}{Update Peer's Authorized Addresses}
// Remark
//	KEEP_ALIVE may carry out-of-band EoT flag. See also ValidateSNACK
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
	printf_s("Fiber#%u: SNACK packet with %d gap(s) advertised received\n", fidPair.source, n);
#endif
	if(acknowledgible && RespondToSNACK(ackSeqNo, gaps, n) > 0)
		Notify(FSP_NotifyBufferReady);
	
	PFSP_HeaderSignature phs = headPacket->GetHeaderFSP()->PHeaderNextTo<FSP_SelectiveNACK>(& gaps[n]);
	if(phs != NULL)
		HandlePeerSubnets(phs);
}



//ACTIVE-->/PURE_DATA/
//	|-->{EOT}
//		-->{stop keep-alive}PEER_COMMIT-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//COMMITTING-->/PURE_DATA/
//	|-->{EOT}
//		-->COMMITTING2-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//COMMITTED-->/PURE_DATA/
//	|-->{EOT}
//		-->{stop keep-alive}CLOSABLE-->[Send ACK_FLUSH]-->[Notify]
//	|-->{otherwise}-->{keep state}[Send SNACK]-->[Notify]
//{CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE}<-->/PURE_DATA/{just prebuffer}
// However ULA protocol designer must keep in mind that these prebuffered may be discarded
void CSocketItemEx::OnGetPureData()
{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	TRACE_SOCKET();
#endif
	if (!InStates(7, ESTABLISHED, COMMITTING, COMMITTED, CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE))
	{
#ifdef TRACE
		printf_s("In state %s data may not be accepted.\n", stateNames[lowState]);
#endif
		return;
	}

	if(! ICCSeqValid())
	{
#ifdef TRACE
		printf_s("@%s: Invalid sequence number: %u or invald ICC\n", __FUNCTION__, headPacket->pktSeqNo);
#endif
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

	int r = PlacePayload();
	if(r == -EFAULT)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("No buffer when the receive window is not closed?");
		Notify(FSP_NotifyOverflow);
		return;
	}
	if (r == -ENOENT || r == -EEXIST)
	{
		AddLazyAckTimer();
		return;
	}
#if defined(_DEBUG) && defined(TRACE)
	if(r == 0)
	{
		printf_s("Either a PURE_DATA does not carry payload or the payload it is not stored safely\n");
		return;
	}
	if(r < 0)
	{
		printf_s("Fatal error when place payload, error number = %d\n", r);
		return;
	}
#else
	// r == 0 || r == -ENOENT, shall not occur in a stable implementation
	if(r <= 0)
		return;
#endif

	tLastRecv = NowUTC();
	// State transition signaled to DLL CSocketItemDl::WaitEventToDispatch()
	if(HasBeenCommitted())
	{
		TransitOnPeerCommit();
		Notify(FSP_NotifyToCommit);
	}
	// PURE_DATA cannot start a transmit transaction, so in state like CLONING just prebuffer
	else if(! InStates(4, CLONING, PEER_COMMIT, COMMITTING2, CLOSABLE))
	{
		AddLazyAckTimer();
		Notify(FSP_NotifyDataReady);
	}
	// See also OnGetPersist()
}



// On
//	getting the set End of Transaction flag piggybacked on the KEEP_ALIVE or ACK_FLUSH packet
// Do
//	 some state migration
// Remark
//	Take snapshot of the right edge of the receive window for sake of possibly synchronizing new session key
void CSocketItemEx::OnGetEOT()
{
	// As the EoT flag is piggybacked only if the last packet of the transmit transaction has been sent
	// the last packet of the receive buffer is need to be checked
	if(headPacket->pktSeqNo != pControlBlock->recvWindowNextSN - 1)
		return;

	// See also ControlBlock::AllocRecvBuf
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->recvWindowNextPos <= 0
		? pControlBlock->HeadRecv() + pControlBlock->recvWindowNextPos - 1
		: pControlBlock->HeadRecv() + pControlBlock->recvBufferBlockN - 1;

	// Unnecessary EOT is simply ignored
	if(skb->opCode == _COMMIT || skb->GetFlag<TransactionEnded>())
		return;

	// but maynot change the opCode as it is mark of delivery
	if(skb->opCode != 0)
	{
		skb->SetFlag<TransactionEnded>();
		skb->opCode = _COMMIT;
		if(! pControlBlock->HasBeenCommitted())
			return;
	}
	// if(skb->opCode == 0) every packet has been delivered. EOT make it committed
	// slightly different against CSocketItemEx::HasBeenCommitted
	pControlBlock->SnapshotReceiveWindowRightEdge();
	TransitOnPeerCommit();
	Notify(FSP_NotifyToCommit);
}




// Make state transition on end-of-transmit-transaction got from the peer
// Side-effect: send ACK_FLUSH immediately
void CSocketItemEx::TransitOnPeerCommit()
{
#ifdef TRACE
	printf_s("\nEoT got, transit from state %s to ", stateNames[lowState]);
#endif
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
		StopKeepAlive();
		break;
	case CLONING:
		StopKeepAlive();
		SetState(_InterlockedExchange8(&shouldAppendCommit, 0) ? CLOSABLE : PEER_COMMIT);
		break;
		// default:	// case PEER_COMMIT: case COMMITTING2: case CLOSABLE:	// keep state
	}
#ifdef TRACE
	printf_s("%s\n", stateNames[lowState]);
#endif
	SendAckFlush();
}



// ACK_FLUSH, now a pure out-of-band control packet. A special norm of KEEP_ALIVE
//	COMMITTING-->/ACK_FLUSH/-->COMMITTED-->[Notify]
//	COMMITTING2-->/ACK_FLUSH/-->{stop keep-alive}CLOSABLE-->[Notify]
// Remark
//	Like KEEP_ALIVE, ACK_FLUSH may carry out-of-band EoT flag. See also OnGetEOT
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
		BREAK_ON_DEBUG();	//TRACE_HERE("ACK_FLUSH should carry accumulatively positively acknowledge only");
		return;
	}
#endif
	_InterlockedExchange8(& shouldAppendCommit, 0);	// might be redundant, but it do little harm

	if (InState(COMMITTING2))
	{
		StopKeepAlive();
		SetState(CLOSABLE);
	}
	else if(InState(COMMITTING))
	{
		SetState(COMMITTED);
	}

	// For ACK_FLUSH just accumulatively positively acknowledge
	RespondToSNACK(ackSeqNo, NULL, 0);
	Notify(FSP_NotifyFlushed);
}



// CLOSABLE-->/RELEASE/-->CLOSED-->[Send RELEASE]-->[Notify]
// {COMMITTING2, PRE_CLOSED}-->/RELEASE/
//    -->{stop keep-alive}CLOSED-->[Send RELEASE]-->[Notify]
// Remark
//	RELEASE carries no payload but consumes the sequence space via ValidateICC to fight against play-back DoS attack
//	Duplicate RELEASE might be received AFTER the control block has been released already, so check before trace
// UNRESOLVED! To support connection context reuse/connection resurrection should not destroy the connection context
void CSocketItemEx::OnGetRelease()
{
	if (!InState(COMMITTING2) && !InState(CLOSABLE) && !InState(PRE_CLOSED) && !InState(CLOSED))
		return;
	TRACE_SOCKET();

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
		BREAK_ON_DEBUG();	//TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	// Note that if ever a duplicate RELEASE packet is received, the socket context may not be reused(non-recyclable)
	if (InState(CLOSED))
	{
		Destroy();	// LLS 
		return;
	}

	FSP_NormalPacketHeader *p1 = headPacket->GetHeaderFSP();
	ControlBlock::seq_t ackSeqNo = be32toh(p1->expectedSN);
	RespondToSNACK(ackSeqNo, NULL, 0);

	// There used to be 'connection resurrection'; might send redundant RELEASE, but it makes robustness
	SetState(CLOSED);
	SendRelease();
	Notify(FSP_NotifyToFinish);
	//
	ReplaceTimer(RECYCLABLE_TIMEOUT_ms);
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|<-->/MULTIPLY/{duplication detected: retransmit acknowledgement}
//	|<-->/MULTIPLY/{collision detected}[Send RESET]
//	|-->/MULTIPLY/-->[API{Callback}]
// Remark
//	It is assumed that ULA/DLL implements connection multiplication throttle control
//	See also OnGetConnectRequest()
void CSocketItemEx::OnGetMultiply()
{
	TRACE_SOCKET();

	if (!InStates(6, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE))
		return;

	int32_t d = IsOutOfWindow(headPacket->pktSeqNo);
	if (d > 0 || d <= -MAX_BUFFER_BLOCKS)
	{
		BREAK_ON_DEBUG();
		return;	// stale packets are silently discarded
	}

	FSP_NormalPacketHeader *pFH = (FSP_NormalPacketHeader *)headPacket->GetHeaderFSP();	// the fixed header
	uint32_t remoteHostID = pControlBlock->connectParams.remoteHostID;
	ALFID_T idSource = headPacket->fidPair.source;
	uint32_t salt = pFH->expectedSN;
	// The out-of-band serial number is stored in p1->expectedSN
	// Recover the hidden expected SN exploited by the peer
	pFH->expectedSN = htobe32(contextOfICC.snFirstSendWithCurrKey);
	if (!ValidateICC(pFH, headPacket->lenData, idSource, salt))
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Invalid intergrity check code!?");
		return;
	}

	// Check whether the request is already put into the multiplication backlog
	// Check whether it is a collision!?
	CMultiplyBacklogItem *newItem  = CLowerInterface::Singleton.FindByRemoteId(remoteHostID, idSource, fidPair.source);
	// Unlike ACK_CONNECT_REQ, response to MULTIPLY is retranmitted on timed-out, not on demand
	if (newItem != NULL)
		return;

	// See also CLowerInterface::OnGetInitConnect
	newItem = (CMultiplyBacklogItem *)CLowerInterface::Singleton.AllocItem();
	if(newItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot for multiplication");
		return;		// for security reason silently the exception
	}

	BackLogItem backlogItem(pControlBlock->connectParams);
	backlogItem.idRemote = idSource;
	if (pControlBlock->backLog.Has(&backlogItem))
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Duplicate MULTIPLY backlogged already");
l_bailout:
		CLowerInterface::Singleton.FreeItem(newItem);
		return;
	}

	backlogItem.expectedSN = headPacket->pktSeqNo;
	rand_w32(&backlogItem.initialSN, 1);
	// Inherit the parent's session key:
	backlogItem.idParent = fidPair.source;
	backlogItem.acceptAddr = pControlBlock->nearEndInfo;
	backlogItem.acceptAddr.idALF = newItem->fidPair.source;
	memcpy(backlogItem.allowedPrefixes, pControlBlock->peerAddr.ipFSP.allowedPrefixes, sizeof(uint64_t)* MAX_PHY_INTERFACES);
	//^See also CSocketItemDl::PrepareToAccept()

	// lastly, put it into the backlog
	if (pControlBlock->backLog.Put(&backlogItem) < 0)
	{
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
		printf_s("Cannot put the multiplying connection request into the SCB backlog.\n");
#endif
		goto l_bailout;
	}

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("Multiply request put into the backlog\n"
		"\tParent's fid = 0x%X, allocated fid = 0x%X, peer's fid = 0x%X\n", fidPair.source, newItem->fidPair.source, idSource);
#endif

	SOCKADDR_HOSTID(newItem->sockAddrTo) = remoteHostID;
	// While the ALFID part which was assigned dynamically by AllocItem() is preserved
	newItem->fidPair.peer = idSource;
	newItem->idParent = fidPair.source;
	newItem->nextOOBSN = this->nextOOBSN;
	newItem->lastOOBSN = be32toh(salt);
	//^As a salt it is of neutral byte-order, as an OOBSN it should be transformed to host byte order.
	// place payload into the backlog, see also placepayload
	newItem->CopyInPlainText((BYTE *)pFH + be16toh(pFH->hs.hsp), headPacket->lenData);

	ControlBlock::PFSP_SocketBuf skb = ((CMultiplyBacklogItem *)newItem)->TempSocketBuf();
	skb->version = pFH->hs.major;
	skb->opCode = pFH->hs.opCode;
	skb->CopyInFlags(pFH);
	skb->SetFlag<IS_FULFILLED>();
	//^See also PlacePayload
	// Be free to accept: we accept an imcomplete MULTIPLY
	if(headPacket->lenData != MAX_BLOCK_SIZE)
		skb->SetFlag<TransactionEnded>();

	// The first packet received is in the parent's session key while
	// the first responding packet shall be sent in the derived key
	newItem->contextOfICC.InheritR1(contextOfICC, backlogItem.initialSN);
	newItem->contextOfICC.snFirstRecvWithCurrKey = headPacket->pktSeqNo + 1;
	//^See also FinalizeMultiply()
	// Derivation of the new session key is delayed until ULA accepted the multiplication, however.

	newItem->tLastRecv = tLastRecv;	// inherit the time when the MULTIPLY packet was received
	newItem->tRoundTrip_us = tRoundTrip_us;	// inherit the value of the parent as the initial
	newItem->tKeepAlive_ms = TRANSIENT_STATE_TIMEOUT_ms;
	newItem->lowState = NON_EXISTENT;	// so that when timeout it is scavenged
	newItem->AddTimer();

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

	if(skb->GetFlag<IS_FULFILLED>())
		return -EEXIST;

	FSP_NormalPacketHeader *pHdr = headPacket->GetHeaderFSP();
	if(headPacket->lenData > 0)
	{
		BYTE *ubuf = GetRecvPtr(skb);
		if(ubuf == NULL)
			return -EFAULT;
		//
		memcpy(ubuf, (BYTE *)pHdr + be16toh(pHdr->hs.hsp), headPacket->lenData);
		skb->CopyInFlags(pHdr);
	}
	skb->version = pHdr->hs.major;
	// Force the last packet descriptor of the transaction in the receive buffer to be _COMMIT.
	// See also Check HasBeenCommitted()
	skb->opCode = skb->GetFlag<TransactionEnded>() ? _COMMIT : pHdr->hs.opCode;
	skb->len = headPacket->lenData;
	skb->SetFlag<IS_FULFILLED>();

	return headPacket->lenData;	// Might be zero for PERSIST or MULTIPLY packet
}
