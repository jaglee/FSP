/*
 * FSP lower-layer service program, the 'socket'/session control block classes
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
#include <stddef.h>


// Translation-Look-aside-Buffer of the Service Sockets, the constructor
CSocketSrvTLB::CSocketSrvTLB()
{
	memset(listenerSlots, 0, sizeof(listenerSlots));
	memset(itemStorage, 0, sizeof(itemStorage));
	memset(tlbSockets, 0, sizeof(tlbSockets));
	memset(tlbSocketsByRemote, 0, sizeof(tlbSocketsByRemote));
	//^ assert(NULL == 0)
	headFreeSID = & itemStorage[0];
	tailFreeSID = & itemStorage[MAX_CONNECTION_NUM - 1];

	register CSocketItemEx *p = headFreeSID;
	register int i = 0;
	while(i < MAX_CONNECTION_NUM)
	{
		tlbSockets[i] = p;
		tlbSockets[i++]->next = ++p;
		// other link pointers are already set to NULL
	}
	tailFreeSID->next = NULL;	// reset last 'next' pointer
	//
	InitMutex();
}



bool CSocketSrvTLB::PutToScavengeCache(CSocketItemEx *pSocket, timestamp_t tNow)
{
	int32_t n;
	if ((n = _InterlockedIncrement((PLONG)&topOfSC)) >= MAX_CONNECTION_NUM)
	{
		topOfSC--;
		return false;
	}

	scavengeCache[n - 1].pSocket = pSocket;
	scavengeCache[n - 1].timeRecycled = tNow;
	return true;
}



// allocate from the free list
CSocketItemEx* CSocketSrvTLB::AllocItem()
{
	CSocketItemEx* p, * p1;
	timestamp_t tNow;

	AcquireMutex();

	if (headFreeSID != NULL)
	{
	l_success:
		p = headFreeSID;
		headFreeSID = p->next;
		if (headFreeSID == NULL)
			tailFreeSID = NULL;
		ReleaseMutex();
		//
		p->lowState = CONNECT_BOOTSTRAP;
		p->markInUse = 1;
		return p;
	}

	// as this is a prototype is not bothered to exploit hash table
	// recycle all of the orphan sockets
	register u32 i;
#if !(TRACE & TRACE_HEARTBEAT)
	for (i = 0, p = itemStorage; i < MAX_CONNECTION_NUM; i++, p++)
	{
		if (!p->IsProcessAlive())
			p->AbortLLS(true);
	}
#endif
	if (headFreeSID != NULL)
		goto l_success;

	tNow = NowUTC();
	p1 = NULL;
	// Reserved: a 'CLOSED' socket might be resurrected,
	// provides it is the original ULA process that is to reuse the socket
	if (topOfSC == 0)
	{
		for (i = 0, p = itemStorage; i < MAX_CONNECTION_NUM; i++, p++)
		{
			if (p->lowState == CLOSED || !p->IsInUse())
				PutToScavengeCache(p, tNow);
		}
	}
	if (topOfSC <= 0)
	{
		ReleaseMutex();
		return NULL;
	}

	p1 = scavengeCache[0].pSocket;
	topOfSC--;
	for (i = 0; i < topOfSC; i++)
	{
		scavengeCache[i] = scavengeCache[i + 1];
	}
	// It is hazardous to release the socket by force
	p1->WaitUseMutex();		// it is throttling!
	p1->AbortLLS(true);
	goto l_success;
}



// registration of passive socket: it is assumed that performance is out of question for a conceptual prototype
// allocate in the listeners' socket space
// detect duplication fiber ID, remove 'brain-dead' socket
// UNRESOLVED! LRU and round-robin of recycling
// May we reuse a socket created indirectly by a terminated process?
CSocketItemEx * CSocketSrvTLB::AllocItem(ALFID_T idListener)
{
	AcquireMutex();

	CSocketItemEx *p = NULL;
	for(register int i = 0; i < MAX_LISTENER_NUM; i++)
	{
		register CSocketItemEx &r = listenerSlots[i];
		if (r.IsInUse() && !r.IsProcessAlive())
		{
			r.AbortLLS(true);
			if (p == NULL)
				p = &r;
			// do not break, for purpose of duplicate allocation detection
		}
		else if (r.IsInUse() && r.fidPair.source == idListener)
		{
#ifdef TRACE
			printf_s("\nCollision detected:\n"
					 "\twith process#%u, listener fiber#%u\n", r.idSrcProcess, idListener);
#endif
			p = NULL;
			break;
		}
		else if (p == NULL && r.TestSetState(LISTENING))
		{
			p = &r;
			// do not break, for purpose of duplicate allocation detection and dad process removal
		}
	}

	if (p != NULL)
	{
		memset(p, 0, sizeof(CSocketItemEx));
		p->markInUse = 1;
		p->SetPassive();
		p->fidPair.source = idListener;
		PutToListenTLB(p, be32toh(idListener) & (MAX_CONNECTION_NUM - 1));
	}

	ReleaseMutex();
	return p;
}



// Given
//	CSocketItemEx *		pointer to the socket item to be inserted, might be updated
//	int					the 'compressed' hash key for searching the socket item
// Do
//	Insert the given socket item into the translation-look-aside buffer of listening sockets
void CSocketSrvTLB::PutToListenTLB(CSocketItemEx* p, int k)
{
	CSocketItemEx* p0 = tlbSockets[k];
	register CSocketItemEx* p1;
	// TODO: UNRESOLVED! Is it unnecessary to detect the stale entry?
	for (p1 = p0; p1 != NULL; p1 = p1->prevSame)
	{
		if (p == p1)
			return;
		//
		if (p->fidPair.source == p1->fidPair.source)
		{
			REPORT_ERRMSG_ON_TRACE("collision found when putting socket into sockets TLB");
			return;
		}
	}
	assert(p1 == NULL && p != NULL);
	p->prevSame = p0;
	tlbSockets[k] = p;
}



// Given
//	CSocketItemEx	The pointer to the socket item to free
// Do
//	Put the given socket item onto the free list
// Remark
//	Assume having obtained the lock of TLB. Will free the lock in the end.
void CSocketSrvTLB::FreeItemDonotCareLock(CSocketItemEx *p)
{
	// if it is allocated by AllocItem(ALFID_T idListener):
	if(p->IsPassive())
	{
		int k = be32toh(p->fidPair.source) & (MAX_CONNECTION_NUM - 1);
		register CSocketItemEx *p1 = tlbSockets[k];
		// detach it from the hash collision list
		if(p1 == p)
		{
			tlbSockets[k] = p1->prevSame;
		}
		else
		{
			while(p1 != NULL)
			{
				if(p1->prevSame == p)
				{
					p1->prevSame = p->prevSame;
					break;
				}
				p1 = p1->prevSame;
			}
			//^it provides a safe-net to check whether p1 == NULL firstly
			if(p1 == NULL)
				REPORT_ERRMSG_ON_TRACE("A passive socket to be free is not an instance allocated properly");
		}
		//
		return;
	}

	// if it is allocated by AllocItem() [by assigning a pseudo-random fiber ID]
	if(tailFreeSID == NULL)
	{
		headFreeSID = tailFreeSID = p;
	}
	else
	{
		tailFreeSID->next = p;
		tailFreeSID = p;
	}
	p->next = NULL;	// in case it is not
	bzero((octet *)p + offsetof(CSocketItemEx, idSrcProcess)
		, sizeof(CSocketItemEx) - offsetof(CSocketItemEx, idSrcProcess));
	// It might be unfriendly for connection resurrection. However, here security takes precedence.
}



// Given
//	ALFID_T		The application layer fiber ID
// Return
//	The pointer to the socket item entry that matches the ID
// Remark
//	The hash algorithm MUST be kept synchronized with PoolingALFIDs
CSocketItemEx * CSocketSrvTLB::operator[](ALFID_T id)
{
	register CSocketItemEx *p = tlbSockets[be32toh(id) & (MAX_CONNECTION_NUM-1)];
	do
	{
		if(p->fidPair.source == id)
			return p;
		p = p->prevSame;
	} while(p != NULL);
	//
	return p;	// assert(p == NULL);
}



// Given
//	CommandNewSessionSrv	The 'new session' command
// Return
//	The new socket item, with control block memory mapped
// We allow a socket slot waiting scavenge to be reused earlier than recycled. See also KeepAlive
CSocketItemEx * CSocketSrvTLB::AllocItem(const CommandNewSessionSrv & cmd)
{
	AcquireMutex();
	//
	CSocketItemEx *p = (*this)[cmd.fiberID];
	if(p != NULL)
	{
		if (!p->TestSetState(CHALLENGING))
		{
			p = NULL;
			goto l_return;
		}
		if(! p->MapControlBlock(cmd))
		{
			REPORT_ERRMSG_ON_TRACE("Control block shall be created by the ULA via DLL call already");
			p->ClearInUse();	// No, you cannot 'FreeItem(p);' because mutex is SHARED_BUSY
			p = NULL;
			goto l_return;
		}
		p->markInUse = 1;
	}
l_return:
	ReleaseMutex();
	return p;
}



// Given
//	CSocketItemEx * The pointer to the socket that to be put into the Remote Translate Look-aside Buffer
// Return
//	true if succeeded
//	false if failed
// Remark
//	Assume the remote application layer fiber ID HAS been stored in the fidPair
//	The algorithm MUST be keep aligned with FindByRemoteId
bool CSocketSrvTLB::PutToRemoteTLB(CMultiplyBacklogItem *pItem)
{
	uint32_t remoteHostId = SOCKADDR_HOSTID(pItem->sockAddrTo);
	ALFID_T idRemote = pItem->fidPair.peer;
	ALFID_T idParent = pItem->idParent;
	assert(pItem->pControlBlock == NULL || pItem->idParent == pItem->pControlBlock->idParent);
	int k = be32toh(idRemote) & (MAX_CONNECTION_NUM-1);
	CSocketItemEx *p0 = tlbSocketsByRemote[k];
	pItem->prevRemote = p0;	// might be NULL
	//
	for(register CSocketItemEx *p = p0; p != NULL; p = p->prevRemote)
	{
		if(p->fidPair.peer == idRemote
		&& p->idParent == idParent
		&& SOCKADDR_HOSTID(p->sockAddrTo) == remoteHostId)
		{
#ifdef TRACE
			printf_s("\nFound collision when put to remote ALFID's translate look-aside buffer:\n"
					 "Parent fiber#%u, remote fiber#%u\n", idParent, idRemote);
#endif
			return false;
		}
	}
	// If no collision found, good!
	tlbSocketsByRemote[k] = pItem;
	return true;
}



// Given
//	uint32_t	The remote host ID
//	ALFID_T		The remote application layer fiber ID
//	ALFID_T		The parent application layer fiber ID
// Return
//	The pointer to the socket item entry that matches the given parameters
CMultiplyBacklogItem * CSocketSrvTLB::FindByRemoteId(uint32_t remoteHostId, ALFID_T idRemote, ALFID_T idParent)
{
	register CSocketItemEx *p = tlbSocketsByRemote[be32toh(idRemote) & (MAX_CONNECTION_NUM-1)];
	for (; p != NULL; p = p->prevRemote)
	{
		if(p->fidPair.peer == idRemote
		&& p->idParent == idParent
		&& SOCKADDR_HOSTID(p->sockAddrTo) == remoteHostId)
		{
			return (CMultiplyBacklogItem *)p;
		}
	}
	//
	return (CMultiplyBacklogItem *)p;	// assert(p == NULL);
}



// Return true if succeeded in obtaining the mutex lock, false if waited but timed-out
bool CSocketItemEx::WaitUseMutexAt(const char* funcName)
{
	uint64_t t0 = GetTickCount64();
	while (_InterlockedCompareExchangePointer((PVOID*)& lockedAt, (PVOID)funcName, 0) != 0)
	{
		if (!IsInUse() || GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			return false;
		Sleep(TIMER_SLICE_ms);	// if there is some thread that has exclusive access on the lock, wait patiently
	}

	if (IsInUse())
		return true;
	//
	lockedAt = 0;
	return false;
}



// Lock the session context if the process of upper layer application is still active
// Abort the FSP session if ULA is not active
// Return true if the session context is locked, false if not
bool CSocketItemEx::LockWithActiveULAt(const char* funcName)
{
	void* c = _InterlockedCompareExchangePointer((PVOID*)& lockedAt, (PVOID)funcName, 0);
	if (IsProcessAlive())
		return (c == 0 || WaitUseMutexAt(funcName));
	//
	AbortLLS();
	lockedAt = 0;
	return false;
}



// Initialize the association of the remote end [represent by sockAddrTo] and the near end
// Side-effect: set the initial 'previous state'
// TODO: UNRESOLVED! hard-coded here, limit capacity of multi-home support?
void CSocketItemEx::InitAssociation()
{
	// 'source' field of fidPair shall be filled already. See also CInterface::PoolingALFIDs()
	// and CSocketSrvTLB::AllocItem(), AllocItem(ALFID_T)
	fidPair.peer = pControlBlock->peerAddr.ipFSP.fiberID;
	idParent = pControlBlock->idParent;

	// See also CLowerInterface::EnumEffectiveAddresses
	register PSOCKADDR_INET const pFarEnd = sockAddrTo;
#ifdef OVER_UDP_IPv4
	for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		memset(&pFarEnd[i], 0, sizeof(pFarEnd[i]));
		pFarEnd[i].Ipv4.sin_family = AF_INET;
		*(u32 *) & pFarEnd[i].Ipv4.sin_addr
			= ((PFSP_IN4_ADDR_PREFIX) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[i])->ipv4;
		pFarEnd[i].Ipv4.sin_port = DEFAULT_FSP_UDPPORT;
		((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALF = fidPair.peer;
	}
	// namelen = sizeof(SOCKADDR_IN);
#else
	uint32_t idRemoteHost = pControlBlock->peerAddr.ipFSP.hostID;
	// local address is yet to be determined by the LLS
	for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		pFarEnd[i].Ipv6.sin6_family = AF_INET6;
		pFarEnd[i].Ipv6.sin6_flowinfo = 0;
		pFarEnd[i].Ipv6.sin6_port = 0;
		pFarEnd[i].Ipv6.sin6_scope_id = 0;
		((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->subnet
			= pControlBlock->peerAddr.ipFSP.allowedPrefixes[i];
		((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idHost = idRemoteHost;
		((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALF = fidPair.peer;
	}
	// namelen = sizeof(SOCKADDR_IN6);
#endif
	//
	SyncState();
}



// Given
//	ALFID_T		The remote peer's Application Layer Fiber ID
// Do
//	Set the stored multi-path destination fiber ID to the given one
void CSocketItemEx::SetRemoteFiberID(ALFID_T id)
{
	fidPair.peer = id;
	for (register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		SOCKADDR_ALFID(sockAddrTo + i) = id;
	}
}



// INIT_CONNECT, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
void CSocketItemEx::InitiateConnect()
{
	SConnectParam & initState = pControlBlock->connectParams;
	rand_w32((uint32_t *) & initState,
		( sizeof(initState.initCheckCode)
		+ sizeof(initState.cookie)
		+ sizeof(initState.salt) ) / sizeof(uint32_t) );
	initState.nboTimeStamp = htobe64(NowUTC());
	rand_w32(& initState.initialSN, 1);
	// Remote fiber ID was set when the control block was created
	// for calculation of the initial round-trip time
	pControlBlock->connectParams.nboTimeStamp = initState.nboTimeStamp;
	pControlBlock->SetSendWindow(initState.initialSN);

	// INIT_CONNECT can only be the very first packet
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	skb->opCode = INIT_CONNECT;
	skb->len = sizeof(FSP_InitiateRequest);
	//
	FSP_InitiateRequest* q = (FSP_InitiateRequest*)GetSendPtr(skb);
	if(q == NULL)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Memory corruption!");
		return;
	}
	SetHeaderSignature(*q, INIT_CONNECT);
	q->salt = initState.salt;
	q->timeStamp = initState.nboTimeStamp;
	q->initCheckCode = initState.initCheckCode;
	// See also AffirmConnect()

	skb->ReInitMarkComplete();
	SendPacket(1, ScatteredSendBuffers(q, sizeof(FSP_InitiateRequest)));
	skb->timeSent = tRecentSend;

	SyncState();
	ReplaceTimer(RETRANSMIT_MIN_TIMEOUT_us/1000);
}



// CONNECT_REQUEST, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
// Given
//	SConnectParam	the initial state
//	ALFID_T			the responder's Application Layer Fiber ID
// Do
//	Make and send the CONNECT_REQUEST command
// Remark
//	Because CONNECT_REQUEST overlays INIT_CONNECT these three fields are reused: timeStamp, initCheckCode, salt
// It is assumed that exclusive access to the socket has been gained
// Safely suppose that internal processing takes orders of magnitude less time than network propagation
// TODO: UNRESOLVED! For FSP over IPv6, attach initiator's resource reservation...
void CSocketItemEx::AffirmConnect(const SConnectParam & initState, ALFID_T idListener)
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend(); // Reuse what's occupied by INIT_CONNECT
	FSP_ConnectRequest *pkt = (FSP_ConnectRequest *)this->GetSendPtr(skb);
	if(pkt == NULL)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("memory corruption");
		return;
	}

	SetFirstRTT(int64_t(NowUTC() - skb->timeSent));

	pkt->_init.hs.opCode = CONNECT_REQUEST;
	// The major version MUST be kept
	pkt->_init.hs.offset = htobe16(sizeof(FSP_ConnectRequest));
	SetConnectParamPrefix(pkt->params);
	pkt->params.idListener = idListener;
	// assert(sizeof(initState.allowedPrefixes) >= sizeof(varParams.subnets));
	memcpy(pkt->params.subnets, initState.allowedPrefixes, sizeof(pkt->params.subnets));
	pkt->initialSN = htobe32(initState.initialSN);
	// only the responder may care about the granularity and byte order of the time delta
	pkt->timeDelta = initState.timeDelta;
	pkt->cookie = initState.cookie;

	// while version remains as the same as the very beginning INIT_CONNECT
	skb->opCode = CONNECT_REQUEST;
	skb->len = sizeof(FSP_ConnectRequest);

	SetState(CONNECT_AFFIRMING);
	ReplaceTimer(RETRANSMIT_MIN_TIMEOUT_us/1000);
	SendPacket(1, ScatteredSendBuffers(pkt, skb->len));	// it would set tRecentSend
}



// MULTIPLY, SequenceNo, Salt, ICC, FREWS[, payload]
// See InitiateConnect and @DLL ULA FSPAPI ConnectMU
// Given
//	CSocketItemEx *		Pointer to the source socket slot. The nextOOBSN field would be updated
// See also
//	EmitWithICC
//	OnConnectRequestAck; CSocketItemDl::ToWelcomeConnect; CSocketItemDl::ToWelcomeMultiply
void CSocketItemEx::InitiateMultiply(CSocketItemEx *srcItem)
{
	// Inherit the interfaces, excluding the last one which is ephemeral 
	memcpy(&pControlBlock->peerAddr, &srcItem->pControlBlock->peerAddr, sizeof(pControlBlock->peerAddr));
	memcpy(this->sockAddrTo, srcItem->sockAddrTo, sizeof(SOCKADDR_INET) * MAX_PHY_INTERFACES);
	pControlBlock->nearEndInfo.idALF = fidPair.source;	// and pass back to DLL/ULA
	pControlBlock->connectParams = srcItem->pControlBlock->connectParams;
	InitAssociation();
	// pControlBlock->idParent was set in @DLL::ToPrepareMultiply()
	assert(idParent == pControlBlock->idParent);	// Set in InitAssociation
	assert(fidPair.peer == srcItem->fidPair.peer);	// Set in InitAssociation

	ControlBlock::seq_t seq0 = pControlBlock->sendWindowNextSN;	// See also @DLL::ToPrepareMultiply
	nextOOBSN = ++srcItem->nextOOBSN;
	contextOfICC.InheritS0(srcItem->contextOfICC, seq0);
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("\nTo send MULTIPLY in LLS, ICC context:\n"
		"\tSN of MULTIPLY to send = %09u\n"
		"\tALFID of near end's branch = %u, ALFID of peer's parent = %u\n"
		, seq0
		, fidPair.source, fidPair.peer);
#endif
	if (contextOfICC.keyLifeRemain != 0)
		DeriveKey(fidPair.source, fidPair.peer);

	// MULTIPLY can only be the very first packet
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	void * payload = GetSendPtr(skb);
	ALIGN(FSP_ALIGNMENT) FSP_FixedHeader q;
	void* paidLoad;
	lastOOBSN = 0;	// As the response from the peer, if any, is not an out-of-band packet

	SignHeaderWith(&q, MULTIPLY, sizeof(FSP_NormalPacketHeader), seq0, nextOOBSN);
	skb->CopyFlagsTo(& q);

	paidLoad = SetIntegrityCheckCode(&q, payload, skb->len, GetSalt(q));
	if (paidLoad == NULL || skb->len > (int32_t)sizeof(this->cipherText))
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Cannot set ICC for the new MULTIPLY command");
		return;	// but it's an exception!
	}
	assert(paidLoad == this->cipherText);

	// Buffer the header in the queue for sake of retransmission on time-out. See also EmitStart() and KeepAlive()
	memcpy(payload, &q, sizeof(FSP_NormalPacketHeader));

	pControlBlock->SetFirstSendWindowRightEdge();
	SyncState();
	//// In case of trace condition
	//if (!WaitUseMutex())
	//{
	//	BREAK_ON_DEBUG();
	//	return;
	//}
	SendPacket(2, ScatteredSendBuffers(payload, sizeof(FSP_NormalPacketHeader), this->cipherText, skb->len));
	skb->MarkSent();
	skb->timeSent = NowUTC();
	SetFirstRTT(srcItem->tRoundTrip_us);
	tSessionBegin = skb->timeSent;
	tPreviousTimeSlot = skb->timeSent;
	tPreviousLifeDetection = tSessionBegin;
	ReplaceTimer(RETRANSMIT_MIN_TIMEOUT_us/1000);
	//SetMutexFree();
}



// On getting the peer's response to MULTIPLY, fill in the proper field of contextOfICC
// so that the derived new session key is put into effect
// Remark
//	On get the peer's ACK_START/PERSIST the socket would be put into the remote id's translate look-aside buffer
//	In some extreme situation the peer's ACK_START/PERSIST to MULTIPLY could be received before tSessionBegin was set
//	and such an acknowledgement is effectively lost
//	however, it is not a fault but is a feature in sake of proper state management
bool CSocketItemEx::FinalizeMultiply()
{
	pControlBlock->peerAddr.ipFSP.fiberID = headPacket->fidPair.source;
	contextOfICC.snFirstRecvWithCurrKey = pktSeqNo;
	//^See also ResponseToMultiply()
	InitAssociation();	// reinitialize with new peer's ALFID
	assert(fidPair.peer == headPacket->fidPair.source);

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("\nGet the acknowledgement ACK_START/PERSIST of MULTIPLY\n");
#endif
	if (!ValidateICC())
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Invalid integrity check code!?");
		return false;
	}

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("Response of MULTIPLY was accepted, recvBufferBlockN = %d\n"
		"\tAllocated fiber#%u, peer's fiber#%u\n"
		, pControlBlock->recvBufferBlockN
		, fidPair.source, fidPair.peer);
#endif
	RestartKeepAlive();
	// And continue to accept the payload in the caller
	pControlBlock->SetRecvWindow(pktSeqNo);
	return CLowerInterface::Singleton.PutToRemoteTLB((CMultiplyBacklogItem *)this);
}



// See also OnGetMultiply(), SendReset(), ICC_Context::InheritR1()
void CSocketItemEx::RefuseToMultiply(uint32_t reasonCode)
{
	ALIGN(FSP_ALIGNMENT) FSP_FixedHeader hdr;
	// See also SendReset(), but note that there was no receive window nor send window
	SetHeaderSignature(hdr, RESET);
	((FSP_RejectConnect*)&hdr)->reasons = reasonCode;
	hdr.sequenceNo = htobe32(contextOfICC.snFirstSendWithCurrKey);
	hdr.expectedSN = htobe32(contextOfICC.snFirstRecvWithCurrKey);
	SetIntegrityCheckCode(&hdr);
	SendPacket(1, ScatteredSendBuffers(&hdr, sizeof(hdr)));

	// See also Recycle(), but lowState is already zeroed, and control block is not mapped at all
	RemoveTimers();
	CLowerInterface::Singleton.FreeItem(this);

}



//{ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|-->/MULTIPLY/-->[API{Callback}]
//		|-->[{Return Accept}]-->{new context}-->{further LLS process}
//			|{Send queue EoT}
//				|{Peer's MULTIPLY was not EoT}-->COMMITTING
//				|{Peer's MULTIPLY was EoT}-->COMMITTING2
//			|{Send queue not EoT}
//				|{Peer's MULTIPLY was not EoT}-->ESTABLISHED
//				|{Peer's MULTIPLY was EoT}-->PEER_COMMIT
// Congest the peer's MULTIPLY payload and make response designated by ULA transmitted
// See also OnGetMultiply(), @DLL::PrepareToAccept, ToWelcomeMultiply
void CMultiplyBacklogItem::RespondToMultiply()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv() + GetRecvWindowHeadPos();
	// if (!CheckMemoryBorder(skb)) throw -EFAULT;
	// See also PlacePayload
	octet*ubuf = GetRecvPtr(skb);
	if(ubuf == NULL)
	{
		AbortLLS();		// Used to be HandleMemoryCorruption();
		return;
	}
	// tRecentSend = NowUTC();	// in case it is timed-out prematurely
	// The opCode field is overridden to PERSIST for sake of clearer transmit transaction management
	skb->len = CopyOutPlainText(ubuf);
	CopyOutFVO(skb);
	skb->opCode = PERSIST;
	skb->ReInitMarkComplete();
	skb->timeRecv = tLastRecv;	// so that delay of acknowledgement can be calculated more precisely

	pControlBlock->recvWindowExpectedSN = ++pControlBlock->recvWindowNextSN;
	_InterlockedIncrement((PLONG)&pControlBlock->recvWindowNextPos);
	// The receive buffer is eventually ready

	ControlBlock::PFSP_SocketBuf skbOut = pControlBlock->GetLastBuffered();
	// Hidden dependency: tLastRecv which is exploited in SendAckFlush in set OnGetMultiply
	if (skb->GetFlag<TransactionEnded>())
	{
		SetState(skbOut->GetFlag<TransactionEnded>() ? COMMITTING2 : PEER_COMMIT);
		SendAckFlush();
		SignalFirstEvent(FSP_NotifyToCommit);					// And deliver data instantly if it is to commit
	}
	else
	{
		SetState(skbOut->GetFlag<TransactionEnded>() ? COMMITTING : ESTABLISHED);
		pControlBlock->notices.nmi = FSP_NotifyDataReady;		// But do not signal until next packet is received
	}
	RestartKeepAlive();
}



// Do
//	Acknowledge the connection/multiplication of connection request by sending the head packet in the send queue
// Remark
//	Send the first packet in the send queue only, for sake of congestion control
//	ACK_CONNECT_REQ is resent on requested only.
//	bind to the interface as soon as the control block mapped into server's memory space
// See also
//	CSocketItemEx::OnConnectRequestAck(); CSocketItemDl::ToWelcomeConnect(), ToWelcomeMultiply()
void CSocketItemEx::Accept()
{
	if (!WaitUseMutex())
		return;	// but how on earth could it happen? race condition does exist!

	InitAssociation();
	//
	pControlBlock->SetFirstSendWindowRightEdge();
	if (lowState == CHALLENGING)
	{
		InstallEphemeralKey();
		//^ ephemeral session key material was ready when CSocketItemDl::PrepareToAccept
		SetFirstRTT(pControlBlock->connectParams.tDiff);
		EmitStart();
		tSessionBegin = tRecentSend;
		ReplaceTimer(TRANSIENT_STATE_TIMEOUT_ms);	// The socket slot might be a reused one
	}
	else
	{
		// Timer has been set when the socket slot was prepared on getting MULTIPLY
		((CMultiplyBacklogItem *)this)->RespondToMultiply();
		tSessionBegin = NowUTC();
	}
	//
	tPreviousLifeDetection = tPreviousTimeSlot = tSessionBegin;
	SetMutexFree();
}



// Send the abnormal 'RESET' command
void CSocketItemEx::SendReset()
{
	ControlBlock::seq_t seqR = pControlBlock->sendWindowFirstSN;
	ALIGN(FSP_ALIGNMENT) FSP_FixedHeader hdr;
	// Make sure that the packet falls into the receive window
	if (int32_t(pControlBlock->sendWindowNextSN - seqR) > 0)
		seqR = pControlBlock->sendWindowNextSN - 1;
	SetHeaderSignature(hdr, RESET);
	// To confuse the attacker?! The reason field is obfuscated by zero flags and receive window size
	hdr.ClearFlags();
	SetSequenceAndWS(&hdr, seqR);
	SetIntegrityCheckCode(& hdr);
	SendPacket(1, ScatteredSendBuffers(&hdr, sizeof(hdr)));
}



// Dispose on the demand of the remote peer. Let the garbage collector recycle the resource occupied
// See also Destroy() and *::KeepAlive case NON_EXISTENT
void CSocketItemEx::DisposeOnReset()
{
	lowState = NON_EXISTENT;	// But the ULA's state is kept
	// It is somewhat an NMI to ULA
	SignalFirstEvent(FSP_NotifyReset);
	ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);
}



// Presume that ULA has release upper-layer socket, recycle the LLS counterpart.
void CSocketItemEx::Recycle()
{
	lowState = NON_EXISTENT;
	RemoveTimers();
	UnmapControlBlock();
	CLowerInterface::Singleton.FreeItem(this);
}



// Send RESET to the remote peer to reject some request in pre-active state but keep local context.
// The RESET packet is not guaranteed to be received by the remote peer.
// ULA should use FSP_Reset command if it is to free local context.
void CSocketItemEx::Reject(uint32_t reasonCode)
{
	if (lowState >= ESTABLISHED)
		SendReset();
	else if (!IsPassive())
		CLowerInterface::Singleton.SendPrematureReset(reasonCode, this);
}



// Send RESET to the remote peer to reject some request in pre-active state.
// The RESET packet is not guaranteed to be received by the remote peer.
// The local context is free as well
// See also DisposeOnReset, Recycle
void CSocketItemEx::Reset()
{
	if (lowState >= ESTABLISHED)
		SendReset();
	else if (!IsPassive())
		CLowerInterface::Singleton.SendPrematureReset(FSP_Reset, this);
	Destroy();	// MUST signal event before Destroy
}



// Set the state to 'NON_EXISTENT', and make the resources be safely recyclable
// See also ~::KeepAlive case NON_EXISTENT
void CSocketItemEx::Destroy()
{
	if (_InterlockedExchange((PLONG)&idSrcProcess, 0) == 0)
		return;
	//
	try
	{
#ifdef TRACE
		printf_s("\nSCB of fiber#%u to be destroyed\n", fidPair.source);
#endif
		lowState = NON_EXISTENT;	// Do not [SetState(NON_EXISTENT);] as the ULA might do further cleanup
		markInUse = 0;
		RemoveTimers();
		UnmapControlBlock();
		//
		CLowerInterface::Singleton.FreeItem(this);
	}
	catch(...)
	{
		BREAK_ON_DEBUG();
		// UNRESOLVED! trap run-time exception and trace the calling stack, write error log
	}
}



// Given
//	bool		whether having obtained the mutex lock of the TLB
// Do
//	Abort the session at the LLS layer.
// Remark
//	Might send RESET packet to the remote end
void CSocketItemEx::AbortLLS(bool haveTLBLocked)
{
	if (pControlBlock != NULL
	&& InStates(ESTABLISHED, COMMITTING, COMMITTED, COMMITTING2, PEER_COMMIT, CLOSABLE, PRE_CLOSED))
	{
		SendReset();
	}
	//
	if (!haveTLBLocked)
	{
		Destroy();
		return;
	}
	// If TLB has been locked, 'Destroy' is simplified:
	RemoveTimers();
	UnmapControlBlock();
	CLowerInterface::Singleton.FreeItemDonotCareLock(this);
}



// Given
//	const void *	pointer to the buffer block to dump to the stdout stream
//	int				number of octets to be dumped
void LOCALAPI DumpHexical(const void *buf, int len)
{
	for(register int i = 0; i < len; i++)
	{
		printf("%02X ", ((const uint8_t *)buf)[i]);
	}
	printf("\n");
}



// Given
//	uint16_t *	pointer to the buffer block to dump to the stdout stream
//	int			number of 16-bit short words to be dumped
void LOCALAPI DumpNetworkUInt16(uint16_t * buf, int len)
{
	for(register int i = 0; i < len; i++)
	{
		printf("%04X ", be16toh(buf[i]));
	}
	printf("\n");
}
