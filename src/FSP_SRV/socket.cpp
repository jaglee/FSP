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

	forestFreeFlags = ~0;

	InitMutex();
}



// Return an available random ID. Here it is pre-calculated. Should be really random for better security
// In this implementation it is actually preprocessing for socket entry allocation
ALFID_T CSocketSrvTLB::AllocItemReserve()
{
	AcquireMutex();

	CSocketItemEx *p = headFreeSID;
	if (p == NULL)
	{
		p = headLRUitem;
		if (p == NULL)
		{
			ReleaseMutex();
			return 0;
		}
		// If there is only one socket entry available:
		if (p->next == NULL)
		{
			assert(p->rootULA == NULL);
			ReleaseMutex();
			return p->fidPair.source;
		}
		// The head of the LRU list is reused at first
		headLRUitem = (CSocketItemEx*)p->next;
	}
	else
	{
		headFreeSID = (CSocketItemEx*)p->next;
		if (headFreeSID == NULL)
			tailFreeSID = NULL;
	}
	// Attach the new allocated entry at the tail of the LRU list
	if (tailLRUitem == NULL)
	{
		p->prev = NULL;
		headLRUitem = tailLRUitem = p;
	}
	else
	{
		p->prev = tailLRUitem;
		tailLRUitem->next = p;
		tailLRUitem = p;
	}
	tailLRUitem->next = NULL;

	assert(p->rootULA == NULL);
	ReleaseMutex();
	return p->fidPair.source;
}


// Make the reserved socket entry whose associated local ALFID is given dedicated to the caller of the function
CSocketItemEx * CSocketSrvTLB::AllocItemCommit(SProcessRoot *pULA, ALFID_T idProactive)
{
	AcquireMutex();

	CSocketItemEx *p = (*this)[idProactive];
	if (p->IsInUse())
	{
		ReleaseMutex();
		return NULL;
	}

	if (p->prev == NULL)
	{
		headLRUitem = (CSocketItemEx *)p->next;
		if (headLRUitem == NULL)
			tailLRUitem = NULL;
	}
	else
	{
		p->prev->next = p->next;
	}
	if (p->next == NULL)
	{
		tailLRUitem = (CSocketItemEx *)p->prev;
		if (tailLRUitem == NULL)
			headLRUitem = NULL;
	}
	else
	{
		p->next->prev = p->prev;
	}

	assert(p->rootULA == NULL);
	p->AddKinshipTo(pULA);
	p->markInUse = 1;
	ReleaseMutex();
	return p;
}



// Allocate one socket entry from the global pool of free entries
CSocketItemEx* CSocketSrvTLB::AllocItem(SProcessRoot *pULA)
{
	CSocketItemEx* p;
	AcquireMutex();

	if (headFreeSID == NULL)
	{
		ReleaseMutex();
		return NULL;
	}

	p = headFreeSID;
	headFreeSID = (CSocketItemEx*)p->next;
	if (headFreeSID == NULL)
		tailFreeSID = NULL;
	else
		headFreeSID->prev = NULL;

	p->AddKinshipTo(pULA);
	p->markInUse = 1;
	ReleaseMutex();
	return p;
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
		if (r.IsInUse() && r.fidPair.source == idListener)
		{
#ifdef TRACE
			printf_s("\nCollision detected, listener fiber#%u\n", idListener);
#endif
			p = NULL;
			break;
		}
		else if (p == NULL && r.TestSetState(LISTENING))
		{
			p = &r;
			// do not break, for purpose of duplicate allocation detection
		}
	}

	if (p != NULL)
	{
		unsigned m = sizeof(CSocketItem) + sizeof(SProcessRoot *) + sizeof(CSocketItemEx *) * 2;
		bzero((octet *)p + m, sizeof(CSocketItemEx) - m);
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
// Return
//	true if it succeeded. if the entry has been registered in the TLB, return true. 
//	false if it failed, typically because some entry with the same ALFID has been registered
bool CSocketSrvTLB::PutToListenTLB(CSocketItemEx *p1, int k)
{
	register CSocketItemEx *p = tlbSockets[k];
	while (p != NULL)
	{
		if (p == p1)
			return true;
		if (p->fidPair.source == p1->fidPair.source)
		{
			REPORT_ERRMSG_ON_TRACE("collision found when putting socket into sockets TLB");
			return false;
		}
		p = p->prevSame;
	}
	p1->prevSame = tlbSockets[k];
	tlbSockets[k] = p1;
	return true;
}



// Given
//	CSocketItemEx *		pointer to the socket item to be detached
// Do
//	Detach the given socket item from the translation-look-aside buffer of listening sockets
// Return
//	true if the socket was registered in the TLB of listening sockets
//	false if the TLB cache missed
bool CSocketSrvTLB::DetachFromListenTLB(CSocketItemEx *p1)
{
	int k = be32toh(p1->fidPair.source) & (MAX_CONNECTION_NUM - 1);
	CSocketItemEx *p = tlbSockets[k];
	if (p == p1)
	{
		tlbSockets[k] = p->prevSame;
		return true;
	}
	while (p != NULL)
	{
		if (p->prevSame == p1)
		{
			p->prevSame = p1->prevSame;
			return true;
		}
		p = p->prevSame;
	}
	return false;
}



// Given
//	CSocketItemEx	The pointer to the socket item to free
// Do
//	Put the given socket item onto the free list
// Remark
//	Assume having obtained the lock of TLB. Will free the lock in the end.
void CSocketSrvTLB::FreeItemDonotCareLock(CSocketItemEx *p)
{
	assert(p->rootULA != NULL);
	p->RemoveULAKinship();

	p->allFlags = 0;
	p->Destroy();

	if (p->IsPassive())
	{
		DetachFromListenTLB(p);
		return;
	}

	DetachFromRemoteTLB(p);
	if (tailFreeSID == NULL)
	{
		headFreeSID = tailFreeSID = p;
	}
	else
	{
		tailFreeSID->next = p;
		p->prev = tailFreeSID;
		tailFreeSID = p;
	}
}



// Suppose it will automatically make the working thread terminated by closing the communication pipe
// DONOT 'reset' here, or else working thread may encounter memory access exception
bool CSocketSrvTLB::FreeULAChannel(SProcessRoot *pRoot)
{
	SProcessRoot& r = *pRoot;
	CLOSE_PIPE(r.sdPipe);

	AcquireMutex();

	CSocketItemEx *p = r.latest;
	CSocketItemEx *p1;
	while (p != NULL)
	{
		p1 = (CSocketItemEx *)p->prev;
		FreeItemDonotCareLock(p);
		p = p1;
	}
	assert(r.latest == NULL);
	forestFreeFlags |= 1 << r.index;

	ReleaseMutex();

	return true;
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
//	CSocketItemEx * The pointer to the socket to be put into the Remote Translate Look-aside Buffer
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
	assert(pItem->pControlBlock == NULL || pItem->idParent == pItem->pControlBlock->connectParams.idParent);
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
//	CSocketItemEx * The pointer to the socket to be detached
// Do
//	Detach the given socket from the Remote Translate Look-aside Buffer
// Return
//	true if the socket is registered in the remote TLB
//	false if TLB cache missed
bool CSocketSrvTLB::DetachFromRemoteTLB(CSocketItemEx *p1)
{
	int k = be32toh(p1->fidPair.peer) & (MAX_CONNECTION_NUM - 1);
	CSocketItemEx* p = tlbSocketsByRemote[k];
	if (p == p1)
	{
		tlbSocketsByRemote[k] = p->prevRemote;
		return true;
	}
	while (p != NULL)
	{
		if (p->prevRemote == p1)
		{
			p->prevRemote = p1->prevRemote;
			return true;
		}
		p = p->prevRemote;
	}
	return false;
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
	bool lockedHere;
	while (!(lockedHere = (_InterlockedCompareExchangePointer((PVOID*)&lockedAt, (PVOID)funcName, 0) == 0))
		&& IsInUse() && !resetPending)
	{
		if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			return false;
		Sleep(TIMER_SLICE_ms);	// if there is some thread that has exclusive access on the lock, wait patiently
	}

	if (!IsInUse() || resetPending)
	{
		if (lockedHere)
			lockedAt = 0;
		return false;
	}

	return true;
}



// Send RESET to the remote peer to abort some established connection if reset pending 
// See also DisposeOnReset, PutToResurrectable, Reject
// However, the RESET packet is not guaranteed to be received.
void CSocketItemEx::SetMutexFree()
{
	if (resetPending && pControlBlock != NULL && lowState >= ESTABLISHED)
		SendReset();
	if (resetPending)
		Free();
	lockedAt = NULL;
	if (callbackTimerPending)
		KeepAlive();
}



// Initialize the association of the remote end [represent by sockAddrTo] and the near end
// Side-effect: set the initial 'previous state'
// TODO: UNRESOLVED! hard-coded here, limit capacity of multi-home support?
void CSocketItemEx::InitAssociation()
{
	// 'source' field of fidPair shall be filled already. See also CInterface::PoolingALFIDs()
	// and CSocketSrvTLB::AllocItem(), AllocItem(ALFID_T)
	fidPair.peer = pControlBlock->peerAddr.ipFSP.fiberID;
	idParent = pControlBlock->connectParams.idParent;

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

	lowState = NON_EXISTENT;
	SyncState();
	//^So that tMigrate is set

	skb->ReInitMarkComplete();
	SendPacket(1, ScatteredSendBuffers(q, sizeof(FSP_InitiateRequest)));
	skb->timeSent = tRecentSend;

	ReplaceTimer(RETRANSMIT_INIT_TIMEOUT_ms);
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
	ReplaceTimer(RETRANSMIT_INIT_TIMEOUT_ms);
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
	// pControlBlock->connectParams.idParent was set in @DLL::ToPrepareMultiply()
	assert(idParent == pControlBlock->connectParams.idParent);	// Set in InitAssociation
	assert(fidPair.peer == srcItem->fidPair.peer);	// Set in InitAssociation

	ControlBlock::seq_t seq0 = pControlBlock->sendWindowNextSN;	// See also @DLL::ToPrepareMultiply
	nextOOBSN = ++srcItem->nextOOBSN;
	
	// The snFirstRecvWithCurrKey is unset until the first response packet is accepted.
	contextOfICC.snFirstSendWithCurrKey = seq0 + 1;
	contextOfICC.InheritS0(srcItem->contextOfICC);
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
	assert(this->contextOfICC.keyLifeRemain == 0 || paidLoad == this->cipherText); // TODO: when would the assertion fail?

	// Buffer the header in the queue for sake of retransmission on time-out. See also EmitStart() and KeepAlive()
	memcpy(payload, &q, sizeof(FSP_NormalPacketHeader));

	pControlBlock->SetFirstSendWindowRightEdge();
	lowState = NON_EXISTENT;
	SyncState();
	//^So that tMigrate is set

	// In case of race condition
	if (!WaitUseMutex())
	{
		BREAK_ON_DEBUG();
		return;
	}

	int r = SendPacket(2, ScatteredSendBuffers(payload, sizeof(FSP_NormalPacketHeader), this->cipherText, skb->len));
	if (r <= 0)
	{
		SignalNMI(FSP_NotifyReset);
		resetPending = 1;
		return;
	}

	skb->timeSent = tRecentSend;
	skb->MarkSent();
	SetFirstRTT(srcItem->tRoundTrip_us);
	tSessionBegin = skb->timeSent;
	tPreviousTimeSlot = skb->timeSent;
	tPreviousLifeDetection = tSessionBegin;
	ReplaceTimer(RETRANSMIT_INIT_TIMEOUT_ms);
	SetMutexFree();
}



// On getting the peer's response to MULTIPLY, fill in the proper field of contextOfICC
// so that the derived new session key is put into effect
// Remark
//	On get the peer's NULCOMMIT/PERSIST the socket would be put into the remote id's translate look-aside buffer
//	In some extreme situation the peer's NULCOMMIT/PERSIST to MULTIPLY could be received before tSessionBegin was set
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
	printf_s("\nGet the acknowledgement NULCOMMIT/PERSIST of MULTIPLY\n");
#endif
	if (!ValidateICC())
	{
		REPORT_ERRMSG_ON_TRACE("Invalid integrity check code for finalizing MULTIPLY!?");
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
// Digest the peer's MULTIPLY payload and make response designated by ULA transmitted
// See also OnGetMultiply(), @DLL::PrepareToAccept, ToWelcomeMultiply
void CMultiplyBacklogItem::RespondToMultiply()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv() + GetRecvWindowHeadPos();
	// See also PlacePayload
	octet*ubuf = GetRecvPtr(skb);
	if(ubuf == NULL)
	{
		SignalNMI(FSP_MemoryCorruption);
		Reset();
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
		NotifyDataReady(FSP_NotifyToCommit);
	}
	else
	{
		SetState(skbOut->GetFlag<TransactionEnded>() ? COMMITTING : ESTABLISHED);
		NotifyDataReady();
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
	// See also @DLL::ToWelcomeConnect:
	pControlBlock->SetFirstSendWindowRightEdge();
#if (TRACE & TRACE_SLIDEWIN)
	printf_s("%s: local fiber#%u(_%X_) in state %s\n", __FUNCTION__
		, fidPair.source, be32toh(fidPair.source)
		, stateNames[lowState]);
	pControlBlock->DumpSendRecvWindowInfo();
#endif
	if (lowState == CHALLENGING)
	{
		// Timer has been set when the socket slot was allocated on getting CONNECT_REQUEST
		InstallEphemeralKey();
		//^ ephemeral session key material was ready when CSocketItemDl::PrepareToAccept
		SetFirstRTT(pControlBlock->connectParams.tDiff);
		//
		EmitStart();
		tSessionBegin = tRecentSend;
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
	// It is somewhat an NMI to ULA
	SignalNMI(FSP_NotifyReset);
	resetPending = 1;
}



// Send RESET to the remote peer to reject some request in pre-active state but keep local context.
// The RESET packet is not guaranteed to be received by the remote peer.
// ULA should use FSP_Reset command if it is to free local context.
// TODO:
void CSocketItemEx::Reject(const CommandRejectRequest& r)
{
	if (lowState >= ESTABLISHED)
		SendReset();
	else if (!IsPassive())
		CLowerInterface::Singleton.SendPrematureReset(r.reasonCode, this);
}



// Embedded code of setting the mutex lock of WaitUseMutex,
// utilize SetMutexFree to do reset safely if the mutex lock is not immediately available
void CSocketItemEx::Reset()
{
	bool lockedHere = (_InterlockedCompareExchangePointer((PVOID*)&lockedAt, (PVOID)__FUNCTION__, NULL) == NULL);
	resetPending = 1;
	if (lockedHere)
		SetMutexFree();
}



void CSocketItemEx::Free()
{
	try
	{
#ifdef TRACE
		printf_s("\nSCB of fiber#%u to be destroyed\n", fidPair.source);
#endif
		lowState = NON_EXISTENT;	// Do not [SetState(NON_EXISTENT);] as the ULA might do further cleanup
		RemoveTimers();
		CLowerInterface::Singleton.FreeItem(this);
	}
	catch(...)
	{
		BREAK_ON_DEBUG();
		// UNRESOLVED! trap run-time exception and trace the calling stack, write error log
	}
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
