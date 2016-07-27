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

// defined in os_win.cpp
extern bool IsProcessAlive(DWORD);



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


// allocate from the free list
CSocketItemEx * CSocketSrvTLB::AllocItem()
{
	AcquireMutex();

	CSocketItemEx *p = headFreeSID;
	if(p != NULL)
	{
		headFreeSID = p->next;
		if(headFreeSID == NULL)
			tailFreeSID = NULL;
		_InterlockedExchange8(& p->isReady, 0);
		// See also Destroy()
		if(_InterlockedExchange8(& p->inUse, 1))
		{
			p->RemoveTimers();
			p->Destroy();
		}
		//
		p->next = NULL;
	}

	SetMutexFree();
	return p;
}


// allocate in the listner space
CSocketItemEx * CSocketSrvTLB::AllocItem(ALFID_T idListener)
{
	AcquireMutex();

	CSocketItemEx *p = NULL;
	// registeration of passive socket: it is assumed that performance is seldom a concern, at least initially
	// detect duplication fiber ID.
	for(register int i = 0; i < MAX_LISTENER_NUM; i++)
	{
		if(! listenerSlots[i].inUse && p == NULL)
		{
			p = & listenerSlots[i];
			p->SetPassive();
			p->fidPair.source = idListener;
			p->isReady = 0;
			p->SetInUse();
			// do not break, for purpose of duplicate allocation detection
		}
		else if(listenerSlots[i].inUse && listenerSlots[i].fidPair.source == idListener)
		{
			if(p != NULL)
				p->inUse = 0;
			// we may reuse of a socket created by a terminated process
			p = & listenerSlots[i];
			if(IsProcessAlive(p->idSrcProcess))
			{
				TRACE_HERE("collision of listener fiber ID detected!");
				p = NULL;
			}
			break;
		}
	}

	if(p != NULL)
	{
		int k = be32toh(idListener) & (MAX_CONNECTION_NUM - 1);
		CSocketItemEx *p0 = tlbSockets[k];
		register CSocketItemEx *p1;
		// TODO: UNRESOLVED! Is it unnecessary to detect the stale entry?
		for(p1 = p0; p1 != NULL; p1 = p1->prevSame)
		{
			if(p == p1) break;
			//
			if(p->fidPair.source == p1->fidPair.source)
			{
				p = NULL;
				break;
			}
		}
		if(p1 == NULL && p != NULL)
		{
			p->prevSame = p0;
			tlbSockets[k] = p;
		}
	}

	SetMutexFree();
	return p;
}



// Given
//	CSocketItemEx	The pointer to the socket item to free
// Do
//	Put the given socket item onto the free list
void CSocketSrvTLB::FreeItem(CSocketItemEx *p)
{
	AcquireMutex();
	//
	// It is deliberate to keep 'isReady'
	//
	// if it is allocated by AllocItem(ALFID_T idListener):
	if(p->IsPassive())
	{
		int k = be32toh(p->fidPair.source) & (MAX_CONNECTION_NUM - 1);
		register CSocketItemEx *p1 = tlbSockets[k];
		_InterlockedExchange8(& p->inUse, 0);
		// detach it from the hash collision list
		if(p1 != p)
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
			if(p1 == NULL)
				REPORT_ERRMSG_ON_TRACE("A passive socket to be free is not an instance allocated properly");
		}
		else if(p1->prevSame != NULL)
		{
			tlbSockets[k] = p1->prevSame;
		}
		// else keep at least one entry in the context-addressing TLB
		SetMutexFree();
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
		p->next = NULL;	// in case it is not
	}
	//
	_InterlockedExchange8(& p->inUse, 0);

	SetMutexFree();
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
	return p;	// assert(p == NULL);
}



// Given
//	CommandNewSessionSrv	The 'new session' command
// Return
//	The new socket item, with control block memory mapped
CSocketItemEx * CSocketSrvTLB::AllocItem(const CommandNewSessionSrv & cmd)
{
	AcquireMutex();
	//
	CSocketItemEx *p = (*this)[cmd.fiberID];
	if(p != NULL)
	{
		// We allow a socket slot waiting scavenge to be reused ealier than recycled. See also KeepAlive
		if(_InterlockedCompareExchange8((char *) & p->inUse, 1, 0) != 0 && p->lowState != NON_EXISTENT)
		{
			p = NULL;
			goto l_return;
		}
		if(! p->MapControlBlock(cmd))
		{
			TRACE_HERE("Control block shall be created by the ULA via DLL call already");
			p->inUse = 0;	// No, you cannot 'FreeItem(p);' because mutex is SHARED_BUSY
			p = NULL;
			goto l_return;
		}
		p->SetReady();
	}
l_return:
	SetMutexFree();
	return p;
}



// Given
//	CSocketItemEx * The pointer to the socket that to be put into the Remote Translate Look-aside Buffer
// Return
//	true if success
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
			TRACE_HERE("Found collision when put to remote ALFID's translate look-aside buffer");
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



// Initialize the association of the remote end [represent by sockAddrTo] and the near end
// Side-effect: set the initial 'previous state'
// TODO: UNRESOLVED! hard-coded here, limit capacity of multi-home support?
void CSocketItemEx::InitAssociation()
{
	uint32_t idRemoteHost = pControlBlock->peerAddr.ipFSP.hostID;
	// 'source' field of fidPair shall be filled already. See also CInterface::PoolingALFIDs()
	// and CSocketSrvTLB::AllocItem(), AllocItem(ALFID_T)
	fidPair.peer = pControlBlock->peerAddr.ipFSP.fiberID;
	idParent = pControlBlock->idParent;

	// See also CLowerInterface::EnumEffectiveAddresses
	register PSOCKADDR_INET const pFarEnd = sockAddrTo;
	if (!pControlBlock->nearEndInfo.IsIPv6())
	{
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			memset(&pFarEnd[i], 0, sizeof(pFarEnd[i]));
			pFarEnd[i].Ipv4.sin_family = AF_INET;
			pFarEnd[i].Ipv4.sin_addr.S_un.S_addr
				= ((PFSP_IN4_ADDR_PREFIX) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[i])->ipv4;
			pFarEnd[i].Ipv4.sin_port = DEFAULT_FSP_UDPPORT;
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALF = fidPair.peer;
		}
		// namelen = sizeof(SOCKADDR_IN);
	}
	else
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pFarEnd[i].Ipv6.sin6_family = AF_INET6;
			pFarEnd[i].Ipv6.sin6_flowinfo = 0;
			pFarEnd[i].Ipv6.sin6_port = 0;
			pFarEnd[i].Ipv6.sin6_scope_id = 0;
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->u.subnet
				= pControlBlock->peerAddr.ipFSP.allowedPrefixes[i];
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idHost = idRemoteHost;
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALF = fidPair.peer;
		}
		// namelen = sizeof(SOCKADDR_IN6);
	}

#ifndef NDEBUG
	printf_s("InitAssociation, fiber ID pair: (%u, %u)\n"
		, be32toh(fidPair.source)
		, be32toh(fidPair.peer));
#endif

	lowState = pControlBlock->state;
	InitializeSRWLock(& rtSRWLock);
	SetReady();
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



// Clone the control block whose handle is passed by the command and bind the interfaces
// Initialize near and remote fiber ID as well
bool CSocketItemEx::MapControlBlock(const CommandNewSessionSrv &cmd)
{
#ifndef NDEBUG
	printf_s(__FUNCDNAME__ " called, source process id = %d, size of the shared memory = 0x%X\n", cmd.idProcess, cmd.dwMemorySize);
#endif
	// TODO: UNRESOLVED! To be reviewed: is it safe to reuse the shared memory?
	if(idSrcProcess == cmd.idProcess && hSrcMemory == cmd.hMemoryMap)
		return true;

	if(hMemoryMap != NULL)
		Destroy();

	HANDLE hThatProcess = OpenProcess(PROCESS_DUP_HANDLE
		, false
		, cmd.idProcess);
	if(hThatProcess == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return false;
	}
#ifdef TRACE
	printf_s("Handle of the source process is %I64X, handle of the shared memory in the source process is %I64X\n"
		, (long long)hThatProcess
		, (long long)cmd.hMemoryMap);
#endif

	// get the near-end shared memory handle
	if(! DuplicateHandle(hThatProcess
		, cmd.hMemoryMap
		, GetCurrentProcess()
		, & hMemoryMap
		, 0	// ignored, because of the duplicate same access option
		, FALSE
		, DUPLICATE_SAME_ACCESS))
	{
		REPORT_ERROR_ON_TRACE();
		goto l_bailout;
	}

#ifdef TRACE
	printf_s("Handle of the mapped memory in current process is %I64X\n", (long long)hMemoryMap);
#endif

	dwMemorySize = cmd.dwMemorySize;
	pControlBlock = (ControlBlock *)MapViewOfFile(hMemoryMap
		, FILE_MAP_ALL_ACCESS
		, 0, 0, dwMemorySize);
	if(pControlBlock == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		goto l_bailout1;
	}
#ifdef TRACE
	printf_s("Successfully take use of the shared memory object.\r\n");
#endif

	CloseHandle(hThatProcess);
	// this->fiberID == cmd.fiberID, provided it is a passive/welcome socket, not a initiative socket
	// assert: the queue of the returned value has been initialized by the caller already
	idSrcProcess = cmd.idProcess;
	hEvent = cmd.hEvent;
	return true;

l_bailout1:
	CloseHandle(hMemoryMap);
l_bailout:
	CloseHandle(hThatProcess);
	return false;
}



// Given
//	FSP_PreparedKEEP_ALIVE& 	the placeholder for the returned gap descriptors, shall be at of at least MAX_BLOCK_SIZE bytes
//	seq_t &						the placeholder for the returned maximum expected sequence number
//	int							the number of bytes that prefix the SNACK header
// Return
//	Number of bytes taken by the gap descriptors, including the suffix fields of the SNACK header and the prefix of the given length
//	negative indicates that some error occurred
// Remark
//	For milky payload this function should never be called
int32_t LOCALAPI CSocketItemEx::GenerateSNACK(FSP_PreparedKEEP_ALIVE &buf, ControlBlock::seq_t &seq0, int nPrefix)
{
	FSP_SelectiveNACK::GapDescriptor *pGaps = buf.gaps;
	register int n = sizeof(buf.gaps) / sizeof(pGaps[0]);
	n = pControlBlock->GetSelectiveNACK(seq0, pGaps, n);
	if (n < 0)
	{
#ifdef TRACE
		printf_s("GetSelectiveNACK return -0x%X\n", -n);
#endif
		return n;
	}
#ifdef TRACE
	if(n > 0)
		printf_s("GetSelectiveNACK reported there were %d gap blocks.\n", n);
#endif
	// Suffix the effective gap descriptors block with the FSP_SelectiveNACK struct
	// built-in rule: an optional header MUST be 64-bit aligned
	// I don't know why, but set buf.n sometime cause memory around some stack variable corruptted!?
	register FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)(pGaps + n);
	buf.n = n;
	while(--n >= 0)
	{
		pGaps[n].dataLength = htobe32(pGaps[n].dataLength);
		pGaps[n].gapWidth = htobe32(pGaps[n].gapWidth);
	}

	++nextOOBSN;	// Because lastOOBSN start from zero as well. See ValidateSNACK
	pSNACK->serialNo = htobe32(nextOOBSN);
	pSNACK->hs.Set(SELECTIVE_NACK, nPrefix);
	return int32_t((uint8_t *)pSNACK + sizeof(FSP_SelectiveNACK) - (uint8_t *)pGaps) + nPrefix;
}



// INIT_CONNECT, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
void CSocketItemEx::InitiateConnect()
{
	TRACE_HERE("called");
	SetState(CONNECT_BOOTSTRAP);

	// Note tht we cannot put initial SN into ephemeral session key as the peers do not have the same initial SN
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
	// Overlay INIT_CONNECT and CONNECT_REQUEST
	FSP_ConnectRequest *q = (FSP_ConnectRequest *)GetSendPtr(skb);
	if(q == NULL)
	{
		TRACE_HERE("Memory corruption!");
		return;
	}
	q->initCheckCode = initState.initCheckCode;
	q->salt = initState.salt;
	q->hs.Set<FSP_InitiateRequest, INIT_CONNECT>();	// See also AffirmConnect()

	q->timeStamp = initState.nboTimeStamp;
	skb->SetFlag<IS_COMPLETED>();	// for resend
	skb->timeSent = NowUTC();		// SetEarliestSendTime();
	// it neednot be unlocked
	SendPacket(1, ScatteredSendBuffers(q, sizeof(FSP_InitiateRequest)));

	tKeepAlive_ms = INIT_RETRANSMIT_TIMEOUT_ms;
	AddTimer();
}



// CONNECT_REQUEST, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
// It is assumed that exclusive access to the socket has been gained
void CSocketItemEx::AffirmConnect(const SConnectParam & initState, ALFID_T idListener)
{
	TRACE_HERE("called");

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend(); // Reuse what's occupied by INIT_CONNECT
	FSP_ConnectRequest *pkt = (FSP_ConnectRequest *)this->GetSendPtr(skb);
	if(pkt == NULL)
	{
		TRACE_HERE("memory corruption");
		return;
	}
	tRoundTrip_us = uint32_t(min(UINT32_MAX, NowUTC() - skb->timeSent));

	// Because CONNECT_REQUEST overlay INIT_CONNECT these three fields are reused
	//pkt->timeStamp = initState.nboTimeStamp;
	//pkt->initCheckCode = initState.initCheckCode;
	//pkt->salt = initState.salt;
	pkt->initialSN = htobe32(initState.initialSN);
	pkt->timeDelta = htobe32(initState.timeDelta);
	pkt->cookie = initState.cookie;
	// assert(sizeof(initState.allowedPrefixes) >= sizeof(varParams.subnets));
	memcpy(pkt->params.subnets , initState.allowedPrefixes, sizeof(pkt->params.subnets));
	pkt->params.listenerID = idListener;
	pkt->params.hs.Set(PEER_SUBNETS, sizeof(FSP_ConnectRequest) - sizeof(FSP_ConnectParam));
	pkt->hs.Set<FSP_ConnectRequest, CONNECT_REQUEST>();

	// while version remains as the same as the very beginning INIT_CONNECT
	skb->opCode = CONNECT_REQUEST;
	skb->len = sizeof(FSP_ConnectRequest);

	// TODO: UNRESOLVED! For FSP over IPv6, attach inititator's resource reservation...

	// Safely suppose that internal processing takes orders of magnitude less time than network propagation
	SetState(CONNECT_AFFIRMING);
	SendPacket(1, ScatteredSendBuffers(pkt, skb->len));	// it would set tRecentSend
}



// MULTIPLY, SequenceNo, Salt, ICC, FREWS[, payload]
// See InitiateConnect and @DLL ULA FSPAPI ConnectMU
// Given
//	CSocketItemEx *		Pointer to the source socket slot. The nextOOBSN field would be updated
// Remark
//	On get peer's COMMIT or PERSIST the socket would be put into the remote id's translate look-aside buffer
// See also
//	OnConnectRequestAck; CSocketItemDl::ToWelcomeConnect; CSocketItemDl::ToWelcomeMultiply
void CSocketItemEx::InitiateMultiply(CSocketItemEx *srcItem)
{
	TRACE_HERE("called");

	// Inherit the interfaces, excluding the last one which is ephemeral 
	memcpy(this->sockAddrTo, srcItem->sockAddrTo, sizeof(SOCKADDR_INET) * MAX_PHY_INTERFACES);
	pControlBlock->nearEndInfo.idALF = fidPair.source;	// and pass back to DLL/ULA
	pControlBlock->connectParams = srcItem->pControlBlock->connectParams;
	InitAssociation();

	// Note tht we cannot put initial SN into ephemeral session key as the peers do not have the same initial SN
	// Share the same session key at first:
	ControlBlock::seq_t seq0 = srcItem->pControlBlock->sendWindowNextSN;
	contextOfICC.prev = srcItem->contextOfICC.curr;
	contextOfICC.savedCRC = false;
	contextOfICC.firstSendSNewKey = seq0 + 1;
	contextOfICC.keyLife = pControlBlock->connectParams.keyLife;
	DeriveNextKey();
	// But the firstRecvSNewKey is set until the first response packet is accepted.
	pControlBlock->connectParams.initialSN = seq0;

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("To send MULTIPLY in LLS, sendBufferBlockN = %d\n"
			"\tParent's fid = 0x%X, allocated fid = 0x%X, peer's fid = 0x%X\n"
		, pControlBlock->sendBufferBlockN
		, idParent, fidPair.source, fidPair.peer);
#endif

	pControlBlock->sendWindowFirstSN = seq0;
	assert(pControlBlock->sendWindowHeadPos == 0);
	pControlBlock->sendWindowNextSN = seq0 + pControlBlock->sendWindowNextPos;
	pControlBlock->sendBufferNextSN = seq0 + pControlBlock->sendBufferNextPos;

	// MULTIPLY can only be the very first packet
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	FSP_NormalPacketHeader q;
	nextOOBSN = ++ srcItem->nextOOBSN;
	lastOOBSN = 0;	// As the response from the peer, if any, is not an out-of-band packet
	q.Set(MULTIPLY, sizeof(FSP_NormalPacketHeader), seq0, nextOOBSN, pControlBlock->recvBufferBlockN);

	void * paidLoad = SetIntegrityCheckCode(& q, GetSendPtr(skb), skb->len, q.expectedSN);
	if (paidLoad == NULL)
	{
		TRACE_HERE("Cannot set ICC for the new MULTIPLY command");
		return;	// but it's an exception!
	}
	//
	tSessionBegin = skb->timeSent = NowUTC();	// UNRESOLVED!? But if SendPacket failed?
	SendPacket(2, ScatteredSendBuffers(&q, sizeof(FSP_NormalPacketHeader), paidLoad, skb->len));

	// tRoundTrip_us would be calculated when PERSIST or COMMIT is got, when tLastRecv is set as well
	ReplaceTimer(INIT_RETRANSMIT_TIMEOUT_ms);
}



// On getting the peer's response to MULTIPLY, fill in the proper field of contextOfICC
// so that the derived new session key is put into effect
bool CSocketItemEx::FinalizeMultiply()
{
	contextOfICC.firstRecvSNewKey = headPacket->pktSeqNo;
	fidPair.peer = headPacket->idPair.source;
	if (!ValidateICC())
	{
		TRACE_HERE("Invalid intergrity check code of PERSIST to MULTIPLY!?");
		return false;
	}

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("Response of MULTIPLY was received in LLS, recvBufferBlockN = %d\n"
			"\tParent's fid = 0x%X, allocated fid = 0x%X, peer's fid = 0x%X\n"
		, pControlBlock->recvBufferBlockN
		, idParent, fidPair.source, fidPair.peer);
#endif

	// And continue to accept the payload in the caller
	pControlBlock->SetRecvWindow(headPacket->pktSeqNo);
	return CLowerInterface::Singleton()->PutToRemoteTLB((CMultiplyBacklogItem *)this);
}



// Congest the peer's MULTIPLY payload and make response designated by ULA transmitted
// See also OnGetMultiply(), @DLL::PrepareToAccept
void CMultiplyBacklogItem::ResponseToMultiply()
{
	ALFID_T & idParent = pControlBlock->idParent;

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("To make response to MULTIPLY, parent's fid = 0x%X\n", idParent);
#endif

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetFirstReceived();
	// if (!CheckMemoryBorder(skb)) throw -EFAULT;
	// See also PlacePayload
	BYTE *ubuf = GetRecvPtr(skb);
	if(ubuf == NULL)
	{
		HandleMemoryCorruption();
		return;
	}
	bool eot = this->IsEndOfMessage();
	skb->len = CopyOutPlainText(ubuf);
	skb->SetFlag<TO_BE_CONTINUED>(!eot);
	if (eot)	// See also @DLL::ToWelcomeMultiply
		SetState(pControlBlock->state == COMMITTING ? COMMITTING2 : PEER_COMMIT);
	else
		lowState = pControlBlock->state;
	// Should lowState == NON_EXISTENT before. See also OnGetMultiply

	// assume contextOfICC, including firstRecvSNewKey and firstSendSNewKey has been set properly
	DeriveNextKey();
	EmitStart();
}



// Remark
//	For sake of congestion control only one packet is sent presently
// See also
//	OnConnectRequestAck; CSocketItemDl::ToWelcomeConnect; CSocketItemDl::ToWelcomeMultiply
void CSocketItemEx::Accept()
{
	TRACE_HERE("called");

	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();
	if(lowState == CHALLENGING)
	{
		ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);	// The socket slot might be a reused one
		InstallEphemeralKey();
		//^ ephemeral session key material was ready when CSocketItemDl::PrepareToAccept
		EmitStartAndSlide();
		// ACK_CONNECT_REQUEST is resent on requested only. See also CSocketItemEx::Start()
	}
	else
	{
		// Timer has been set when the socket slot was prepared on getting MULTIPLY
		((CMultiplyBacklogItem *)this)->ResponseToMultiply();
	}
	tSessionBegin = tRecentSend;	// See also CSocketItemEx::OnConnectRequestAck
	SetCallable();	// The success or failure signal is delayed until PERSIST, COMMIT or RESET received
}



// Dispose on the demand of the remote peer. Let the garbage collector recycle the resource occupied
// See also Destroy() and *::KeepAlive case NON_EXISTENT
void CSocketItemEx::DisposeOnReset()
{
	SetState(NON_EXISTENT);
	// It is somewhat an NMI to ULA
	SignalFirstEvent(FSP_NotifyReset);
	ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
}



// Do
//	Set the state to 'NON_EXISTENT', and make the resources be safely recyclable
// See also ~::KeepAlive case NON_EXISTENT
void CSocketItemEx::Destroy()
{
	try
	{
		lowState = NON_EXISTENT;	// SetState(NON_EXISTENT);
		RemoveTimers();
		CSocketItem::Destroy();
		isReady = 0;	// FreeItem does not reset it
		(CLowerInterface::Singleton())->FreeItem(this);
	}
	catch(...)
	{
		// UNRESOLVED! trap run-time exception and trace the calling stack, write error log
	}
}



// Do
//	Recycle the socket
//	Send RESET to the remote peer if not in CLOSED state
void CSocketItemEx::Recycle()
{
	if(!IsInUse())
		return;
	//
	if (lowState != CLOSED && lowState != LISTENING)
	{
#ifdef TRACE
		printf_s("Recycle called in %s(%d) state\n", stateNames[lowState], lowState);
#endif
		RejectOrReset();
		return;
	}
	// See also RejectOrReset, Destroy and @DLL::RespondToRecycle
	pControlBlock->state = NON_EXISTENT;
	SignalFirstEvent(FSP_NotifyRecycled);
	Destroy();
}



// Do
//	Send RESET to the remote peer in the certain states (not guaranteed to be received)
// See also ~::KeepAlive case NON_EXISTENT
void CSocketItemEx::RejectOrReset()
{
	if(lowState == CHALLENGING || lowState == CONNECT_AFFIRMING)
		CLowerInterface::Singleton()->SendPrematureReset(EINTR, this);
	else if(InStates(6, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE))
		SendPacket<RESET>();
	//
	pControlBlock->state = NON_EXISTENT;
	SignalFirstEvent(FSP_NotifyRecycled);
	// See also DisposeOnReset, Recycle
	if(TestAndLockReady())
	{
		Destroy();
	}
	else
	{
		// It could be lazily Destroyed
		SetState(NON_EXISTENT);
		ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
	}
}



void LOCALAPI DumpHexical(BYTE * buf, int len)
{
	for(register int i = 0; i < len; i++)
	{
		printf("%02X ", buf[i]);
	}
	printf("\n");
}



void LOCALAPI DumpNetworkUInt16(uint16_t * buf, int len)
{
	for(register int i = 0; i < len; i++)
	{
		printf("%04X ", be16toh(buf[i]));
	}
	printf("\n");
}



// An auxillary function handling the fixed header
// Given
//	FSPOperationCode
//	uint16_t	The total length of all the headers
//	uint32_t	The sequenceNo field in host byte order
//	uint32_t	The expectedNo field in host byte order
//	uint32_t	The advertised receive window size, in host byte order
// Do
//	Filled in the fixed header
void LOCALAPI FSP_NormalPacketHeader::Set(FSPOperationCode code, uint16_t hsp, uint32_t seqThis, uint32_t seqExpected, int32_t advRecvWinSize)
{
	hs.Set(code, hsp);
	expectedSN = htobe32(seqExpected);
	sequenceNo = htobe32(seqThis);
	ClearFlags();
	SetRecvWS(advRecvWinSize);
}
