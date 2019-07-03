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
	if ((n = InterlockedIncrement(&topOfSC)) >= MAX_CONNECTION_NUM)
	{
		InterlockedDecrement(&topOfSC);
		return false;
	}

	scavengeCache[n].pSocket = pSocket;
	scavengeCache[n].timeRecycled = tNow;
	return true;
}


// allocate from the free list
CSocketItemEx * CSocketSrvTLB::AllocItem()
{
	CSocketItemEx *p;

	AcquireMutex();

	if (headFreeSID != NULL && headFreeSID->TestSetInUse())
		goto l_success;
#if 1
	ReleaseMutex();
	return NULL;
	// For a heavy duty server it might be beneficial to throttle the request by waiting for free socket
#else
	// as this is a prototype is not bothered to exploit hash table
	// recycle all of the orphan sockets
	register int i;
	for (i = 0, p = itemStorage; i < MAX_CONNECTION_NUM; i++, p++)
	{
		if (!p->IsProcessAlive())
			p->AbortLLS(true);
	}
	if (headFreeSID != NULL)
		goto l_success;

	timestamp_t tNow = NowUTC();
	CSocketItemEx *p1 = NULL;
	uint64_t tDiff0;
	// Reserved: a 'CLOSED' socket might be resurrected,
	// provides it is the original ULA process that is to reuse the socket
	if (topOfSC == 0)
	{
		for (i = 0, p = itemStorage; i < MAX_CONNECTION_NUM; i++, p++)
		{
			if (p->lowState == CLOSED)
				PutToScavengeCache(p, tNow);
		}
	}
	//
	if (topOfSC == 0)
	{
		// Found the least recent used socket
		for (i = 0, p = itemStorage; i < MAX_CONNECTION_NUM; i++, p++)
		{
			uint64_t tDiff = min(tNow - p->tLastRecv, tNow - p->tRecentSend);
			if ( (tDiff > KEEP_ALIVE_TIMEOUT_ms) && (p1 == NULL || tDiff > tDiff0))
				p1 = p, tDiff0 = tDiff;
		}
		//
		if (p1 == NULL)
		{
			ReleaseMutex();
			return NULL;
		}
	}
	else
	{
		p1 = scavengeCache[0].pSocket;
		topOfSC--;
		for (i = 0; i < topOfSC; i++)
		{
			scavengeCache[i] = scavengeCache[i++];
		}
	}

	p1->WaitUseMutex();		// it is throttling!
	p1->AbortLLS(true);
	assert(headFreeSID != NULL);
#endif

l_success:
	p = headFreeSID;
	headFreeSID = p->next;
	if (headFreeSID == NULL)
		tailFreeSID = NULL;
	ReleaseMutex();
	//
	p->next = NULL;
	p->TestSetInUse();
	return p;
}



// registration of passive socket: it is assumed that performance is out of question for a conceptual prototype
// allocate in the listeners' socket space
CSocketItemEx * CSocketSrvTLB::AllocItem(ALFID_T idListener)
{
	AcquireMutex();

	CSocketItemEx *p = NULL;
	// detect duplication fiber ID, remove 'brain-dead' socket
	for(register int i = 0; i < MAX_LISTENER_NUM; i++)
	{
		if (listenerSlots[i].TestSetInUse())
		{
			if (p != NULL)
				p->ClearInUse();
			p = &listenerSlots[i];
			// do not break, for purpose of duplicate allocation detection
		}
		else if (!listenerSlots[i].IsProcessAlive())
		{
			// we may reuse a socket created indirectly by a terminated process
			if (p != NULL)
				p->ClearInUse();
			p = &listenerSlots[i];
			p->AbortLLS(true);
			p->TestSetInUse();
			// do not break, for purpose of duplicate allocation detection
		}
		else if (listenerSlots[i].fidPair.source == idListener)
		{
#ifdef TRACE
			printf_s("\nCollision detected:\n"
					 "\twith process#%u, listener fiber#%u\n", listenerSlots[i].idSrcProcess, idListener);
#endif
			p = NULL;
			break;
		}
		else
		{
			continue;
		}
		//
		p->SetPassive();
		p->fidPair.source = idListener;
	}

	if (p != NULL)
		PutToListenTLB(p, be32toh(idListener) & (MAX_CONNECTION_NUM - 1));

	ReleaseMutex();
	return p;
}



// Given
//	CSocketItemEx *		pointer to the socket item to be inserted, might be updated
//	int					the 'compressed' hash key for searching the socket item
// Do
//	Insert the given socket item into the translation-look-aside buffer of listening sockets
void CSocketSrvTLB::PutToListenTLB(CSocketItemEx * p, int k)
{
	CSocketItemEx *p0 = tlbSockets[k];
	register CSocketItemEx *p1;
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
	p->inUse = 0;

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

	bzero(&p->contextOfICC, sizeof(ICC_Context));
	//^For sake of security enforcement.
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
		// We allow a socket slot waiting scavenge to be reused earlier than recycled. See also KeepAlive
		if(!p->TestSetInUse() && p->lowState != NON_EXISTENT)
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
#ifdef OVER_UDP_IPv4
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
#else
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



// Given
//	CommandNewSessionSrv	the command context
// Clone the control block whose handle is passed by the command and bind the interfaces
// Initialize near and remote fiber ID as well
// Return
//	true if succeeded
//	false if failed
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
#if (TRACE & TRACE_ULACALL)
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

#if (TRACE & TRACE_ULACALL)
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
#if (TRACE & TRACE_ULACALL)
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
	if (r < 0)
	{
#ifdef TRACE
		printf_s("\nSession #%u, cannot put soft interrupt %s(%d) into the queue.\n", fidPair.source, noticeNames[n], n);
#endif
		return false;
	}
	//
	if (r > 0)
	{
#if (TRACE & TRACE_ULACALL)
		if (r == FSP_MAX_NUM_NOTICE)
			printf_s("\nSession #%u, duplicate soft interrupt %s(%d) eliminated.\n", fidPair.source, noticeNames[n], n);
		else
			printf_s("\nSession #%u append soft interrupt %s(%d)\n", fidPair.source, noticeNames[n], n);
#endif
		return true;
	}
	//
	SignalEvent();
#if (TRACE & TRACE_ULACALL)
	printf_s("\nSession #%u raise soft interrupt %s(%d)\n", fidPair.source, noticeNames[n], n);
#endif
	return true;
}



// Given
//	FSP_PreparedKEEP_ALIVE& 	the placeholder for the returned gap descriptors, shall be of at least MAX_BLOCK_SIZE bytes
//	seq_t &						the placeholder for the returned maximum expected sequence number
//	int							the number of bytes that prefix the SNACK header
// Return
//	Number of bytes taken till the end of the gap descriptors, including the SNACK header and the prefix of the given length
//	negative indicates that some error occurred
// Remark
//	For milky payload this function should never be called
int32_t LOCALAPI CSocketItemEx::GenerateSNACK(FSP_PreparedKEEP_ALIVE &buf, ControlBlock::seq_t &seq0, int nPrefix)
{
	register int n = (sizeof(buf.gaps) + sizeof(FSP_FixedHeader) - nPrefix) / sizeof(buf.gaps[0]);
	//^ keep the unerlying IP packet from segmentation
	register FSP_SelectiveNACK::GapDescriptor *gaps = buf.gaps;
	n = pControlBlock->GetSelectiveNACK(seq0, gaps, n);
	if (n < 0)
	{
#ifdef TRACE
		printf_s("GetSelectiveNACK return -0x%X\n", -n);
#endif
		return n;
	}
	// Suffix the effective gap descriptors block with the FSP_SelectiveNACK struct
	// built-in rule: an optional header MUST be 64-bit aligned
	register FSP_SelectiveNACK* pSNACK = &buf.sentinel;
	// TODO: to minimize internal state to save
	// record the receive time of the most recently received packet
	register int32_t k = int32_t(seq0 - GetRecvWindowFirstSN()) - 1;
	if (k >= 0)
	{
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv();
		k += GetRecvWindowHeadPos();
		if (k - pControlBlock->recvBufferBlockN >= 0)
			k -= pControlBlock->recvBufferBlockN;
		if (k >= pControlBlock->recvBufferBlockN)
			return -EACCES;	// memory access error!
		skb += k;
		pSNACK->tLazyAck = htobe64(NowUTC() - skb->timeRecv);
#if (TRACE & TRACE_HEARTBEAT)
		printf_s("GetSelectiveNACK reported there were %d gap blocks.\n"
			"\tLazy acknowledgement delay = %lluus\n", n, be64toh(pSNACK->tLazyAck));
#endif
	}
	else
	{
		pSNACK->tLazyAck = 0;
	}
	buf.n = n;

	InterlockedIncrement(& nextOOBSN);	// Because lastOOBSN start from zero as well. See ValidateSNACK
	uint16_t lenSNACK = uint16_t(sizeof(FSP_SelectiveNACK) + sizeof(buf.gaps[0]) * n);
	pSNACK->_h.opCode = SELECTIVE_NACK;
	pSNACK->_h.mark = 0;
	pSNACK->_h.length = htobe16(lenSNACK);
	pSNACK->serialNo = htobe32(nextOOBSN);
#if BYTE_ORDER != LITTLE_ENDIAN
	while (--n >= 0)
	{
		gaps[n].dataLength = htole32(gaps[n].dataLength);
		gaps[n].gapWidth = htole32(gaps[n].gapWidth);
	}
#endif
	return nPrefix + lenSNACK;
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
	ReplaceTimer(INIT_RETRANSMIT_TIMEOUT_ms);
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
	pkt->timeDelta = htobe32(initState.timeDelta);
	pkt->cookie = initState.cookie;

	// while version remains as the same as the very beginning INIT_CONNECT
	skb->opCode = CONNECT_REQUEST;
	skb->len = sizeof(FSP_ConnectRequest);

	SetState(CONNECT_AFFIRMING);
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
	uint32_t salt = htobe32(nextOOBSN = ++srcItem->nextOOBSN);
	contextOfICC.InheritS0(srcItem->contextOfICC, seq0);
#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("\nTo send MULTIPLY in LLS, ICC context:\n"
		"\tSN of MULTIPLY to send = %09u, salt = %09u\n"
		"\tALFID of near end's branch = %u, ALFID of peer's parent = %u\n"
		, seq0, salt
		, fidPair.source, fidPair.peer);
#endif
	if (contextOfICC.keyLifeRemain != 0)
		DeriveKey(fidPair.source, fidPair.peer);

	// MULTIPLY can only be the very first packet
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	void * payload = GetSendPtr(skb);
	ALIGN(MAC_ALIGNMENT) FSP_FixedHeader q;
	lastOOBSN = 0;	// As the response from the peer, if any, is not an out-of-band packet

	SignHeaderWith(&q, MULTIPLY, sizeof(FSP_NormalPacketHeader), seq0, GetRecvWindowFirstSN());
	skb->CopyFlagsTo(& q);
	// Do not mess with 'salt'. New value has to be set after ICC is got
	void * paidLoad = SetIntegrityCheckCode(& q, payload, skb->len, salt);
	q.expectedSN = salt;
	if (paidLoad == NULL || skb->len > sizeof(this->cipherText))
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Cannot set ICC for the new MULTIPLY command");
		return;	// but it's an exception!
	}
	// Buffer the header in the queue for sake of retransmission on time-out. See also EmitStart() and KeepAlive()
	if (paidLoad != this->cipherText)
		memcpy(this->cipherText, paidLoad, skb->len);
	memcpy(payload, &q, sizeof(FSP_NormalPacketHeader));

	pControlBlock->SetFirstSendWindowRightEdge();
	SyncState();
	SendPacket(2, ScatteredSendBuffers(payload, sizeof(FSP_NormalPacketHeader), this->cipherText, skb->len));
	skb->MarkSent();
	//
	tSessionBegin = skb->timeSent = tRecentSend;	// UNRESOLVED!? But if SendPacket failed?
	tPreviousTimeSlot = tRecentSend;
	// tRoundTrip_us would be calculated when PERSIST is got, when tLastRecv is set as well
	ReplaceTimer(INIT_RETRANSMIT_TIMEOUT_ms);
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
	contextOfICC.snFirstRecvWithCurrKey = headPacket->pktSeqNo;
	//^See also ResponseToMultiply()
	InitAssociation();	// reinitialize with new peer's ALFID
	assert(fidPair.peer == headPacket->fidPair.source);

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("\nGet the acknowledgement ACK_START/PERSIST of MULTIPLY\n");
#endif
	if (!ValidateICC())
		return false;

#if defined(TRACE) && (TRACE & TRACE_OUTBAND)
	printf_s("Response of MULTIPLY was accepted, recvBufferBlockN = %d\n"
		"\tAllocated fiber#%u, peer's fiber#%u\n"
		, pControlBlock->recvBufferBlockN
		, fidPair.source, fidPair.peer);
#endif
	RestartKeepAlive();
	// And continue to accept the payload in the caller
	pControlBlock->SetRecvWindow(headPacket->pktSeqNo);
	return CLowerInterface::Singleton.PutToRemoteTLB((CMultiplyBacklogItem *)this);
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
void CMultiplyBacklogItem::ResponseToMultiply()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadRecv() + GetRecvWindowHeadPos();
	// if (!CheckMemoryBorder(skb)) throw -EFAULT;
	// See also PlacePayload
	BYTE *ubuf = GetRecvPtr(skb);
	if(ubuf == NULL)
	{
		AbortLLS();		// Used to be HandleMemoryCorruption();
		return;
	}

	// The opCode field is overriden to PERSIST for sake of clearer transmit transaction management
	skb->len = CopyOutPlainText(ubuf);
	CopyOutFVO(skb);
	skb->opCode = PERSIST;
	skb->ReInitMarkComplete();

	pControlBlock->recvWindowExpectedSN = ++pControlBlock->recvWindowNextSN;
	_InterlockedIncrement((LONG *)&pControlBlock->recvWindowNextPos);
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
		pControlBlock->notices.SetHead(FSP_NotifyDataReady);	// But do not signal until next packet is received
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
	if(lowState == CHALLENGING)
	{
		InstallEphemeralKey();
		//^ ephemeral session key material was ready when CSocketItemDl::PrepareToAccept
		EmitStart();
		pControlBlock->notices.SetHead(NullCommand);
		//^ The success or failure signal is delayed until ACK_START, PERSIST or RESET received
		ReplaceTimer(TRANSIENT_STATE_TIMEOUT_ms);	// The socket slot might be a reused one
	}
	else
	{
		// Timer has been set when the socket slot was prepared on getting MULTIPLY
		((CMultiplyBacklogItem *)this)->ResponseToMultiply();
	}
	//
	tPreviousTimeSlot = tRecentSend;
	tSessionBegin = tRecentSend;
	SetMutexFree();
}



// Send the abnormal 'RESET' command
void CSocketItemEx::SendReset()
{
	ControlBlock::seq_t seqR = pControlBlock->sendWindowFirstSN;
	ALIGN(MAC_ALIGNMENT) FSP_FixedHeader hdr;
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



// Set the state to 'NON_EXISTENT', and make the resources be safely recyclable
// See also ~::KeepAlive case NON_EXISTENT
void CSocketItemEx::Destroy()
{
	if (InterlockedExchange(&idSrcProcess, 0) == 0)
		return;
	//
	try
	{
#ifdef TRACE
		printf_s("\nSCB of fiber#%u to be destroyed\n", fidPair.source);
#endif
		lowState = NON_EXISTENT;	// Do not [SetState(NON_EXISTENT);] as the ULA might do further cleanup
		RemoveTimers();
		CSocketItem::Destroy();
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
	&& InStates(7, ESTABLISHED, COMMITTING, COMMITTED, COMMITTING2, PEER_COMMIT, CLOSABLE, PRE_CLOSED))
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
	CSocketItem::Destroy();
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
