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
	memset(poolFiberID, 0, sizeof(poolFiberID));
	//^ assert(NULL == 0)
	headFreeSID = & itemStorage[0];
	tailFreeSID = & itemStorage[MAX_CONNECTION_NUM - 1];

	register CSocketItemEx *p = headFreeSID;
	register int i = 0;
	while(i < MAX_CONNECTION_NUM)
	{
		poolFiberID[i] = p;
		poolFiberID[i++]->next = ++p;
		// other link pointers are already set to NULL
	}
	tailFreeSID->next = NULL;	// reset last 'next' pointer
	//
	SetMutexFree();
}



CSocketItemEx * CSocketSrvTLB::AllocItem()
{
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex, 1, 0))
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	CSocketItemEx *p = headFreeSID;
	if(p != NULL)
	{
		headFreeSID = p->next;
		if(headFreeSID == NULL)
			tailFreeSID = NULL;
		_InterlockedExchange8(& p->isReady, 0);
		// See also Extinguish()
		if(_InterlockedExchange8(& p->inUse, 1))
		{
			p->RemoveTimer();
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
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex, 1, 0))
	{
		Sleep(0);	// just yield out the CPU time slice
	}

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
			p->SetNotReadyUse();
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
		CSocketItemEx *p0 = poolFiberID[idListener & (MAX_CONNECTION_NUM - 1)];
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
			poolFiberID[idListener & (MAX_CONNECTION_NUM - 1)] = p;
		}
	}

	SetMutexFree();
	return p;
}


void CSocketSrvTLB::FreeItem(CSocketItemEx *p)
{
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex, 1, 0))
	{
		Sleep(0);	// just yield out the CPU time slice
	}
	//
	// It is deliberate to keep 'isReady'
	//
	// if it is allocated by AllocItem(ALFID_T idListener):
	if(p->IsPassive())
	{
		register CSocketItemEx *p1 = poolFiberID[p->fidPair.source & (MAX_CONNECTION_NUM - 1)];
		p->inUse = 0;
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
			poolFiberID[p->fidPair.source & (MAX_CONNECTION_NUM - 1)] = p1->prevSame;
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
		p = NULL;	// in case it is not
	}
	// postpone processing inUse until next allocation

	SetMutexFree();
}



CSocketItemEx * CSocketSrvTLB::operator[](ALFID_T id)
{
	register CSocketItemEx *p = poolFiberID[id & (MAX_CONNECTION_NUM-1)];
	do
	{
		if(p->fidPair.source == id)
			return p;
		p = p->prevSame;
	} while(p != NULL);
	return p;	// assert(p == NULL);
}



CSocketItemEx * CSocketSrvTLB::AllocItem(const CommandNewSessionSrv & cmd)
{
	while(_InterlockedCompareExchange8(& this->mutex, 1, 0))
	{
		Sleep(0);	// just yield out the CPU time slice
	}
	//
	CSocketItemEx *p = (*this)[cmd.fiberID];
	if(p != NULL)
	{
		if(_InterlockedCompareExchange8((char *) & p->inUse, 1, 0) != 0)
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



// Initialize the association of the remote end [represent by sockAddrTo] and the near end
// Side-effect: set the initial 'previous state'
// TODO: UNRESOLVED! hard-coded here, limit capacity of multi-home support?
void CSocketItemEx::InitAssociation()
{
	uint32_t idRemoteHost = pControlBlock->peerAddr.ipFSP.hostID;
	// 'source' field of fidPair shall be filled already. See also CInterface::PoolingALFIDs()
	// and CSocketSrvTLB::AllocItem(), AllocItem(ALFID_T)
	fidPair.peer = pControlBlock->peerAddr.ipFSP.fiberID;

	// See also CLowerInterface::EnumEffectiveAddresses
	register PSOCKADDR_INET const pFarEnd = sockAddrTo;
	if (!pControlBlock->nearEnd->IsIPv6())
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

	// the fiberID part of the first (most preferred local interface) FSP address has been set
	for (register int i = 1; i < MAX_PHY_INTERFACES; i++)
	{
		pControlBlock->nearEnd[i].idALF = fidPair.source;
	}
#ifndef NDEBUG
	printf_s("InitAssociation, fiber ID pair: (%u, %u)\n"
		, fidPair.source
		, fidPair.peer);
#endif
	lowState = pControlBlock->state;
	SetReady();
}



//
void LOCALAPI CSocketItemEx::SetRemoteFiberID(ALFID_T id)
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
	hEvent = cmd.hEvent;
	return true;

l_bailout1:
	CloseHandle(hMemoryMap);
l_bailout:
	CloseHandle(hThatProcess);
	return false;
}



// Given
//	FSP_SelectiveNACK::GapDescriptor *	the placeholder for the returned gap descriptors, shall be at of at least MAX_BLOCK_SIZE bytes
//	seq_t &								the placeholder for the returned maximum expected sequence number
// Return
//	Number of bytes taken by the gap descriptors, including the suffix fields of the SNACK header
//	negative indicates that some error occurred
// Remark
//	For milky payload this function should never be called
int32_t LOCALAPI CSocketItemEx::GenerateSNACK(FSP_PreparedKEEP_ALIVE &buf, ControlBlock::seq_t & seq0)
{
	FSP_SelectiveNACK::GapDescriptor *pGaps = buf.gaps;
	register int n = sizeof(buf.gaps) / sizeof(pGaps[0]);
	n = pControlBlock->GetSelectiveNACK(seq0, pGaps, n);
	if (n < 0)
	{
#ifdef TRACE
		printf_s("GetSelectiveNACK return -0x%X\n", n);
#endif
		return n;
	}

	// built-in rule: an optional header MUST be 64-bit aligned
	buf.n = n;
	FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)(pGaps + n);
	pSNACK->hs.Set<FSP_NormalPacketHeader, SELECTIVE_NACK>();
	while(--n >= 0)
	{
		pGaps[n].dataLength = htobe32(pGaps[n].dataLength);
		pGaps[n].gapWidth = htobe32(pGaps[n].gapWidth);
	}

	pSNACK->ackTime = htobe32((uint32_t)NowUTC());
	return int32_t((uint8_t *)pSNACK + sizeof(FSP_SelectiveNACK) - (uint8_t *)pGaps);
}




// INIT_CONNECT, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
void CSocketItemEx::InitiateConnect()
{
	TRACE_HERE("called");
	SetState(CONNECT_BOOTSTRAP);

	SConnectParam & initState = pControlBlock->connectParams;
	rand_w32((uint32_t *) & initState,
		( sizeof(initState.cookie)
		+ sizeof(initState.initCheckCode)
		+ sizeof(initState.salt)
		+ sizeof(initState.initialSN) ) / sizeof(uint32_t) );
	initState.timeStamp = NowUTC();
	// Remote fiber ID was set when the control block was created
	// for calculation of the initial round-trip time
	pControlBlock->connectParams.timeStamp = initState.timeStamp;
	pControlBlock->SetSendWindowHead(initState.initialSN);

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

	q->timeStamp = htobe64(initState.timeStamp);
	skb->SetFlag<IS_COMPLETED>();	// for resend
	// it neednot be unlocked
	SendPacket(1, ScatteredSendBuffers(q, sizeof(FSP_InitiateRequest)));
	// initState.timeStamp is not necessarily tRecentSend
	SetEarliestSendTime();

	if(timer != NULL)
	{
		TRACE_HERE ("\nInternal panic! Unclean connection reuse?\n"
					"Timer to acknowledge connect request is not cleared beforehand.");
		return;
	}
	tKeepAlive_ms = CONNECT_INITIATION_TIMEOUT_ms;
	AddTimer();
}



// CONNECT_REQUEST, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
// It is assumed that exclusive access to the socket has been gained
void LOCALAPI CSocketItemEx::AffirmConnect(const SConnectParam & initState, ALFID_T idListener)
{
	TRACE_HERE("called");

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend(); // Reuse what's occupied by INIT_CONNECT
	FSP_ConnectRequest *pkt = (FSP_ConnectRequest *)this->GetSendPtr(skb);
	if(pkt == NULL)
	{
		TRACE_HERE("memory corruption");
		return;
	}

	SetState(CONNECT_AFFIRMING);

	FSP_ConnectParam & varParams = pkt->params;
	pkt->cookie = initState.cookie;
	pkt->timeDelta = htobe32(initState.timeDelta);
	pkt->initialSN = htobe32(initState.initialSN);
	// assert(sizeof(initState.allowedPrefixes) >= sizeof(varParams.subnets));
	memcpy(varParams.subnets , initState.allowedPrefixes, sizeof(varParams.subnets));
	varParams.listenerID = idListener;
	varParams.hs.Set<MOBILE_PARAM>(sizeof(FSP_ConnectRequest) - sizeof(FSP_ConnectParam));
	pkt->hs.Set<FSP_ConnectRequest, CONNECT_REQUEST>();

	// while version remains as the same as the very beginning INIT_CONNECT
	skb->opCode = CONNECT_REQUEST;
	skb->len = sizeof(FSP_ConnectRequest);

	// TODO: UNRESOLVED! For FSP over IPv6, attach inititator's resource reservation...

	// Safely suppose that internal processing takes orders of magnitude less time than network propagation
	SendPacket(1, ScatteredSendBuffers(pkt, skb->len));	// it would set tRecentSend
	//
	tRoundTrip_us = uint32_t(min(UINT32_MAX, tRecentSend - tEarliestSend));
	// after ACK_CONNECT_REQ would 'tKeepAlive_ms = tRoundTrip_us >> 8';
}




// Given
//	FSPOperationCode		the opCode of the new inserted or updated to
// Do
//	Update the opCode of the head packet in the send queue to designated, or
//	insert a new packet of the designated opCode if the queue is still empty
// Remark
//	It is assumed that DLL/ULA is waiting for LLS when this subroutine is eventually called
void LOCALAPI CSocketItemEx::ReplaceSendQueueHead(FSPOperationCode opCode)
{
	ControlBlock::PFSP_SocketBuf skb;
	if(pControlBlock->CountSendBuffered() <= 0)
	{
		skb = pControlBlock->GetSendBuf();
		skb->len = 0;
	}
	else
	{
		skb = pControlBlock->GetSendQueueHead();
	}
	skb->opCode = opCode;
}


// Remark
//	For sake of congestion control only one packet is sent presently
// See also
//	OnConnectRequestAck; CSocketItemDl::ToWelcomeConnect; CSocketItemDl::ToWelcomeMultiply
void CSocketItemEx::SynConnect()
{
	TRACE_HERE("called");
	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();

	// See also CSocketItemEx::Start()
	if(lowState == ESTABLISHED)
		ReplaceSendQueueHead(PERSIST);
	else if(lowState == COMMITTING || lowState == COMMITTING2)
		ReplaceSendQueueHead(COMMIT);
	else // It MUST be in CHALLENGING state
		InstallEphemeralKey();
	//^ ephemeral session key material was ready when CSocketItemDl::PrepareToAccept

	EmitStart();
	pControlBlock->MoveNextToSend();

	if(timer != NULL)
	{
		TRACE_HERE ("\nInternal panic! Unclean connection reuse?\n"
					"Timer to acknowledge connect request is not cleared beforehand.");
		return;
	}

	tKeepAlive_ms = TRASIENT_STATE_TIMEOUT_ms;
	AddTimer();

	SetReturned();	// The success or failure signal is delayed until PERSIST, COMMIT or RESET received
}



//ACTIVE<-->[{duplication detected}: retransmit {in the new context}]
//      |<-->[{no listener}: Send {out-of-band} RESET]
//      |-->[API{Callback}{new context}]-->ACTIVE{new context}
//         |-->[{Return}:Accept]-->[Send PERSIST]
//         |-->[{Return}:Commit]-->[Send COMMIT]-->COMMITTING{new context}
//         |-->[{Return}:Reject]-->[Send RESET]-->NON_EXISTENT
void CSocketItemEx::OnMultiply()
{
}



//PEER_COMMIT-->/RESUME/-->ACTIVE-->[Send PERSIST]{restart keep-alive}
//COMMITTING2-->/RESUME/-->ACTIVE-->[Send PERSIST]
//CLOSABLE-->/RESUME/-->[API{callback}]
//	|-->[{Return Accept}]-->ACTIVE-->[Send PERSIST]{restart keep-alive}
//	|-->[{Return Commit}]-->COMMITTING-->[Send COMMIT]{enable retry}
//	|-->[{Return Reject}]-->NON_EXISTENT-->[Send RESET]
void CSocketItemEx::OnResume()
{
	// TODO: re-allocate send buffer/window and receive buffer/window
}



//CLOSED<-->/RESUME/{RDSC missed}<-->[Send ACK_INIT_CONNECT]
//	|-->/RESUME/{RDSC hit}-->[API{callback}]
//	|-->[{Return Accept}]-->ACTIVE-->[Send PERSIST]{start keep-alive}
//	|-->[{Return Commit}]-->COMMITTING-->[Send COMMIT]{enable retry}
//	|-->[{Return Reject}]-->NON_EXISTENT-->[Send RESET]
void CSocketItemEx::OnResurrect()
{
	// TODO: re-allocate buffers
}



// Dispose on the demand of the remote peer. Let the garbage collector recycle the resource occupied
// See also Extinguish() and *::TimeOut() {case NON_EXISTENT}
void CSocketItemEx::DisposeOnReset()
{
	_InterlockedExchange8((char *)pControlBlock->notices, FSP_NotifyReset);
	SetState(NON_EXISTENT);
	// It is somewhat an NMI to ULA
	SignalEvent();
	ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
}



// Do
//	Set the state to 'NON_EXISTENT', and make the resources be safely recyclable
// See also ~::TimeOut case NON_EXISTENT
void CSocketItemEx::Extinguish()
{
	SetState(NON_EXISTENT);
	RemoveTimer();
	CSocketItem::Destroy();
	inUse = 0;	// FreeItem does not reset it
	(CLowerInterface::Singleton())->FreeItem(this);
}


// Do
//	Commit the receive-side half-session on request of the remote end
//	Send ACK_FLUSH to the remote peer if not in CLOSED state and notify the near end ULA
void CSocketItemEx::PeerCommit()
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
	else // if (lowState == ESTABLISHED, CHALLENGING, CLONING, RESUMING, QUASI_ACTIVE)
	{
		StopKeepAlive();
		SetState(PEER_COMMIT);
	}
	//
	SendPacket<ACK_FLUSH>();

	Notify(FSP_NotifyToCommit);
}


// Do
//	Recycle the socket
//	Send RESET to the remote peer if not in CLOSED state
void CSocketItemEx::CloseSocket()
{
	if(!IsInUse())
		return;

	if(lowState == CLOSABLE)
		SetState(CLOSED);

	if (lowState != CLOSED)
	{
		Disconnect();
		return;
	}

	ReplaceTimer(SCAVENGE_THRESHOLD_ms);
	(CLowerInterface::Singleton())->FreeItem(this);
}


// Do
//	Shutdown the socket
void CSocketItemEx::CloseToNotify()
{
	ReplaceTimer(SCAVENGE_THRESHOLD_ms);
	SetState(CLOSED);
	(CLowerInterface::Singleton())->FreeItem(this);
	Notify(FSP_NotifyRecycled);
}


// Do
//	Send RESET to the remote peer in the certain states (not guaranteed to be received)
// See also ~::TimeOut case NON_EXISTENT
void CSocketItemEx::Disconnect()
{
	if(lowState == CHALLENGING || lowState == CONNECT_AFFIRMING)
		CLowerInterface::Singleton()->SendPrematureReset(EINTR, this);
	else if(InStates(7, ESTABLISHED, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE, RESUMING))
		SendPacket<RESET>();
	//
	if(TestAndLockReady())
	{
		Extinguish();
	}
	else
	{
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



void LOCALAPI DumpCMsgHdr(CtrlMsgHdr & hdrInfo)
{
	// Level: [0 for IPv4, 41 for IPv6]]
	printf("Len = %d, level = %d, type = %d, local interface address:\n"
		, hdrInfo.pktHdr.cmsg_len
		, hdrInfo.pktHdr.cmsg_level
		, hdrInfo.pktHdr.cmsg_type);
	DumpHexical((BYTE *) & hdrInfo.u, sizeof(hdrInfo.u));
}
