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

// Initialize the control message header
//	WSABUF &	reference to the internal storage of control message
CtrlMsgHdr::CtrlMsgHdr(WSABUF & control)
{
	memset(this, 0, sizeof(CtrlMsgHdr));
	memcpy(this, control.buf, min(control.len, sizeof(CtrlMsgHdr)));
}



CSocketSrvTLB::CSocketSrvTLB()
{
	memset(listenerSlots, 0, sizeof(listenerSlots));
	memset(itemStorage, 0, sizeof(itemStorage));
	memset(poolSessionID, 0, sizeof(poolSessionID));
	//^ assert(NULL == 0)
	headFreeSID = & itemStorage[0];
	tailFreeSID = & itemStorage[MAX_CONNECTION_NUM - 1];

	register CSocketItemEx *p = headFreeSID;
	register int i = 0;
	while(i < MAX_CONNECTION_NUM)
	{
		poolSessionID[i] = p;
		poolSessionID[i++]->next = ++p;
		// other link pointers are already set to NULL
	}
	tailFreeSID->next = NULL;	// reset last 'next' pointer
	//
	mutex = SHARED_FREE;
}



CSocketItemEx * CSocketSrvTLB::AllocItem()
{
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex
		, SHARED_BUSY
		, SHARED_FREE) 
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	CSocketItemEx *p = headFreeSID;
	while(p != NULL && p->inUse)
	{	// lazy-move of headFreeSID
		p = headFreeSID = p->next;
	}

	if(p == NULL)
	{
		tailFreeSID = NULL;	// assert: headFreeSID is set to NULL already
	}
	else
	{
		headFreeSID = p->next;
		if(headFreeSID == NULL)
			tailFreeSID = NULL;
		p->isReady = 0;
		p->inUse = 1;
		p->next = NULL;
	}

	this->mutex = SHARED_FREE;
	return p;
}


// allocate in the listner space
CSocketItemEx * CSocketSrvTLB::AllocItem(ALT_ID_T idListener)
{
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex
		, SHARED_BUSY
		, SHARED_FREE) 
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	CSocketItemEx *p = NULL;
	// registeration of passive socket: it is assumed that performance is seldom a concern, at least initially
	// detect duplication session ID.
	for(register int i = 0; i < MAX_LISTENER_NUM; i++)
	{
		if(! listenerSlots[i].inUse && p == NULL)
		{
			p = & listenerSlots[i];
			p->SetPassive();
			p->isReady = 0;
			p->inUse = 1;
			p->sessionID = idListener;
			// do not break, for purpose of duplicate allocation detection
		}
		else if(listenerSlots[i].inUse && listenerSlots[i].sessionID == idListener)
		{
			if(p != NULL)
				p->inUse = 0;
			// we may reuse of a socket created by a terminated process
			p = & listenerSlots[i];
			if(IsProcessAlive(p->idSrcProcess))
			{
				TRACE_HERE("collision of listener session ID detected!");
				p = NULL;
			}
			break;
		}
	}

	if(p != NULL)
	{
		CSocketItemEx *p0 = poolSessionID[idListener & (MAX_CONNECTION_NUM - 1)];
		register CSocketItemEx *p1;
		// TODO: UNRESOLVED! Is it unnecessary to detect the stale entry?
		for(p1 = p0; p1 != NULL; p1 = p1->prevSame)
		{
			if(p == p1) break;
			//
			if(p->sessionID == p1->sessionID)
			{
				p = NULL;
				break;
			}
		}
		if(p1 == NULL && p != NULL)
		{
			p->prevSame = p0;
			poolSessionID[idListener & (MAX_CONNECTION_NUM - 1)] = p;
		}
	}

	this->mutex = SHARED_FREE;
	return p;
}


void CSocketSrvTLB::FreeItem(CSocketItemEx *p)
{
	// TODO: UNRESOLVED!? Make sure it is multi-thread/muti-core safe
	while(_InterlockedCompareExchange8(& this->mutex
		, SHARED_BUSY
		, SHARED_FREE) 
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}
	//
	p->inUse = 0;
	// It is deliberate to keep 'isReady'
	//
	// if it is allocated by AllocItem(ALT_ID_T idListener):
	if(p->IsPassive())
	{
		register CSocketItemEx *p1 = poolSessionID[p->sessionID & (MAX_CONNECTION_NUM - 1)];
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
			poolSessionID[p->sessionID & (MAX_CONNECTION_NUM - 1)] = p1->prevSame;
		}
		// else keep at least one entry in the context-addressing TLB
		this->mutex = SHARED_FREE;
		return;
	}

	// if it is allocated by AllocItem() [by assigning a pseudo-random session ID]
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

	this->mutex = SHARED_FREE;
}



CSocketItemEx * CSocketSrvTLB::operator[](ALT_ID_T id)
{
	register CSocketItemEx *p = poolSessionID[id & (MAX_CONNECTION_NUM-1)];
	do
	{
		if(p->sessionID == id)
			return p;
		p = p->prevSame;
	} while(p != NULL);
	return p;	// assert(p == NULL);
}



CSocketItemEx * CSocketSrvTLB::operator[](const CommandNewSession & cmd)
{
	while(_InterlockedCompareExchange8(& this->mutex
		, SHARED_BUSY
		, SHARED_FREE) 
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}
	//
	CSocketItemEx *p = (*this)[cmd.idSession];
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
	this->mutex = SHARED_FREE;
	return p;
}



// Return
//	The send buffer block descriptor of the packet to send
// Remark
//	It is assumed that the caller knew there exists at least one packet in the queue
ControlBlock::PFSP_SocketBuf CSocketItemEx::PeekNextToSend()
{
	register int d = int(pControlBlock->sendWindowNextSN - pControlBlock->sendWindowFirstSN);
	if(d < 0 || d > pControlBlock->sendWindowSize)
		return NULL;

	d += pControlBlock->sendWindowHeadPos;
	return pControlBlock->HeadSend()
		+ (d - pControlBlock->sendBufferBlockN >= 0 ? d - pControlBlock->sendBufferBlockN : d);
}



// Initialize the association of the remote end [represent by sockAddrTo] and the near end
// Side-effect: set the initial 'previous state'
// TODO: UNRESOLVED! hard-coded here, limit capacity of multi-home support?
void CSocketItemEx::InitAssociation()
{
	// loop roll-out
	pWSAMsg[0].name = (PSOCKADDR) & pControlBlock->sockAddrTo[0];
	pWSAMsg[0].namelen = IsIPv6MSGHDR(pControlBlock->nearEnd[0]) 
		? sizeof(SOCKADDR_IN6) 
		: sizeof(SOCKADDR_IN);
	pWSAMsg[0].dwFlags = 0;
	pWSAMsg[0].Control.buf = (CHAR *) & pControlBlock->nearEnd[0];
	pWSAMsg[0].Control.len = sizeof(CtrlMsgHdr);
	// wsaMsg.dwFlags = 0;
	// 'flag', 'lpBuffers' and 'dwBufferCount' are set on fly
	pWSAMsg[1].name = (PSOCKADDR) & pControlBlock->sockAddrTo[1];
	pWSAMsg[1].namelen = IsIPv6MSGHDR(pControlBlock->nearEnd[1]) 
		? sizeof(SOCKADDR_IN6) 
		: sizeof(SOCKADDR_IN);
	pWSAMsg[1].dwFlags = 0;
	pWSAMsg[1].Control.buf = (CHAR *) & pControlBlock->nearEnd[1];
	pWSAMsg[1].Control.len = sizeof(CtrlMsgHdr);

	pairSessionID.dstSessionID = GetRemoteSessionID();
	pairSessionID.srcSessionID
		= MSGHDR_ALT_ID(pControlBlock->nearEnd[0])
		= MSGHDR_ALT_ID(pControlBlock->nearEnd[1])
		= this->sessionID;

	lowState = pControlBlock->state;
	usingPrimary = true;
	SetReady();
}


// Initialize the message descriptor
void LOCALAPI CSocketItemEx::SetRemoteAddress(PFSP_IN6_ADDR addrTo)
{
	PSOCKADDR_INET pFarEnd = pControlBlock->sockAddrTo;
	if(addrTo->u.st.prefix == IPv6PREFIX_MARK_FSP)
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pFarEnd[i].Ipv4.sin_family = AF_INET;
			pFarEnd[i].Ipv4.sin_port = DEFAULT_FSP_UDPPORT;
			pFarEnd[i].Ipv4.sin_addr.S_un.S_addr = addrTo[i].u.st.ipv4;
			memset(pFarEnd[i].Ipv4.sin_zero	// assert(sizeof(pFarEnd[i].Ipv4.sin_zero) == 8)
				, 0		// idHost is set to zero as well
				, sizeof(SOCKADDR_IN6) - sizeof(SOCKADDR_IN) + 8 - sizeof(ALT_ID_T));
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALT = addrTo->idALT;
		}
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
			pFarEnd[i].Ipv6.sin6_addr = *(PIN6_ADDR) & addrTo[i];
		}
	}
	//
	pControlBlock->u.connectParams.idRemote = addrTo->idALT;
}




// Clone the control block whose handle is passed by the command and bind the interfaces
// Initialize near and remote session ID as well
bool CSocketItemEx::MapControlBlock(const CommandNewSession & cmd)
{
#ifdef TRACE
	printf(__FUNCDNAME__ " called, source process id = %d, size of the shared memory = 0x%X\n", cmd.idProcess, cmd.dwMemorySize);
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
	printf("Handle of the source process is %I64X, handle of the shared memory in the source process is %I64X\n"
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
	printf("Handle of the mapped memory in current process is %I64X\n", (long long)hMemoryMap);
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
	printf("Successfully take use of the shared memory object.\r\n");
#endif

	CloseHandle(hThatProcess);
	// this->sessionID == cmd.idSession, provided it is a passive/welcome socket, not a initiative socket
	// assert: the queue of the returned value has been initialized by the caller already
	hEvent = cmd.u.s.hEvent;
	return true;

l_bailout1:
	CloseHandle(hMemoryMap);
l_bailout:
	CloseHandle(hThatProcess);
	return false;
}



// Given
//	BYTE *		the placeholder for the returned gap descriptors, shall be at of at least MAX_BLOCK_SIZE bytes
//	seq_t &		the placeholder for the returned maximum expected sequence number
// Return
//	Number of bytes taken by the gap descriptors, including the fixed header fields
//	0 or negative indicates that some error occurred
// Remark
//	For milky payload this function should never be called
int LOCALAPI CSocketItemEx::GenerateSNACK(BYTE * buf, ControlBlock::seq_t & seq0)
{
	FSP_SelectiveNACK::GapDescriptor *pGaps
		= (FSP_SelectiveNACK::GapDescriptor *) & buf[sizeof(FSP_NormalPacketHeader)];
	int n = (MAX_BLOCK_SIZE - sizeof(FSP_SelectiveNACK)) / sizeof(pGaps[0]) + 1;
	n = pControlBlock->GetSelectiveNACK(seq0, pGaps, n);
	if(n < 0)
		return n;

	// built-in rule: an optional header MUST be 64-bit aligned
	int spFull = sizeof(FSP_NormalPacketHeader) + sizeof(pGaps[0]) * (n & 0xFFFE);
	FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)(buf + spFull);
	spFull += sizeof(FSP_SelectiveNACK);
	if((n & 1) == 0)
		pSNACK->lastGap = 0;
	pSNACK->hs.Set<FSP_NormalPacketHeader, SELECTIVE_NACK>();

	for(register int i = n - 1; i >= 0; i--)
	{
		pGaps[i].dataLength = htons(pGaps[i].dataLength);
		pGaps[i].gapWidth = htons(pGaps[i].gapWidth);
	}
	// ONLY those marked as gap are considered unacknowledged

	return spFull;
}




// INIT_CONNECT, timestamp, Cookie, Salt, ephemeral-key, half-connection parameters [, resource requirement]
void CSocketItemEx::InitiateConnect()
{
	TRACE_HERE("called");

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend(); // INIT_CONNECT can only be the very first packet
	FSP_InitiateRequest *pkt = (FSP_InitiateRequest *)GetSendPtr(skb);
	if(pkt == NULL)
		return;	// memory corruption

	pControlBlock->u.connectParams.timeStamp = NowUTC();
	pkt->timeStamp = htonll(pControlBlock->u.connectParams.timeStamp);
	//
	wsaBuf[1].buf = (CHAR *) pkt;
	wsaBuf[1].len = sizeof(FSP_InitiateRequest);
	//^ == (ULONG)skb->len;	// See also DLL::InitiateConnect()
	SendPacket(1);
	skb->SetFlag<IS_COMPLETED>();	// for resend

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
void LOCALAPI CSocketItemEx::AffirmConnect(const SConnectParam & initState, ALT_ID_T idListener)
{
	TRACE_HERE("called");

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend(); // Reuse what's occupied by INIT_CONNECT
	FSP_ConnectRequest *pkt = (FSP_ConnectRequest *)this->GetSendPtr(skb);
	if(pkt == NULL)
		return;
	FSP_ConnectParam & varParams = pkt->params;
	//
	pkt->cookie = initState.cookie;
	pkt->timeDelta = htonl(initState.delay.p2p);
	// timeStamp, salt were overlaid; public key was exported already

	// assert(sizeof(initState.allowedPrefixes) >= sizeof(varParams.subnets));
	memcpy(varParams.subnets , initState.allowedPrefixes, sizeof(varParams.subnets));
	varParams.delayLimit = 0;	// for main/root session, milky-payload is unsupported
	varParams.initialSN = htonl(initState.initialSN);
	varParams.listenerID = idListener;
	pkt->hs.Set<FSP_ConnectRequest, CONNECT_REQUEST>();
	// while version remains as the same as the very beginning INIT_CONNECT
	skb->opCode = CONNECT_REQUEST;
	skb->len = sizeof(FSP_ConnectRequest);

	// TODO: UNRESOLVED! For FSP over IPv6, attach inititator's resource reservation...
	wsaBuf[1].buf = (CHAR *) pkt;
	wsaBuf[1].len = (ULONG) skb->len;
	SendPacket(1);

	timestamp_t t1 = NowUTC();	// internal processing takes orders of magnitude less time than network propagation
	tRoundTrip_us = uint32_t(t1 - tRecentSend);
	tRecentSend = t1;

	SetState(CONNECT_AFFIRMING);
}



// ACK_CONNECT_REQUEST, Initial SN, Expected SN, Timestamp, Receive Window, responder's half-connection parameter, optional payload
// Remark
//	Unlike INITIATE_CONNECT nor CONNECT_REQUEST, there may be a huge queue of payload packet followed
void LOCALAPI CSocketItemEx::SynConnect(CommandNewSession *pCmd)
{
	TRACE_HERE("called");

	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();
	ScheduleEmitQ();
	SetReturned();

	if(timer != NULL)
	{
		TRACE_HERE ("\nInternal panic! Unclean connection reuse?\n"
					"Timer to acknowledge connect request is not cleared beforehand.");
		return;
	}

	tKeepAlive_ms = TRASIENT_STATE_TIMEOUT_ms;
	AddTimer();
}



//ACTIVE<-->[{duplication detected}: retransmit {in the new context}]
//      |<-->[{no listener}: Snd {out-of-band} RESET]
//      |-->[API{Callback}{new context}]-->ACTIVE{new context}
//         |-->[{Return}:Accept]-->[Snd PERSIST]
//         |-->[{Return}:Commit]-->[Snd ADJOURN]-->PAUSING{new context}
//         |-->[{Return}:Reject]-->[Snd RESET]-->NON_EXISTENT
void CSocketItemEx::OnMultiply()
{
}



//PAUSING-->[Notify{Adjourn failed} if is legal]-->ACTIVE
//CLOSABLE<-->[{if no listener or it is illegal } Snd RESET]
//      |-->[Notify if is legal]-->[API{callback}:Send/{go on}]-->ACTIVE
void CSocketItemEx::OnResume()
{
	// TODO: re-allocate send buffer/window and receive buffer/window
}



//CLOSED<-->[{if no listener}Snd RESET]
//      |<-->[{if is illegal}Snd ACK_INIT_CONNECT from parent listener]
//      |-->[API{callback}
//            |-->[{Return}:Accept]-->[Snd PERSIST]-->ACTIVE
//            |-->[{Return}:Reject]-->[Snd RESET]-->NON_EXISTENT
void CSocketItemEx::OnResurrect()
{
	// TODO: re-allocate buffers
}



// Dispose on the demand of the remote peer. Let the garbage collector recycle the resource occupied
// See also Extinguish() and *::TimeOut() {case NON_EXISTENT}
void CSocketItemEx::DisposeOnReset()
{
	pControlBlock->notices[0] = FSP_NotifyReset;
	// It is somewhat an NMI to ULA
	SignalEvent();
	SetState(NON_EXISTENT);
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
	(CLowerInterface::Singleton())->FreeItem(this);
}


// Do
//	Send RESET to the remote peer in the certain states (not guaranteed to be received)
// See also ~::TimeOut case NON_EXISTENT
void CSocketItemEx::Disconnect()
{
	if(lowState == CHALLENGING || lowState == CONNECT_AFFIRMING)
		CLowerInterface::Singleton()->SendPrematureReset(ReturnedValue(), this);
	else if(lowState == ESTABLISHED || lowState == CLOSABLE || lowState == PAUSING || lowState == RESUMING)
		SendPacket<RESET>();
	//
	if(TestAndLockReady())
	{
		Extinguish();
		// UNRESOLVED! Should it SetReady() again?
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



void LOCALAPI DumpNetworkUInt16(UINT16 * buf, int len)
{
	for(register int i = 0; i < len; i++)
	{
		printf("%04X ", ntohs(buf[i]));
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
