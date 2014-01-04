/*
 * FSP lower-layer service program, abstract local physical interface services
 * Platform-independent mobility support
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

ALT_ID_T CLowerInterface::GetLocalSessionID() const
{
	return IsIPv6MSGHDR(nearInfo)
		? MSGHDR_ALT_ID(nearInfo)
		: HeaderFSPoverUDP().dstSessionID;
}


ALT_ID_T CLowerInterface::SetLocalSessionID(ALT_ID_T value)
{
	register volatile ALT_ID_T *p = IsIPv6MSGHDR(nearInfo)
		? & MSGHDR_ALT_ID(nearInfo)
		: & HeaderFSPoverUDP().dstSessionID;
	return InterlockedExchange((volatile LONG *)p, value);
}

// only valid for received message
ALT_ID_T CLowerInterface::GetRemoteSessionID() const
{
	return IsIPv6MSGHDR(nearInfo)
		? SOCKADDR_ALT_ID(sinkInfo.name)
		: HeaderFSPoverUDP().srcSessionID;
}


// Given
//	PairSessionID &		placeholder to receive the resulted session ID association
// Do
//	Store the local(near end) session ID as the source, the remote end session ID as
//	the destination session ID in the given session ID association
// Remark
//	Only valid for received message
void CLowerInterface::GetEchoingPairSession(PairSessionID & sidPair) const
{
	if(IsIPv6MSGHDR(nearInfo))
	{
		sidPair.dstSessionID = SOCKADDR_ALT_ID(sinkInfo.name);
		sidPair.srcSessionID = MSGHDR_ALT_ID(nearInfo);
	}
	else
	{
		sidPair.dstSessionID = HeaderFSPoverUDP().srcSessionID;
		sidPair.srcSessionID = HeaderFSPoverUDP().dstSessionID;
	}
}



// return the session ID, or 0 if no more slot available
ALT_ID_T LOCALAPI CLowerInterface::RandALT_ID(PIN6_ADDR addrList)
{
	CSocketItemEx *p = headFreeSID;
	int ifIndex;

	if(p == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}

	register BYTE *s = addrList->u.Byte;
	// if there's at least one hint, the ALT_ID_T part of the hint address will be altered if prefix matched
	if(*(long long *)addrList->u.Byte != 0)
	{
		bool isEffective = false;
		for(register int j = 0; j < nAddress; j++)
		{
			if(*(long long *)s == *(long long *)addresses[j].sin6_addr.u.Byte)
			{
				memcpy(s + 12, & p->sessionID, 4);
				ifIndex = interfaces[j];
				isEffective = true;
				break;
			}
		}
		if(! isEffective)
		{
			// it is weired if it failed
			REPORT_ERROR_ON_TRACE();
			return 0;
		}
	}
	else
	{
		// by default exploit the first interface configured
		memcpy(s, addresses[0].sin6_addr.u.Byte, 12);
		memcpy(s + 12, & p->sessionID, 4);
		ifIndex = interfaces[0];
	}
	// circle the entry
	tailFreeSID->next = p;	// if it is the only entry, p->next is assigned p
	headFreeSID = p->next;
	tailFreeSID = p;
	if(headFreeSID == p)
		p->next = NULL;
	// just take use of sessionID portion of the new entry
	return p->sessionID;
}


ALT_ID_T LOCALAPI CLowerInterface::RandALT_ID()
{
	CSocketItemEx *p = headFreeSID;
	if(p == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}
	// circle the entry
	tailFreeSID->next = p;	// if it is the only entry, p->next is assigned p
	tailFreeSID = p;
	headFreeSID = p->next;	// might be NULL, to be recalibrated
	if(p->next == NULL)
		headFreeSID = p;
	else
		p->next = NULL;
	// just take use of sessionID portion of the new entry
	return p->sessionID;
}


// Remark
//	Rekeying every INT_MAX microseconds (about 2147 seconds, i.e. about 35 minutes) due to time-delta limit
UINT64 LOCALAPI CalculateCookie(BYTE *header, int sizeHdr, timestamp_t t0)
{
	static struct
	{
		timestamp_t timeStamp;
		timestamp_t timeSign;
		vmac_ctx_t	ctx;
	} prevCookieContext, cookieContext;
	//
	ALIGN(MAC_ALIGNMENT) BYTE m[VMAC_KEY_LEN >> 3];
	timestamp_t t1 = NowUTC();

#ifdef TRACE
	printf("\n**** Cookie Context timestamp ****\n");
	printf("Previous = 0x%016I64X\n", prevCookieContext.timeStamp);
	printf("Current  = 0x%016I64X\n", cookieContext.timeStamp);
	printf("Packet   = 0x%016I64X\n", t0);
	printf("JustNow  = 0x%016I64X\n", t1);
#endif

	// public information included in cookie calculation should be as little as possible
	if(sizeHdr < 0 || sizeHdr > sizeof(m))
		return 0;
	memcpy(m, header, sizeHdr);
	memset(m + sizeHdr, 0, sizeof(m) - sizeHdr);

	if(t1 - cookieContext.timeStamp > INT_MAX)
	{
		BYTE	st[VMAC_KEY_LEN >> 3];
		memcpy(& prevCookieContext, & cookieContext, sizeof(cookieContext));
		//
		cookieContext.timeStamp = t1;
		rand_w32((uint32_t *) & st, sizeof(st) / sizeof(uint32_t));
		//
		vmac_set_key((unsigned char *) & st, & cookieContext.ctx);
	}

	return ((long long)(t0 - cookieContext.timeStamp) < INT_MAX)
		? vmac(m, sizeHdr
			, (unsigned char * ) & cookieContext.timeStamp
			, & (cookieContext.timeSign = t0)
			, & cookieContext.ctx)
		: vmac(m, sizeHdr
			, (unsigned char * ) & prevCookieContext.timeStamp
			, & (prevCookieContext.timeSign = t0)
			, & prevCookieContext.ctx);
}



// Given
//	char *	pointer the data buffer to send back.
//	int		length of the data to send back, in bytes. must be positive
// Do
//	Send back to the remote address where the most recent received packet was sent
// Return
//	Number of bytes actually sent (0 means error)
// Remark
//	It is safely assume that remote and near address are of the same address family
int LOCALAPI CLowerInterface::SendBack(char * buf, int len)
{
	// the final WSAMSG structure
	PairSessionID sidPair;
	WSABUF wsaData[2];
	WSABUF *pToSend;
	int nToSend;

	wsaData[1].buf = buf;
	wsaData[1].len = len;
	if(IsIPv6MSGHDR(nearInfo))
	{
		pToSend = & wsaData[1];
		nToSend = 1;
	}
	else
	{
		GetEchoingPairSession(sidPair);
		wsaData[0].buf = (char *) & sidPair;
		wsaData[0].len = sizeof(PairSessionID);
		//
		pToSend = wsaData;
		nToSend = 2;
	}
	//
	DWORD n = 0;
	int r = WSASendTo(sdSend
			, pToSend, nToSend,	& n
			, 0
			, (const sockaddr *) & addrFrom, sinkInfo.namelen
			, NULL, NULL);
	if(r != 0)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}
#ifdef TRACE
	printf("%s, line %d, %d bytes sent back.\n", __FILE__, __LINE__, n);
	printf("Peer name length = %d, socket address:\n", sinkInfo.namelen);
	DumpNetworkUInt16((UINT16 *) & addrFrom, sizeof(SOCKADDR_IN6) / 2);
#endif
	return n;
}


// Given
//	The header to be filled with 
// Do
//	Set ICC value
// Remark
//	IV = (sequenceNo, expectedSN)
//	AAD = (source session ID, destination session ID, flags, receive window free pages
//		 , version, OpCode, header stack pointer, optional headers)
#if 0
void LOCALAPI CSocketItemEx::SetIntegrityCheckCode(FSP_NormalPacketHeader *p1)
{
#define FSP_MAC_IV_SIZE (sizeof(p1->sequenceNo) + sizeof(p1->expectedSN))	
	unsigned char *m = (BYTE *) & p1->integrity.id;	// the message
	uint64_t tag;
	unsigned char pad[MAC_ALIGNMENT];
	ALIGN(MAC_ALIGNMENT) unsigned char nonce[16];	// see vmac()
	// "An i byte nonce, is made as the first 16-i bytes of n being zero, and the final i the nonce."
	// here it is (p1->sequenceNo, p1->expectedSN) of 8 bytes
	memset(nonce, 0, sizeof(nonce) - FSP_MAC_IV_SIZE);
	memcpy(nonce + sizeof(nonce) - FSP_MAC_IV_SIZE, p1, FSP_MAC_IV_SIZE);
	//
	// prepare vmac memory alignment and initialize the padding
	unsigned int mbytes = ntohs(p1->hs.hsp) - FSP_MAC_IV_SIZE;
	int misAlign = (int)m & (MAC_ALIGNMENT - 1);
	int padLen = (MAC_ALIGNMENT - (int)(mbytes & (MAC_ALIGNMENT - 1))) & (MAC_ALIGNMENT - 1);
	if(misAlign > 0)
	{
		memcpy(pad, m - misAlign, misAlign);
		memmove(m - misAlign, m, mbytes);
	}
	if(padLen - misAlign > 0)
		memcpy(pad + misAlign, m + mbytes, padLen - misAlign);
	if(padLen > 0)
		memset(m - misAlign + mbytes, 0, padLen);
	//
	tag = vmac(m - misAlign, mbytes, nonce, NULL, & pControlBlock->mac_ctx);
	// recover what's been moved and initialized
	if(misAlign > 0)
	{
		memmove(m, m - misAlign, mbytes);
		memcpy(m - misAlign, pad, misAlign);
	}
	if(padLen - misAlign > 0)
		memcpy(m + mbytes, pad + misAlign, padLen - misAlign);
	//
	p1->integrity.code = tag;
#undef FSP_MAC_IV_SIZE
}
#endif
//  Previous version of SetIntegrityCheckCode() try to align the original message with a little complex algorithm
//	in favor of less stack memory. This version is simpler but is not very suitable as kernel driver prototype
//  due to larger stack memory requirement
void LOCALAPI CSocketItemEx::SetIntegrityCheckCode(FSP_NormalPacketHeader *p1)
{
#define FSP_MAC_IV_SIZE (sizeof(p1->sequenceNo) + sizeof(p1->expectedSN))	
	unsigned char *m = (BYTE *) & p1->integrity.id;	// the message
	uint64_t tag;
	ALIGN(MAC_ALIGNMENT) unsigned char nonce[16];	// see vmac()
	ALIGN(MAC_ALIGNMENT) unsigned char padded[MAX_BLOCK_SIZE];
	// "An i byte nonce, is made as the first 16-i bytes of n being zero, and the final i the nonce."
	// here it is (p1->sequenceNo, p1->expectedSN) of 8 bytes
	memset(nonce, 0, sizeof(nonce) - FSP_MAC_IV_SIZE);
	memcpy(nonce + sizeof(nonce) - FSP_MAC_IV_SIZE, p1, FSP_MAC_IV_SIZE);
	//
	// prepare vmac memory alignment and initialize the padding
	unsigned int mbytes = ntohs(p1->hs.hsp) - FSP_MAC_IV_SIZE;
	memcpy(padded, m, mbytes);
	memset(padded + mbytes, 0, (MAC_ALIGNMENT - (int)(mbytes & (MAC_ALIGNMENT - 1))) & (MAC_ALIGNMENT - 1));
	tag = vmac(padded, mbytes, nonce, NULL, & pControlBlock->mac_ctx);
	p1->integrity.code = tag;
#undef FSP_MAC_IV_SIZE
}



void LOCALAPI CSocketItemEx::SetSequenceFlags(FSP_NormalPacketHeader *pHdr, ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq)
{
	// UNRESOLVED! TODO: how to set sequence number/flags of MULTIPLY/RESTORE command
	pHdr->expectedSN = htonl(pControlBlock->receiveMaxExpected);
	pHdr->sequenceNo = htonl(seq);
	pHdr->ClearFlags();	// pHdr->u.flags = 0;
	if(skb->GetFlag<TO_BE_CONTINUED>())
		pHdr->SetFlag<ToBeContinued>();
	else
		pHdr->ClearFlag<ToBeContinued>();
	// UNRESOLVED! compressed? ECN?
	// here we needn't check memory corruption as mishavior only harms himself
	pHdr->SetRecvWS(pControlBlock->RecvWindowSize());
}



void LOCALAPI CSocketItemEx::SetSequenceFlags(FSP_NormalPacketHeader *pHdr)
{
	// UNRESOLVED! TODO: how to set sequence number/flags of MULTIPLY/RESTORE command
	pHdr->expectedSN = htonl(pControlBlock->receiveMaxExpected);
	pHdr->sequenceNo = htonl(pControlBlock->sendWindowNextSN);
	pHdr->ClearFlags();
	// UNRESOLVED! compressed? ECN?
	// here we needn't check memory corruption as mishavior only harms himself
	pHdr->SetRecvWS(pControlBlock->RecvWindowSize());
}



/**
 * Storage location of command header, send/receive: remark
 * ('payload buffer' means that the full FSP packet is stored in the payload buffer)
 *
	INIT_CONNECT		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_INIT_CONNECT	temporary		/ temporary: stateless for responder/transient for initiator
	CONNECT_REQUEST		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_CONNECT_REQUEST	separate payload/ temporary: responder may retransmit it passively/transient for initiator
	RESET				temporary		/ temporary: one-shot only
	PERSIST				separate payload/ separate payload: fixed and optional headers regenerated on each heartbeat
	PURE_DATA			separate payload/ separate payload: without any optional header, fixed header regenerate whenever retransmit
	ADJOURN				separate payload/ separate payload buffer: space reserved for fixed and optional headers
	ACK_FLUSH			temporary		/ temporary: ACK_FLUSH is always generate on fly
	RESTORE				payload buffer	/ payload buffer: initiator of restore operation may retransmit it actively
	FINISH				temporary		/ temporary: one-shot only
	MULTIPLY			payload buffer	/ payload buffer: initiator of clone operation may retransmit it actively
 *
 *
 */
// Do
//	Transmit a packet to the remote end, enforcing secure mobility support
// Remark
//  The IP address of the near end may change dynamically
bool LOCALAPI CSocketItemEx::Emit(ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq)
{
	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		TRACE_HERE("TODO: debug log memory corruption error");
		HandleMemoryCorruption();
		return false;
	}

	FSP_NormalPacketHeader hdr;
	int result;
	wsaBuf[1].buf = (CHAR *) & hdr;
	wsaBuf[1].len = (ULONG)(sizeof(hdr));
	wsaBuf[2].buf = (CHAR *)payload;
	wsaBuf[2].len = (ULONG)skb->len;

	// wsaBuf[0] is reserved for session ID
	// ICC, if required, is always set just before being sent
	switch(skb->opCode)
	{
	case ACK_CONNECT_REQUEST:
		SetSequenceFlags(& hdr);
		hdr.integrity.code = htonll(NowUTC());
		CLowerInterface::Singleton()->EnumEffectiveAddresses
			( (UINT64 *)((BYTE *)payload + sizeof(FSP_AckConnectKey))
			, sizeof(((FSP_ConnectParam *)payload)->subnets) / sizeof(UINT64) );
		hdr.hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQUEST>();
		//
		result = this->SendPacket(2);
		break;
	/*
	case MULTIPLY:
		SetSequenceFlags(pHdr);
		pAllowedPrefix = (UINT64 *)((BYTE *)pHdr + sizeof(FSP_NormalPacketHeader));
		//^We're confident that the 'allowed prefixes' field of the half-connection
		// parameter header is following the fixed header / Built-in rule
		CLowerInterface::Singleton()->EnumEffectiveAddresses(pAllowedPrefix, 2);
		// bool LOCALAPI PiggyBack(WSABUF &, ControlBlock::PFSP_SocketBuf);
		SetIntegrityCheckCode(*pHdr);
		result = this->SendPacket(1);
		if(timer != NULL)
		{
			TRACE_HERE ("\nInternal panic! Unclean multiplied connection reuse?\n"
						"Timer to acknowledge connect request is not cleared beforehand.");
			break;
		}
		//
		tKeepAlive = CONNECT_INITIATION_TIMEOUT_ms;
		AddTimer();
		break;
	*/
	case RESTORE:
	case ADJOURN:	// ADJOURN is always in-the-queue
	case PERSIST:	// PERSIST is either out-of-band with optional header or as a keep-alive packet
	case PURE_DATA:
		if(skb->GetFlag<TO_BE_CONTINUED>() && skb->len != MAX_BLOCK_SIZE)
		{
			// TODO: debug log failure of segmented and/or online-compressed send
#ifdef 	TRACE
			printf_s("\nIncomplete packet to send, opCode = %d\n", skb->opCode);
#endif
			return false;
		}
		// Which is the norm. Dynanically generate the fixed header.
		SetSequenceFlags(& hdr, skb, seq);
		hdr.hs.opCode = skb->opCode;
		hdr.hs.version = THIS_FSP_VERSION;
		hdr.hs.hsp = htons(sizeof(FSP_NormalPacketHeader));
		// Only when the first acknowledgement is received may the faster Keep-Alive timer started. See also OnGetFullICC()
		SetIntegrityCheckCode(hdr);
		result = this->SendPacket(skb->len > 0 ? 2 : 1);
		break;
	// Only possible for retransmission
	case INIT_CONNECT:
	case CONNECT_REQUEST:
		wsaBuf[1] = wsaBuf[2];	// See also InitiateConnect() and AffirmConnect()
		result = this->SendPacket(1);
		break;
	default:
		TRACE_HERE("Unexpected socket buffer block");
		result = 1;	// return false;	// unrecognized packet type is simply ignored ?
	}

	tRecentSend = NowUTC();

#ifdef TRACE
	printf_s("Session#%u emit opcode %d, sequence = %u, result = %d, time : 0x%016llX\n"
		, sessionID, skb->opCode, seq, result, tRecentSend);
#endif

	return (result > 0);
}



// Emit packet in the send queue, by default transmission of new packets takes precedence
// To make life easier assume it has gain unique access to the LLS socket
// See also HandleEmitQ, HandleFullICC
// TODO: rate-control/quota control
void CSocketItemEx::EmitQ()
{
	ControlBlock::seq_t tail = pControlBlock->sendWindowNextSN;
	int nAvailable = int(pControlBlock->sendBufferNextSN - tail);
	int nAllowedToSend = int(pControlBlock->sendWindowFirstSN + pControlBlock->sendWindowSize - tail);
	int n = min(nAvailable, nAllowedToSend);

#ifdef TRACE
	printf_s("\n%s, session #%u meant to send = %d, allowed to send = %d\n"
		, __FUNCTION__
		, sessionID
		, nAvailable
		, nAllowedToSend
		);
#endif
	if(n <= 0)
		return;

	ControlBlock::PFSP_SocketBuf skb;
	while((skb = PeekNextToSend()) != NULL)
	{
#ifdef TRACE
		printf_s("\nIn session#%u, to emit opcode %d, sequence = %u, len = %d\n"
			, sessionID
			, skb->opCode
			, pControlBlock->sendWindowNextSN
			, skb->len);
#endif
		if(! skb->GetFlag<IS_COMPLETED>())
		{
			TRACE_HERE("the last packet might not be ready, say, "
				"during process of sending real-time encrypted long stream");
			break;
		}
		if(! skb->MarkInSending())
		{
			TRACE_HERE("Cannot gain exclusive sending lock on the last packet");
			break;
		}
		if(! Emit(skb, pControlBlock->sendWindowNextSN))
		{
			skb->MarkUnsent();
			break;
		}
		//
		if(pControlBlock->sendWindowNextSN == pControlBlock->sendWindowFirstSN)
			tEarliestSend = tRecentSend;
		//
		++(pControlBlock->sendWindowNextSN);
	}
}



// UNRESOLVED! TODO: enforce rate-limit (and rate-limit based congestion avoidance/control)
// TODO: UNRESOLVED! is it multi-home awared?
int LOCALAPI CSocketItemEx::SendPacket(ULONG n1)
{
	WSAMSG m = pWSAMsg[usingPrimary ? 0 : 1];
	if(IsIPv6MSGHDR(*m.Control.buf))
	{
		m.lpBuffers = & wsaBuf[1];
	}
	else
	{
		// assume sidPair is maintained properly
		wsaBuf[0].buf = (CHAR *) & pairSessionID;
		wsaBuf[0].len = sizeof(pairSessionID);
		m.lpBuffers = & wsaBuf[0];
		n1++;
	}
	//
	m.dwBufferCount = n1;

	DWORD n = 0;
	//int r = WSASendMsg(sdSend, (LPWSAMSG) & m, 0, & n, NULL, NULL);
	// here we assume that WSASendMsg does not change anyting in m.
	// as minimum OS version that support WSASendMSg is Windows Vista/Server 2008
	// for XP/2003 compatibility reason we utilize WSASendTo
	int r = WSASendTo(CLowerInterface::Singleton()->sdSend
		, m.lpBuffers, m.dwBufferCount, & n
		, 0
		, m.name, m.namelen
		, NULL, NULL);
	if(r != 0)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}
#ifdef TRACE
	printf("%s, line %d, %d bytes sent.\n", __FILE__, __LINE__, n);
	//printf("Control len = %d\n", m.Control.len);
	//DumpCMsgHdr(*(CtrlMsgHdr *)m.Control.buf);
	//
	printf("Peer name length = %d, socket address:\n", m.namelen);
	DumpNetworkUInt16((UINT16 *)m.name, sizeof(SOCKADDR_IN6) / 2);
	//
	//printf("Buffer count = %d, flags = %x, data len = %d, data: \n"
	//	, m.dwBufferCount, m.dwFlags, m.lpBuffers[0].len);
	//DumpHexical((BYTE *)m.lpBuffers[0].buf, m.lpBuffers[0].len);
	//if(m.dwBufferCount > 1)
	//	DumpHexical((BYTE *)m.lpBuffers[1].buf, m.lpBuffers[1].len);
#endif
	return n;
}


// Remark
//	Designed side-effect for mobility support: automatically refresh the corresponding address list...
bool CSocketItemEx::ValidateICC(FSP_NormalPacketHeader *pkt)
{
	UINT64	savedICC = pkt->integrity.code;
	PairSessionID idPair;
	idPair.dstSessionID = pairSessionID.srcSessionID;
	idPair.srcSessionID = pairSessionID.dstSessionID;
	pkt->integrity.id = idPair;
	SetIntegrityCheckCode(pkt);
	if(pkt->integrity.code != savedICC)
		return false;
	// TODO: automatically register remote address as the favorite contact address
	// iff the integrity check code has passed the validation
	if(addrFrom.si_family == AF_INET)
	{
	}
	else if(addrFrom.si_family == AF_INET6)
	{
	}
	addrFrom.si_family = 0;	// AF_UNSPEC;	// as the flag
	return true;
}
