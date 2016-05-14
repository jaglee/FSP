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

// From the receiver's point of view the local fiber id was stored in the peer fiber id field of the received packet
ALFID_T CLowerInterface::SetLocalFiberID(ALFID_T value)
{
	if(nearInfo.IsIPv6())
		nearInfo.u.idALF = value;
	return _InterlockedExchange((volatile LONG *) & pktBuf->idPair.peer, value);
}



// return the fiber ID, or 0 if no more slot available
ALFID_T LOCALAPI CLowerInterface::RandALFID(PIN6_ADDR addrList)
{
	CSocketItemEx *p = headFreeSID;
	int ifIndex;

	if(p == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}

	register BYTE *s = addrList->u.Byte;
	// if there's at least one hint, the ALFID_T part of the hint address will be altered if prefix matched
	if(*(uint64_t *)addrList->u.Byte != 0)
	{
		bool isEffective = false;
		for(register u_int j = 0; j < sdSet.fd_count; j++)
		{
			if(*(uint64_t *)s == *(uint64_t *)addresses[j].sin6_addr.u.Byte)
			{
				*(ALFID_T *)(s + 12) = p->fidPair.source;
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
		*(ALFID_T *)(s + 12) = p->fidPair.source;
		memcpy(s, addresses[0].sin6_addr.u.Byte, 12);
		ifIndex = interfaces[0];
	}
	// circle the entry
	tailFreeSID->next = p;	// if it is the only entry, p->next is assigned p
	headFreeSID = p->next;
	tailFreeSID = p;
	if(headFreeSID == p)
		p->next = NULL;
	// just take use of fiberID portion of the new entry
	return p->fidPair.source;
}



// Return an available random ID. Here it is pre-calculated. Should be really random for better security
ALFID_T LOCALAPI CLowerInterface::RandALFID()
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
	// just take use of fiberID portion of the new entry
	return p->fidPair.source;
}



// Given
//	BYTE *		pointer to the byte string of cookie material for the calculation
//	int			the length of the cookie material
//	timestamp_t	the time associated with the cookie, to deduce the life-span of the cookie
// Do
//	Calculate the cookie
// Return
//	The 64-bit cookie value
uint64_t LOCALAPI CalculateCookie(BYTE *header, int sizeHdr, timestamp_t t0)
{
	static struct
	{
		ALIGN(MAC_ALIGNMENT)
		timestamp_t timeStamp;
		ALIGN(MAC_ALIGNMENT)
		timestamp_t timeSign;
		ALIGN(MAC_ALIGNMENT)
		GCM_AES_CTX	ctx;
	} prevCookieContext, cookieContext;
	//
	ALIGN(MAC_ALIGNMENT) BYTE m[sizeof(FSP_InitiateRequest)];
	timestamp_t t1 = NowUTC();

#if defined(TRACE) && (TRACE & TRACE_PACKET)
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
		ALIGN(MAC_ALIGNMENT)
		BYTE	st[COOKIE_KEY_LEN];	// in bytes
		memcpy(& prevCookieContext, & cookieContext, sizeof(cookieContext));
		//
		cookieContext.timeStamp = t1;
		rand_w32((uint32_t *) & st, sizeof(st) / sizeof(uint32_t));
		//
		GCM_AES_SetKey(& cookieContext.ctx, st, COOKIE_KEY_LEN);
	}

	BYTE tag[sizeof(uint64_t)];
	if((long long)(t0 - cookieContext.timeStamp) < INT_MAX)
	{
		cookieContext.timeSign = t0;
		GCM_SecureHash(& cookieContext.ctx, cookieContext.timeStamp, m, sizeof(m), tag, sizeof(tag));
	}
	else
	{
		prevCookieContext.timeSign = t0;
		GCM_SecureHash(& prevCookieContext.ctx, prevCookieContext.timeStamp, m, sizeof(m), tag, sizeof(tag));
	}
	return *(uint64_t *)tag;
}



// The ephemeral key is weakly securely established. It is a 64-bit value meant to make obfuscation in calcuate the CRC64 tag
void CSocketItemEx::InstallEphemeralKey()
{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Session key materials:\n");
	DumpNetworkUInt16((uint16_t *)  & pControlBlock->connectParams, FSP_MAX_KEY_SIZE / 2);
#endif
	// contextOfICC.savedCRC = true; // don't care
	contextOfICC.keyLife = 0;
	// Overlay with 'initCheckCode', 'cookie', 'salt', 'initialSN' and 'timeStamp'
	contextOfICC.curr.precomputedICC[0] 
		=  CalculateCRC64(* (uint64_t *) & fidPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);

	PairALFID recvFIDPair;
	recvFIDPair.peer = fidPair.source;
	recvFIDPair.source = fidPair.peer;
	contextOfICC.curr.precomputedICC[1]
		=  CalculateCRC64(* (uint64_t *) & recvFIDPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Precomputed ICC 0:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[0], 4);
	printf_s("Precomputed ICC 1:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[1], 4);
#endif
}



// See @DLL::InstallKey
void CSocketItemEx::InstallSessionKey()
{
#ifndef NDEBUG
	contextOfICC._mac_ctx_protect_prolog[0]
		= contextOfICC._mac_ctx_protect_prolog[1]
		= contextOfICC._mac_ctx_protect_epilog[0]
		= contextOfICC._mac_ctx_protect_epilog[1]
		= MAC_CTX_PROTECT_SIGN;
#endif
	contextOfICC.savedCRC = (contextOfICC.keyLife == 0);
	contextOfICC.prev = contextOfICC.curr;
	contextOfICC.keyLife = pControlBlock->connectParams.initialSN;
	GCM_AES_SetKey(& contextOfICC.curr.gcm_aes, (uint8_t *) & pControlBlock->connectParams, pControlBlock->connectParams.keyLength);

	contextOfICC.firstSendSNewKey = pControlBlock->sendBufferNextSN;
	contextOfICC.firstRecvSNewKey = pControlBlock->recvWindowNextSN;
}



// Do
//	Automatically register source IP address as the favorite returning IP address
// Remark
//	Suppose the most-recently received message has been validated and the peer's address obtained from the underlying IPv6 packet
//	has been saved in the sentinel place sockAddrTo[MAX_PHY_INTERFACES]
//	Target address selection/protocol related to network path selection is undetermined yet
// See also SendPacket
inline void CSocketItemEx::ChangeRemoteValidatedIP()
{
//	Currently not bothered to support mobility under IPv4 yet
#ifndef OVER_UDP_IPv4
	register int i = MAX_PHY_INTERFACES - 1;
	for (; i >= 0; i--)
	{
		if (SOCKADDR_SUBNET(sockAddrTo + i) == SOCKADDR_SUBNET(sockAddrTo + MAX_PHY_INTERFACES)
		 && SOCKADDR_HOSTID(sockAddrTo + i) == SOCKADDR_HOSTID(sockAddrTo + MAX_PHY_INTERFACES))
		{
			sockAddrTo[i] = sockAddrTo[0];	// save the original favorite target IP address
			break;
		}
	};
	//^Let's the compiler do loop-unrolling, if it worthes
	if(i < 0)
	{
		memcpy(sockAddrTo + 1, sockAddrTo, sizeof(sockAddrTo[0]) * (MAX_PHY_INTERFACES - 1));
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("%s: set the new favorite target IP to the source address of the most recently received packet.\n", __FUNCTION__);
#endif
	}
	else if(i == 0)
	{
		return;
	}
#if defined(TRACE) && (TRACE & TRACE_ADDRESS) && (TRACE & TRACE_HEARTBEAT)
	else // (i > 0)
	{
		printf_s("%s: change the favorite target IP to the source IP address of the new received packet.\n", __FUNCTION__);
	}
#endif
	sockAddrTo[0] = sockAddrTo[MAX_PHY_INTERFACES];
#endif
}



// Given
//	FSP_NormalPacketHeader *	The pointer to the fixed header, plaintext may or may not follow
//	void *	[in,out]			The plaintext/ciphertext, either payload or optional header
//	int32_t						The payload length
//	uint32_t					The xor'ed salt
// Do
//	Set ICC value
// Return
//	The pointer to the ciphertext. == content if CRC64 applied, == internal buffer if GCM_AES applied.
// Remark
//	IV = (sequenceNo, expectedSN)
//	AAD = (source fiber ID, destination fiber ID, flags, receive window free pages
//		 , version, OpCode, header stack pointer, optional headers)
//	This function is NOT multi-thread safe
void * LOCALAPI CSocketItemEx::SetIntegrityCheckCode(FSP_NormalPacketHeader *p1, void *content, int32_t ptLen, uint32_t salt)
{
	ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
	void * buf;
	uint32_t seqNo = be32toh(p1->sequenceNo);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("\nBefore GCM_AES_AuthenticatedEncrypt: ptLen = %d\n", ptLen);
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif

	// CRC64
	if(contextOfICC.keyLife == 0)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.curr.precomputedICC[0], sizeof(uint64_t) / 2);
#endif
		p1->integrity.code = contextOfICC.curr.precomputedICC[0];
		tag[0] = CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader));
		buf = content;
	}
	else if(int32_t(seqNo - contextOfICC.firstSendSNewKey) < 0 && contextOfICC.savedCRC)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.prev.precomputedICC[0], sizeof(uint64_t) / 2);
#endif
		p1->integrity.code = contextOfICC.prev.precomputedICC[0];
		tag[0] = CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader));
		buf = content;
	}
	else
	{
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.firstSendSNewKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;
		uint32_t byteA = be16toh(p1->hs.hsp);
		if(byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
			return NULL;

		p1->integrity.id = fidPair;
		GCM_AES_XorSalt(pCtx, salt);
		if(GCM_AES_AuthenticatedEncrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)content, ptLen
			, (const uint64_t *)p1 + 1, byteA - sizeof(uint64_t)
			, (uint64_t *)this->cipherText
			, (uint8_t *)tag, FSP_TAG_SIZE)
			!= 0)
		{
			TRACE_HERE("Encryption error?");
			GCM_AES_XorSalt(pCtx, salt);
			return NULL;
		}
		GCM_AES_XorSalt(pCtx, salt);
		buf = this->cipherText;
	}

	p1->integrity.code = tag[0];
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("After GCM_AES_AuthenticatedEncrypt:\n");	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
	return buf;
}



// Given
//	FSP_NormalPacketHeader *	The pointer to the fixed header
//	int32_t						The size of the ciphertext
//	uint32_t					The xor'ed salt
// Return
//	true if all of the headers passed authentication and the optional payload successfully decrypted
// Remark
//	Assume the headers are 64-bit aligned
//	UNRESOLVED!? Is it meaningless to recover the ICC field?	// p1->integrity.code = *(uint64_t *)tag;
bool CSocketItemEx::ValidateICC(FSP_NormalPacketHeader *p1, int32_t ctLen, uint32_t salt)
{
	ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];

	tag[0] = p1->integrity.code;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Before GCM_AES_AuthenticateAndDecrypt:\n");
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
	uint32_t seqNo = be32toh(p1->sequenceNo);
	register bool r;
	// CRC64
	if(contextOfICC.keyLife == 0)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.curr.precomputedICC[1], sizeof(uint64_t) / 2);
#endif
		// well, well, send is not the same as receive...
		p1->integrity.code = contextOfICC.curr.precomputedICC[1];
		r = (tag[0] == CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader)));
	}
	else if(int32_t(seqNo - contextOfICC.firstRecvSNewKey) < 0 && contextOfICC.savedCRC)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.prev.precomputedICC[1], sizeof(uint64_t) / 2);
#endif
		// well, well, send is not the same as receive...
		p1->integrity.code = contextOfICC.prev.precomputedICC[1];
		r = (tag[0] == CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader)));
	}
	else
	{
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.firstRecvSNewKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;
		uint32_t byteA = be16toh(p1->hs.hsp);
		if(byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
			return false;

		GCM_AES_XorSalt(pCtx, salt);
		p1->integrity.id.source = fidPair.peer;
		p1->integrity.id.peer = fidPair.source;
		// CRC64 is the initial integrity check algorithm
		r = (GCM_AES_AuthenticateAndDecrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)p1 + byteA, ctLen
			, (const uint64_t *)p1 + 1, byteA - sizeof(uint64_t)
			, (const uint8_t *)tag, FSP_TAG_SIZE
			, (uint64_t *)p1 + byteA / sizeof(uint64_t))
			== 0);
		GCM_AES_XorSalt(pCtx, salt);
	}
	p1->integrity.code = tag[0];
	if(! r)
		return false;

	ChangeRemoteValidatedIP();
	return true;
}



/**
 * Storage location of command header, send/receive: remark
 * ('payload buffer' means that the full FSP packet is stored in the payload buffer)
 *
	INIT_CONNECT		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_INIT_CONNECT	temporary		/ temporary: stateless for responder/transient for initiator
	CONNECT_REQUEST		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_CONNECT_REQ		separate payload/ temporary: responder may retransmit it passively/transient for initiator
	RESET				temporary		/ temporary: one-shot only
	PERSIST				separate payload/ separate payload: fixed header regenerated on retransmission
	COMMIT				separate payload/ separate payload buffer: space reserved for fixed and optional headers
	PURE_DATA			separate payload/ separate payload: fixed header regenerated on retransmission
	KEEP_ALIVE			temporary		/ temporary: KEEP_ALIVE is always generate on fly
	ACK_FLUSH			temporary		/ temporary: ACK_FLUSH is always generate on fly
	RELEASE				temporary		/ temporary: one-shot only
	MULTIPLY			payload buffer	/ payload buffer: initiator of clone operation may retransmit it actively
 *
 *
 */
// Do
//	Transmit the head packet in the send queue to the remote end
// Remark
//  The IP address of the near end may change dynamically
bool CSocketItemEx::EmitStart()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		TRACE_HERE("TODO: debug log memory corruption error");
		HandleMemoryCorruption();
		return false;
	}

	register FSP_NormalPacketHeader * const pHdr = & pControlBlock->tmpHeader;
	int result;
	switch (skb->opCode)
	{
	case ACK_CONNECT_REQ:
		pControlBlock->SetSequenceFlags(pHdr);
		pHdr->integrity.code = htobe64(tRecentSend);

		CLowerInterface::Singleton()->EnumEffectiveAddresses(pControlBlock->connectParams.allowedPrefixes);
		memcpy((BYTE *)payload, pControlBlock->connectParams.allowedPrefixes, sizeof(uint64_t) * MAX_PHY_INTERFACES);

		pHdr->hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();
		//
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), payload, skb->len));
		break;
	case PERSIST:	// PERSIST is an in-band control packet with optional payload that confirms a connection
	case COMMIT:	// COMMIT is always in the queue
	case MULTIPLY:
		result = EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
		break;
	// Only possible for retransmission
	case INIT_CONNECT:
	case CONNECT_REQUEST:
		// Header has been included in the payload. See also InitiateConnect() and AffirmConnect()
		result = SendPacket(1, ScatteredSendBuffers(payload, skb->len));
		break;
	default:
		TRACE_HERE("Unexpected socket buffer block");
		result = 0;	// unrecognized packet type is simply ignored?!
	}

#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Session#%u emit %s, result = %d, time : 0x%016llX\n"
		, fidPair.source, opCodeStrings[skb->opCode], result, tRecentSend);
#endif
	if(result > 0)
		SetEarliestSendTime();
	return (result >= 0);
}


// Do
//	Transmit a packet to the remote end, enforcing secure mobility support
// Remark
//  The IP address of the near end may change dynamically
bool LOCALAPI CSocketItemEx::EmitWithICC(ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq)
{
#ifdef _DEBUG
	if(skb->opCode == INIT_CONNECT || skb->opCode == ACK_INIT_CONNECT || skb->opCode == CONNECT_REQUEST || skb->opCode == ACK_CONNECT_REQ)
	{
		printf_s("Assertion failed! %s (opcode: %d) has no ICC field\n", opCodeStrings[skb->opCode], skb->opCode);
		return false;
	}
#endif
	if(contextOfICC.keyLife == 1)
	{
		TRACE_HERE("Session key run out of life");
		return false;
	}

	// UNRESOLVED! retransmission consume key life? of course?
	if(contextOfICC.keyLife > 0)
		contextOfICC.keyLife--;

	// The COMMIT packet, if any, is the last one that applied CRC64 or the old transmission key
	// assume the receive direction is not ready yet
	// See also OnAckFlush and @DLL::InstallKey 
	if(skb->opCode == COMMIT && (pControlBlock->hasPendingKey & HAS_PENDING_KEY_FOR_SEND) != 0)
	{
		InstallSessionKey();
		pControlBlock->hasPendingKey &= ~HAS_PENDING_KEY_FOR_SEND;
		contextOfICC.firstRecvSNewKey = pControlBlock->recvWindowNextSN + INT32_MAX;
	}

	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		TRACE_HERE("TODO: debug log memory corruption error");
		HandleMemoryCorruption();
		return false;
	}

	register FSP_NormalPacketHeader *pHdr = & pControlBlock->tmpHeader;
	int result;
	// ICC, if required, is always set just before being sent
	if (skb->GetFlag<TO_BE_CONTINUED>() && skb->len != MAX_BLOCK_SIZE)
	{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("\nImcomplete packet to send, opCode: %s(%d, len = %d)\n"
			, opCodeStrings[skb->opCode]
			, skb->opCode
			, skb->len);
#endif
		return false;
	}
	// Which is the norm. Dynanically generate the fixed header.
	pControlBlock->SetSequenceFlags(pHdr, skb, seq);
	pHdr->hs.Set(skb->opCode, sizeof(FSP_NormalPacketHeader));

	void * paidLoad = SetIntegrityCheckCode(pHdr, (BYTE *)payload, skb->len);
	if(paidLoad == NULL)
		return false;
	if (skb->len > 0)
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), paidLoad, skb->len));
	else
		result = SendPacket(1, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader)));

	return (result > 0);
}



// On near end's IPv6 address changed automatically send KEEP_ALIVE with MOBILE_HEADER
// See also CSocketItemEx::SendSNACK(), OnGetPureData, OnGetPersist
#ifndef OVER_UDP_IPv4
void CSocketItemEx::OnLocalAddressChanged()
{
	if(! IsInUse() || IsPassive())
		return;

	FSPOperationCode opCode = (pControlBlock->HasBeenCommitted() > 0) ? ACK_FLUSH : KEEP_ALIVE;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("Line %d @ %s\n\tTo make acknowledgement: %s [%d]\n", __LINE__, __FUNCTION__, opCodeStrings[opCode], opCode);
#endif
	ControlBlock::seq_t seqExpected;
	struct
	{
		FSP_NormalPacketHeader	hdr;
		FSP_ConnectParam		mp;
		FSP_PreparedKEEP_ALIVE	snack;
	} buf;

	int32_t len = GenerateSNACK(buf.snack, seqExpected,  sizeof(FSP_NormalPacketHeader) + sizeof(FSP_ConnectParam));
#if defined(TRACE) && (TRACE & (TRACE_ADDRESS | TRACE_HEARTBEAT))
	printf_s("Keep-alive local fiber#%u\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source
		, seqExpected
		, len);
#endif
	if (len < sizeof(FSP_SelectiveNACK) + sizeof(FSP_NormalPacketHeader) + sizeof(FSP_ConnectParam))
	{
		printf_s("Fatal error %d encountered when generate SNACK, bundled with MOBILE_PARAM\n", len);
		return;
	}

	u_int k = CLowerInterface::Singleton()->sdSet.fd_count;
	u_int j = 0;
	LONG w = CLowerInterface::Singleton()->disableFlags;
	for (register u_int i = 0; i < k; i++)
	{
		if (!BitTest(&w, i))
		{
			buf.mp.subnets[j++] = SOCKADDR_SUBNET(&CLowerInterface::Singleton()->addresses[i]);
			if (j >= sizeof(buf.mp.subnets) / sizeof(uint64_t))
				break;
		}
	}
	// temporarily there is no path to the local end:
	if (j <= 0)
		return;
	//
	while(j < sizeof(buf.mp.subnets) / sizeof(uint64_t))
	{
		buf.mp.subnets[j] = buf.mp.subnets[j - 1];
		j++;
	}
	//^Let's the compiler do loop-unrolling
	buf.mp.idHost = SOCKADDR_HOSTID(&CLowerInterface::Singleton()->addresses[0]);
	buf.mp.hs.Set(MOBILE_PARAM, sizeof(FSP_NormalPacketHeader));

	// Both KEEP_ALIVE and ACK_FLUSH are payloadless out-of-band control block which always apply current session key
	buf.hdr.Set(pControlBlock->sendWindowNextSN - 1, seqExpected, pControlBlock->RecvWindowSize(), opCode, len);
	SetIntegrityCheckCode(& buf.hdr, NULL, 0, buf.snack.GetSaltValue());
	// See also CSocketItemEx::SendSNACK
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("To send KEEP_ALIVE seq #%u, acknowledge #%u, source ALFID = %u\n", be32toh(buf.hdr.sequenceNo), seqExpected, fidPair.source);
	printf_s("KEEP_ALIVE total header length: %d, including mobile parameter\n", len);
	DumpNetworkUInt16((uint16_t *)& buf, len / 2);
#endif

	// If destination interface happen to be on the same host, update the registered address simultaneously
	// UNRESOLVED!? The default interface should be the one that is set to promiscuous
	if (SOCKADDR_SUBNET(sockAddrTo) == 0 && SOCKADDR_HOSTID(sockAddrTo) == 0)
	{
		PSOCKADDR_IN6 p = CLowerInterface::Singleton()->addresses + CLowerInterface::Singleton()->iRecvAddr;
		SOCKADDR_SUBNET(sockAddrTo) = SOCKADDR_SUBNET(p);
		SOCKADDR_HOSTID(sockAddrTo) = SOCKADDR_HOSTID(p);
	}

	SendPacket(1, ScatteredSendBuffers(&buf, len));
}
#endif


// Given
//	PFSP_HeaderSignature	the MOBILE_PARAM header
// Do
//	Process the getting remote address event
// Remark
//	Although the subnet that the host belong to could be mobile, the ID of the host should be persistent
bool LOCALAPI CSocketItemEx::HandleMobileParam(PFSP_HeaderSignature optHdr)
{
	if (optHdr == NULL || optHdr->opCode != MOBILE_PARAM)
		return false;
#ifndef OVER_UDP_IPv4
	FSP_ConnectParam *pMobileParam = (FSP_ConnectParam *)((uint8_t *)optHdr + sizeof(FSP_HeaderSignature) - sizeof(FSP_ConnectParam));
	// loop roll-out
	SOCKADDR_SUBNET(&sockAddrTo[0]) = pMobileParam->subnets[0];
	SOCKADDR_SUBNET(&sockAddrTo[1]) = pMobileParam->subnets[1];
	SOCKADDR_SUBNET(&sockAddrTo[2]) = pMobileParam->subnets[2];
	SOCKADDR_SUBNET(&sockAddrTo[3]) = pMobileParam->subnets[3];
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("New target address set for host %u (== %u)\n", SOCKADDR_HOSTID(sockAddrTo), pMobileParam->idHost);
#endif
	//
#endif
	return true;
}



// Emit packet in the send queue, by default transmission of new packets takes precedence
// To make life easier assume it has gain unique access to the LLS socket
// See also HandleEmitQ, HandleFullICC
// TODO: rate-control/quota control
void CSocketItemEx::EmitQ()
{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	TRACE_HERE("Sending data...");
#endif
	ControlBlock::seq_t lastSN = _InterlockedOr((LONG *) & pControlBlock->sendBufferNextSN, 0);
	ControlBlock::seq_t firstSN = pControlBlock->sendWindowFirstSN;
	ControlBlock::seq_t & nextSN = pControlBlock->sendWindowNextSN;
	int32_t winSize = _InterlockedOr((LONG *) & pControlBlock->sendWindowSize, 0);
	//
	register ControlBlock::PFSP_SocketBuf skb;
	while (int(nextSN - lastSN) < 0 && int(nextSN - firstSN) <= winSize)
	{
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		// The flag IS_COMPLETED is for double-stage commit of send buffer, for sake of sending online compressed stream
		if (!skb->GetFlag<IS_COMPLETED>())
		{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("Not ready to send packet SN#%u; next to buffer SN#%u\n", nextSN, lastSN);
#endif 
			break;
		}

		if (!skb->Lock())
		{
#ifndef NDEBUG
			printf_s("Should be rare: cannot get the exclusive lock on the packet to send SN#%u\n", nextSN);
#endif
			pControlBlock->SlideNextToSend();
			continue;
		}

		if (!EmitWithICC(skb, nextSN))
		{
			skb->Unlock();
			break;
		}
		skb->SetFlag<IS_SENT>();
		//
		if (pControlBlock->SlideNextToSend() == firstSN + 1)
			SetEarliestSendTime();
	}
}


// An auxillary function handling the fixed header
// Given
//	uint32_t	The sequenceNo field in host byte order
//	uint32_t	The expectedNo field in host byte order
//	uint32_t	The advertised receive window size, in host byte order
//	uint8_t		The opCode
//	uint16_t	The total length of all the headers
// Do
//	Filled in the fixed header
void LOCALAPI FSP_NormalPacketHeader::Set(uint32_t seqThis, uint32_t seqExpected, int32_t advRecvWinSize, uint8_t code, uint16_t hsp)
{
	expectedSN = htobe32(seqExpected);
	sequenceNo = htobe32(seqThis);
	ClearFlags();
	SetRecvWS(advRecvWinSize);
	hs.Set(code, hsp);
}
