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
	return InterlockedExchange((volatile LONG *) & pktBuf->idPair.peer, value);
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
		for(register int j = 0; j < nAddress; j++)
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




void CSocketItemEx::InstallEphemeralKey()
{
#ifdef TRACE
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
#ifdef TRACE
	printf_s("Precomputed ICC 0:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[0], 4);
	printf_s("Precomputed ICC 1:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[1], 4);
#endif
}



// TODO: (see also ValidateICC)
// Install session key might be quick, e.g. a pre-shared key installed as soon as CHALLENGE
// If there's no data in flight, the send key is installed immediately
// But only in CHALLENGING, PEER_COMMIT, COMMITTING2 or CLOSABLE state
// may the first receive sequence number of the packet that exploited the new key set
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
	contextOfICC.keyLife = pControlBlock->connectParams.timeDelta;
	contextOfICC.firstSendSNewKey = pControlBlock->sendWindowNextSN;
	contextOfICC.firstRecvSNewKey = pControlBlock->recvWindowNextSN;
	
	GCM_AES_SetKey(& contextOfICC.curr.gcm_aes, (uint8_t *) & pControlBlock->connectParams, pControlBlock->connectParams.keyLength);
}


// Given
//	FSP_NormalPacketHeader *	The pointer to the fixed header, plaintext may or may not follow
//	void *	[in,out]			The plaintext/ciphertext, either payload or optional header
//	int32_t						The payload length
//	uint32_t					The xor'ed salt
// Do
//	Set ICC value
// Remark
//	IV = (sequenceNo, expectedSN)
//	AAD = (source fiber ID, destination fiber ID, flags, receive window free pages
//		 , version, OpCode, header stack pointer, optional headers)
void LOCALAPI CSocketItemEx::SetIntegrityCheckCode(FSP_NormalPacketHeader *p1, void *content, int32_t ptLen, uint32_t salt)
{
	ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
	
#ifdef TRACE_PACKET
	printf_s("\nBefore GCM_AES_AuthenticatedEncrypt: ptLen = %d\n", ptLen);
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
	uint32_t seqNo = be32toh(p1->sequenceNo);
	// CRC64
	if(contextOfICC.keyLife == 0)
	{
#ifdef TRACE_PACKET
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.curr.precomputedICC[0], sizeof(uint64_t) / 2);
#endif
		p1->integrity.code = contextOfICC.curr.precomputedICC[0];
		tag[0] = CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader));
	}
	else if(int32_t(seqNo - contextOfICC.firstSendSNewKey) < 0 && contextOfICC.savedCRC)
	{
#ifdef TRACE_PACKET
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.prev.precomputedICC[0], sizeof(uint64_t) / 2);
#endif
		p1->integrity.code = contextOfICC.prev.precomputedICC[0];
		tag[0] = CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader));
	}
	else
	{
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.firstSendSNewKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;
		uint32_t byteA = be16toh(p1->hs.hsp);
		if(byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
			return;

		// Synchronize the session key
		if(seqNo == contextOfICC.firstSendSNewKey)
			p1->SetFlag<Encrypted>();
		p1->integrity.id = fidPair;
		GCM_AES_XorSalt(pCtx, salt);
		if(GCM_AES_AuthenticatedEncrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)content, ptLen
			, (const uint64_t *)p1 + 1, byteA - sizeof(uint64_t)
			, (uint64_t *)content
			, (uint8_t *)tag, FSP_TAG_SIZE)
			!= 0)
		{
			TRACE_HERE("Encryption error?");
			GCM_AES_XorSalt(pCtx, salt);
			return;
		}
		GCM_AES_XorSalt(pCtx, salt);
	}

	p1->integrity.code = tag[0];
#ifdef TRACE_PACKET
	printf_s("After GCM_AES_AuthenticatedEncrypt:\n");	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
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

	// UNRESOLVED! But if out-of-order packet which set the sequence number continually received within the receive window?
	// synchronize the session key
	//if(p1->GetFlag<Encrypted>())
	//	contextOfICC.firstRecvSNewKey = headPacket->pktSeqNo;

	tag[0] = p1->integrity.code;
#ifdef TRACE_PACKET
	printf_s("Before GCM_AES_AuthenticateAndDecrypt:\n");
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
	uint32_t seqNo = be32toh(p1->sequenceNo);
	register bool r;
	// CRC64
	if(contextOfICC.keyLife == 0)
	{
#ifdef TRACE_PACKET
		printf_s("\nPrecomputed ICC: ");
		DumpNetworkUInt16((uint16_t *) & contextOfICC.curr.precomputedICC[1], sizeof(uint64_t) / 2);
#endif
		// well, well, send is not the same as receive...
		p1->integrity.code = contextOfICC.curr.precomputedICC[1];
		r = (tag[0] == CalculateCRC64(0, (uint8_t *)p1, sizeof(FSP_NormalPacketHeader)));
	}
	else if(int32_t(seqNo - contextOfICC.firstRecvSNewKey) < 0 && contextOfICC.savedCRC)
	{
#ifdef TRACE_PACKET
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
	RESUME				payload buffer	/ payload buffer: initiator of RESUME operation may retransmit it actively
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
		if(! skb->GetFlag<TO_BE_CONTINUED>())	// which mean it has not been chained with sending
			skb->SetFlag<IS_COMPLETED>();
		if(InState(COMMITTING) || InState(COMMITTING2))
			skb->opCode = COMMIT;
	case RESUME:	// RESUME is an in-band control packet that try re-established a broken/paused connection
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
	// case PURE_DATA:
		// it cannot be the first packet to send on connection established/resumed,
		// nor can it be retransmitted separately
	default:
		TRACE_HERE("Unexpected socket buffer block");
		result = 0;	// unrecognized packet type is simply ignored?!
	}

#ifdef TRACE_SOCKET
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
	// UNRESOLVED! retransmission consume key life? of course?
	if(contextOfICC.keyLife == 1)
	{
		TRACE_HERE("Session key run out of life");
		return false;
	}

	//
	if(contextOfICC.keyLife > 0)
	{
		contextOfICC.keyLife--;
	}
	else if(_InterlockedCompareExchange8(& pControlBlock->newKeyPending, 0, 1) != 0)
	{
		// but only in some limit state may a new key installed!
	}

	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		TRACE_HERE("TODO: debug log memory corruption error");
		HandleMemoryCorruption();
		return false;
	}

	register FSP_NormalPacketHeader * const pHdr = & pControlBlock->tmpHeader;
	int result;
	// ICC, if required, is always set just before being sent
	if (skb->GetFlag<TO_BE_CONTINUED>() && skb->len != MAX_BLOCK_SIZE)
	{
		// TODO: debug log failure of segmented and/or online-compressed send
//#ifdef TRACE
		printf_s("\nImcomplete packet to send, opCode: %s(%d, len = %d)\n"
			, opCodeStrings[skb->opCode]
			, skb->opCode
			, skb->len);
//#endif
		return false;
	}
	// Which is the norm. Dynanically generate the fixed header.
	pControlBlock->SetSequenceFlags(pHdr, skb, seq);
	pHdr->hs.opCode = skb->opCode;
	pHdr->hs.version = THIS_FSP_VERSION;
	pHdr->hs.hsp = htobe16(sizeof(FSP_NormalPacketHeader));
	SetIntegrityCheckCode(pHdr, (BYTE *)payload, skb->len);
	if (skb->len > 0)
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), payload, skb->len));
	else
		result = SendPacket(1, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader)));

	return (result > 0);
}



bool LOCALAPI CSocketItemEx::HandleMobileParam(PFSP_HeaderSignature optHdr)
{
	if (optHdr == NULL || optHdr->opCode != MOBILE_PARAM)
		return false;
	//TODO: synchronization of ULA-triggered session key installation
	// the synchronization option header...
	return true;
}



// Emit packet in the send queue, by default transmission of new packets takes precedence
// To make life easier assume it has gain unique access to the LLS socket
// See also HandleEmitQ, HandleFullICC
// TODO: rate-control/quota control
// To be checked: atomicity of sendWindowFirstSN and sendWindowHeadPos...
void ControlBlock::EmitQ(CSocketItem *context)
{
	while (int(sendWindowNextSN - sendBufferNextSN) < 0 && CheckSendWindowLimit())
	{
		register int d = int(sendWindowNextSN - sendWindowFirstSN);
		if (d < 0)
			break;
		d += sendWindowHeadPos;
		//
		register PFSP_SocketBuf skb = HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
		// The flag IS_COMPLETED is for double-stage commit of send buffer, for sake of sending online compressed stream
		if (!skb->GetFlag<IS_COMPLETED>())
		{
#ifdef TRACE
			printf_s("The packet SN#%u is not ready to send; buffered next SN#%u\n", sendWindowNextSN, sendBufferNextSN);
#endif
			break;
		}
		if (!skb->Lock())
		{
//#ifdef TRACE
			printf_s("Should be rare: cannot get the exclusive lock on the packet to send SN#%u\n", sendWindowNextSN);
//#endif
			++sendWindowNextSN;
			continue;
		}

		if (!CSocketItemEx::Emit((CSocketItemEx *)context, skb, sendWindowNextSN))
		{
			skb->Unlock();
			break;
		}
		//
		if (sendWindowNextSN++ == sendWindowFirstSN) // note that the side-effect is a requirement
			((CSocketItemEx *)context)->SetEarliestSendTime();
	}
}
