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
#include "blake2b.h"

// From the receiver's point of view the local fiber id was stored in the peer fiber id field of the received packet
ALFID_T CLowerInterface::SetLocalFiberID(ALFID_T value)
{
	if(nearInfo.IsIPv6())
		nearInfo.u.idALF = value;
	return _InterlockedExchange((volatile LONG *) & pktBuf->fidPair.peer, value);
}



// Given
//	PIN6_ADDR	the pointer to placeholder of the [in,out] hint address
// Do
//	Get the head item from the free ALFID list.
//	If the hint address is IN6_ANY, by default the first interface is exploit and the hint address is updated accordingly
//	If the hint address is not IN6_ANY, alter ALFID_T part of it if the prefix part matched the prefix of some interface
// Return
//	the fiber ID, or 0 if no more slot available or hint-address prefix, if any, has no matching interface
ALFID_T LOCALAPI CLowerInterface::RandALFID(PIN6_ADDR hintAddr)
{
	CSocketItemEx *p = headFreeSID;
	int ifIndex;

	if(p == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return 0;
	}

	register BYTE *s = hintAddr->u.Byte;
	if(*(uint64_t *)s != 0)
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
//	const void *pointer to the byte string of cookie material for the calculation
//	int			the length of the cookie material
//	timestamp_t	the time associated with the cookie, to deduce the life-span of the cookie
// Do
//	Calculate the cookie
// Return
//	The 64-bit cookie value
uint64_t LOCALAPI CalculateCookie(const void *header, int sizeHdr, timestamp_t t0)
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
// The algorithm:
//	Take 'fidPair' as the initial accumulative CRC64 value,
//	accumulate 'initCheckCode', 'cookie', 'salt', 'timeDelta' and 'nboTimeStamp' to the CRC64 tag.
//	fidPair is composed of the source ALFID and the peer ALFID
//	where on send side the source is the near-end and the peer is the far-end
//	while on receive side the source is the far-end and the 'peer' is the near-end actually. 
void CSocketItemEx::InstallEphemeralKey()
{
#if defined(TRACE) && (TRACE & (TRACE_SLIDEWIN | TRACE_ULACALL))
	printf_s("\n" __FUNCDNAME__ "\n\tsendBufferSN =  %u, recvWindowNextSN = %u\n"
		, pControlBlock->sendBufferNextSN
		, pControlBlock->recvWindowNextSN);
	//
	printf_s("Session key materials:\n");
	DumpNetworkUInt16((uint16_t *)  & pControlBlock->connectParams, FSP_MAX_KEY_SIZE / 2);
#endif
	contextOfICC.keyLife = 0;
	contextOfICC.curr.precomputedICC[0] 
		=  CalculateCRC64(* (uint64_t *) & fidPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);

	ALFIDPair recvFIDPair;
	recvFIDPair.peer = fidPair.source;
	recvFIDPair.source = fidPair.peer;
	contextOfICC.curr.precomputedICC[1]
		=  CalculateCRC64(* (uint64_t *) & recvFIDPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);
#if defined(TRACE) && (TRACE & (TRACE_SLIDEWIN | TRACE_ULACALL))
	printf_s("Precomputed ICC 0:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[0], 4);
	printf_s("Precomputed ICC 1:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedICC[1], 4);
#endif
}



// Given
//	const CommandInstallKey&	Parameter given by ULA
// Do
//	Put the new session key effective starting from the sequence nubmer designated in the parameter given by ULA
// Remark
//	The key length and the first sequence number exploiting the new session key at the receive side next
//	are designated in the control block while the key life and the first sequence number exploiting
//	the new session key at the send side are given in the parameter
// See @DLL::InstallKey
void CSocketItemEx::InstallSessionKey(const CommandInstallKey & cmd)
{
#if defined(TRACE) && (TRACE & (TRACE_SLIDEWIN | TRACE_ULACALL))
	printf_s("\n" __FUNCDNAME__ "\tsendWindowNextSN = %u\n"
		"  sendBufferNextSN = %09u, \trecvWindowNextSN = %09u\n"
		"command.nextSendSN = %09u, \t RecvRE snapshot = %09u\n"
		, pControlBlock->sendWindowNextSN
		, pControlBlock->sendBufferNextSN, pControlBlock->recvWindowNextSN
		, cmd.nextSendSN, pControlBlock->connectParams.nextKey$initialSN);
	printf("Key length: %d bytes\t", pControlBlock->connectParams.keyLength);
	DumpHexical(& pControlBlock->connectParams, pControlBlock->connectParams.keyLength);
#endif
#ifndef NDEBUG
	contextOfICC._mac_ctx_protect_prolog[0]
		= contextOfICC._mac_ctx_protect_prolog[1]
		= contextOfICC._mac_ctx_protect_epilog[0]
		= contextOfICC._mac_ctx_protect_epilog[1]
		= MAC_CTX_PROTECT_SIGN;
#endif
	contextOfICC.savedCRC = (contextOfICC.keyLife == 0);
	contextOfICC.prev = contextOfICC.curr;
	contextOfICC.noEncrypt = (pControlBlock->noEncrypt != 0);
	if (contextOfICC.noEncrypt)
	{
		contextOfICC.curr.keyLength = pControlBlock->connectParams.keyLength;
		memcpy(contextOfICC.curr.rawKey, & pControlBlock->connectParams, contextOfICC.curr.keyLength);
	}
	else
	{
		GCM_AES_SetKey(&contextOfICC.curr.gcm_aes, (uint8_t *)& pControlBlock->connectParams, pControlBlock->connectParams.keyLength);
	}

	contextOfICC.keyLife = cmd.keyLife;
	contextOfICC.snFirstSendWithCurrKey = cmd.nextSendSN;
	contextOfICC.snFirstRecvWithCurrKey	= pControlBlock->connectParams.nextKey$initialSN;
}



// Given
//	ControlBlock::seq_t sn1			The sequence number of the initiator's MULTIPLY packet
//	ControlBlock::seq_t ackSN		The sequence number of the responder's PERSIST packet
//	ALFID_T idInitiator				The initiator's NEW ALFID
//	ALFID_T idResponder				The responder's original ALFID (the parent ALFID)
// Set the session key for the packet next sent and the next received. KDF counter mode
// As the NIST SP800-108 recommended, K(i) = PRF(K, [i] || Label || 0x00 || Context || L)
// Psuedo-Random-Function is GCM_SecureHash, with the nonce set to sn1 concated with ackSN (sn1 || ackSN)
// Label  ¨C A string that identifies the purpose for the derived keying material, here we set to "Multiply an FSP connection"
// Context - idInitiator, idResponder
// Length -  An integer specifying the length (in bits) of the derived keying material K-output
// Assume other fields of contextOfICC have been filled properly, especially contextOfICC.prev = contextOfICC.curr
void LOCALAPI CSocketItemEx::DeriveNextKey(ControlBlock::seq_t sn1, ControlBlock::seq_t ackSN, ALFID_T idInitiator, ALFID_T idResponder)
{
	register uint8_t *keyBuffer = (uint8_t *)& pControlBlock->connectParams;
	register int L = pControlBlock->connectParams.keyLength;
	uint64_t nonce = htobe64(((uint64_t)sn1 << 32) + ackSN);
	// hard coded, as specified by the protocol
	ALIGN(8)
	uint8_t paddedData[40];
	memcpy(paddedData + 1, "Multiply an FSP connection", 26); // works in multi-byte character set/ASCII encoding source only
	paddedData[27] = 0;
	// ALFIDs were transmitted in neutral byte order, actually
	*(uint32_t *)(paddedData + 28) = idInitiator;
	*(uint32_t *)(paddedData + 32) = idResponder;
	*(uint32_t *)(paddedData + 36) = htobe32(L * 8);

	// The first 128 bits
	paddedData[0] = 1;
	GCM_SecureHash(& contextOfICC.prev.gcm_aes
		, nonce
		, paddedData, sizeof(paddedData)
		, keyBuffer, 16);
	if(L <= 16)
		goto l_return;
	// the second 128-bits
	paddedData[0] = 2;
	GCM_SecureHash(& contextOfICC.prev.gcm_aes
		, nonce
		, paddedData, sizeof(paddedData)
		, keyBuffer + 16, 16);
	// 384-bits AES does not exist. However, Blowfish, the default cipher algorithm exploited by OpenVPN,
	// although suspectible to birthday attack in some senario, can utilise key length up to 448 bits
	// https://sweet32.info/  mitigate the attack by forcing frequent rekeying with reneg-bytes 64000000. (64MB) 
	if (L <= 32)
		goto l_return;
	// the third 128-bits
	paddedData[0] = 3;
	GCM_SecureHash(&contextOfICC.prev.gcm_aes
		, nonce
		, paddedData, sizeof(paddedData)
		, keyBuffer + 32, 16);
	//
l_return:
#ifndef NDEBUG
	if (L != 16 && L != 32 && L != 48)
		throw - EDOM;	// unsupported key length, there must be protocol incoherency
#endif
	GCM_AES_SetKey(& contextOfICC.curr.gcm_aes, keyBuffer, L);
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
#ifndef OVER_UDP_IPv4 //_DEBUG //
	register int i = MAX_PHY_INTERFACES - 1;
	for (; i >= 0; i--)
	{
		if (SOCKADDR_SUBNET(sockAddrTo + i) == SOCKADDR_SUBNET(sockAddrTo + MAX_PHY_INTERFACES)
		 && SOCKADDR_HOSTID(sockAddrTo + i) == SOCKADDR_HOSTID(sockAddrTo + MAX_PHY_INTERFACES))
		{
			SOCKADDR_SUBNET(sockAddrTo + i) = SOCKADDR_SUBNET(sockAddrTo);	// save the original favorite target IP address
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
	SOCKADDR_SUBNET(sockAddrTo) = SOCKADDR_SUBNET(sockAddrTo + MAX_PHY_INTERFACES);
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
	uint32_t byteA = be16toh(p1->hs.hsp);	// number of octets that 'additional data' in Galois Counter Mode
	if (byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
		return NULL;
	//
	uint32_t seqNo = be32toh(p1->sequenceNo);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("\nBefore SetIntegrityCheckCode: ptLen = %d\n", ptLen);
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif

	void * buf = content;
	// CRC64
	if(contextOfICC.keyLife == 0)
	{
		p1->integrity.code = contextOfICC.curr.precomputedICC[0];
		p1->integrity.code = CalculateCRC64(0, (uint8_t *)p1, byteA);
	}
	else if(int32_t(seqNo - contextOfICC.snFirstSendWithCurrKey) < 0 && contextOfICC.savedCRC)
	{
		p1->integrity.code = contextOfICC.prev.precomputedICC[0];
		p1->integrity.code = CalculateCRC64(0, (uint8_t *)p1, byteA);
	}
	else if (contextOfICC.noEncrypt)
	{
		p1->integrity.id = fidPair;
		//
		blake2b_ctx ctx;
		memset(& ctx, sizeof(ctx), 0);
		blake2b_init(&ctx, sizeof(p1->integrity), contextOfICC.curr.rawKey, contextOfICC.curr.keyLength);
		blake2b_update(&ctx, p1, byteA);
		blake2b_update(&ctx, content, ptLen);
		blake2b_final(&ctx, &p1->integrity.code);
	}
	else
	{
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.snFirstSendWithCurrKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;

		ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
		p1->integrity.id = fidPair;
		GCM_AES_XorSalt(pCtx, salt);
		if(GCM_AES_AuthenticatedEncrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)content, ptLen
			, (const uint64_t *)p1 + 1, byteA - sizeof(uint64_t)
			, (uint64_t *)this->cipherText
			, (uint8_t *)tag, FSP_TAG_SIZE)
			!= 0)
		{
			GCM_AES_XorSalt(pCtx, salt);
			return NULL;
		}
		GCM_AES_XorSalt(pCtx, salt);
		buf = this->cipherText;
		p1->integrity.code = tag[0];
	}

#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("After SetIntegrityCheckCode:\n");
	DumpNetworkUInt16((uint16_t *)p1, sizeof(FSP_NormalPacketHeader) / 2);
#endif
	return buf;
}



// Given
//	FSP_NormalPacketHeader *	The pointer to the fixed header
//	int32_t						The size of the ciphertext
//	ALFID_T						The source ALFID of the received packet
//	uint32_t					The xor'ed salt
// Return
//	true if all of the headers passed authentication and the optional payload successfully decrypted
// Remark
//	Assume the headers are 64-bit aligned
//	UNRESOLVED!? Is it meaningless to recover the ICC field?	// p1->integrity.code = *(uint64_t *)tag;
bool LOCALAPI CSocketItemEx::ValidateICC(FSP_NormalPacketHeader *p1, int32_t ctLen, ALFID_T idSource, uint32_t salt)
{
	ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
	uint32_t byteA = be16toh(p1->hs.hsp);
	if (byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
		return false;

	tag[0] = p1->integrity.code;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Before ValidateICC:\n");
	DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + 4);
#endif
	uint32_t seqNo = be32toh(p1->sequenceNo);
	register bool r;
	// CRC64
	if(contextOfICC.keyLife == 0)
	{
		// CRC64 is the initial integrity check algorithm
		p1->integrity.code = contextOfICC.curr.precomputedICC[1];
		r = (tag[0] == CalculateCRC64(0, (uint8_t *)p1, byteA));
	}
	else if(int32_t(seqNo - contextOfICC.snFirstRecvWithCurrKey) < 0 && contextOfICC.savedCRC)
	{
		// well, well, send is not the same as receive...
		p1->integrity.code = contextOfICC.prev.precomputedICC[1];
		r = (tag[0] == CalculateCRC64(0, (uint8_t *)p1, byteA));
	}
	else if (contextOfICC.noEncrypt)
	{
		p1->integrity.id.source = idSource;
		p1->integrity.id.peer = fidPair.source;
		//
		uint64_t tagOut;
		blake2b(&tagOut, sizeof(tagOut)
			, contextOfICC.curr.rawKey, contextOfICC.curr.keyLength
			, p1, byteA + ctLen);
		//
		r = (tagOut == tag[0]);
	}
	else
	{
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.snFirstRecvWithCurrKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;
		uint32_t byteA = be16toh(p1->hs.hsp);
		if(byteA < sizeof(FSP_NormalPacketHeader) || byteA > MAX_LLS_BLOCK_SIZE || (byteA & (sizeof(uint64_t) - 1)) != 0)
			return false;

		GCM_AES_XorSalt(pCtx, salt);
		p1->integrity.id.source = idSource;
		p1->integrity.id.peer = fidPair.source;
		r = (GCM_AES_AuthenticateAndDecrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)p1 + byteA, ctLen
			, (const uint64_t *)p1 + 1, byteA - sizeof(uint64_t)
			, (const uint8_t *)tag, FSP_TAG_SIZE
			, (uint64_t *)p1 + byteA / sizeof(uint64_t))
			== 0);
		GCM_AES_XorSalt(pCtx, salt);
	}
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("After ValidateICC:\n");
	DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + 4);
#endif
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
	PURE_DATA			separate payload/ separate payload: fixed header regenerated on retransmission
	KEEP_ALIVE			temporary		/ temporary: KEEP_ALIVE is always generate on fly
	ACK_FLUSH			temporary		/ temporary: ACK_FLUSH is always generate on fly
	RELEASE				temporary		/ temporary: one-shot only
	MULTIPLY			payload buffer	/ payload buffer: initiator of clone operation may retransmit it actively
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
		REPORT_ERRMSG_ON_TRACE("TODO: debug log memory corruption error");
		AbortLLS();			// Used to be HandleMemoryCorruption();
		return false;
	}

	register FSP_NormalPacketHeader * const pHdr = & pControlBlock->tmpHeader;
	int result;
	skb->timeSent = NowUTC();	// This make the initial RTT including the near end's send delay, including timer slice jitter
	switch (skb->opCode)
	{
	case ACK_CONNECT_REQ:
		pControlBlock->SetSequenceFlags(pHdr, pControlBlock->sendWindowNextSN);
		pHdr->integrity.code = htobe64(skb->timeSent);

		CLowerInterface::Singleton.EnumEffectiveAddresses(pControlBlock->connectParams.allowedPrefixes);
		memcpy((BYTE *)payload, pControlBlock->connectParams.allowedPrefixes, sizeof(uint64_t) * MAX_PHY_INTERFACES);

		pHdr->hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();
		//
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), payload, skb->len));
		break;
	case PERSIST:	// PERSIST is an in-band control packet with optional payload that confirms a connection
		result = EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
		skb->SetFlag<IS_SENT>();
		break;
	// Only possible for retransmission
	case MULTIPLY:	// The MULTIPLY command head is stored in the queue while the encrypted payload is buffered in cipherText
		result = SendPacket(2, ScatteredSendBuffers(payload, sizeof(FSP_NormalPacketHeader), this->cipherText, skb->len));
		break;
	case INIT_CONNECT:
	case CONNECT_REQUEST:
		// Header has been included in the payload. See also InitiateConnect() and AffirmConnect()
		result = SendPacket(1, ScatteredSendBuffers(payload, skb->len));
		break;
	default:
		BREAK_ON_DEBUG();
		result = 0;	// unrecognized packet type is simply ignored?!
	}
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("Session#%u emit %s, result = %d, time : 0x%016llX\n"
		, fidPair.source, opCodeStrings[skb->opCode], result, skb->timeSent);
#endif
	return (result >= 0);
}



// Given
//	ControlBlock::PFSP_SocketBuf	pointer to the buffer descriptor of the packet to send
//	ControlBlock::seq_t				the sequence number assigned to the packet to send
// Do
//	Transmit a packet to the remote end, enforcing secure mobility support
// Return
//	Number of octets sent, 0 if nothing sent successfully
//	Negative if failed otherwise
// Remark
//  The IP address of the near end may change dynamically
int CSocketItemEx::EmitWithICC(ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq)
{
#if (TRACE & TRACE_HEARTBEAT)  || defined(EMULATE_LOSS)
	volatile unsigned int vRand = 0;
	if (rand_s((unsigned int *)&vRand) == 0 && vRand > (UINT_MAX >> 2) + (UINT_MAX >> 1))
	{
		printf_s("\nError seed = 0x%X for debug retransmission\n"
			"\tA packet %s (#%u) is discarded deliberately\n", vRand, opCodeStrings[skb->opCode], seq);
		return -ECANCELED;	// emulate 33.33% loss rate
	}
	else
	{
		printf_s("Error seed = 0x%X, going to send %s (#%u)\n", vRand, opCodeStrings[skb->opCode], seq);
	}
#endif
#ifdef _DEBUG
	if(skb->opCode == INIT_CONNECT || skb->opCode == ACK_INIT_CONNECT || skb->opCode == CONNECT_REQUEST || skb->opCode == ACK_CONNECT_REQ)
	{
		printf_s("Assertion failed! %s (opcode: %d) has no ICC field\n", opCodeStrings[skb->opCode], skb->opCode);
		return -EDOM;
	}
#endif
	if(contextOfICC.keyLife == 1)
	{
#ifdef TRACE
		printf_s("\nSession#%u key run out of life\n", fidPair.source);
#endif
		return -EACCES;
	}

	// UNRESOLVED! retransmission consume key life? of course?
	if(contextOfICC.keyLife > 0)
		contextOfICC.keyLife--;

	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("TODO: debug log memory corruption error");
		AbortLLS();			// Used to be HandleMemoryCorruption();
		return -EFAULT;
	}

	register FSP_NormalPacketHeader *pHdr = & pControlBlock->tmpHeader;
	// ICC, if required, is always set just before being sent
	pControlBlock->SetSequenceFlags(pHdr, seq);
	if (skb->GetFlag<END_OF_TRANSACTION>())
		pHdr->SetFlag<EndOfTransaction>();
	pHdr->hs.Set(skb->opCode, sizeof(FSP_NormalPacketHeader));

	// here we needn't check memory corruption as mishavior only harms himself
	void * paidLoad = SetIntegrityCheckCode(pHdr, (BYTE *)payload, skb->len);
	if(paidLoad == NULL)
		return -EPERM;
	//
	if (skb->len > 0)
		return SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), paidLoad, skb->len));
	else
		return SendPacket(1, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader)));
}



#ifndef OVER_UDP_IPv4
// On near end's IPv6 address changed automatically send KEEP_ALIVE
// No matter whether the KEEP_ALIVE flag was set when the connection was setup
void CSocketItemEx::OnLocalAddressChanged()
{
	if (!WaitUseMutex())
		return;
	if (IsPassive())
		goto l_return;
	
	SendKeepAlive();

	// If destination interface happen to be on the same host, update the registered address simultaneously
	// UNRESOLVED!? The default interface should be the one that is set to promiscuous
	if (SOCKADDR_SUBNET(sockAddrTo) == 0 && SOCKADDR_HOSTID(sockAddrTo) == 0)
	{
		PSOCKADDR_IN6 p = CLowerInterface::Singleton.addresses + CLowerInterface::Singleton.iRecvAddr;
		SOCKADDR_SUBNET(sockAddrTo) = SOCKADDR_SUBNET(p);
		SOCKADDR_HOSTID(sockAddrTo) = SOCKADDR_HOSTID(p);
	}
l_return:
	SetMutexFree();
}
#endif



// Given
//	PFSP_HeaderSignature	point to the signature part of the PEER_SUBNETS header
// Do
//	Process the getting remote address event
// Remark
//	Although the subnet that the host belong to could be mobile, the hostID should be stable
//	PEER_SUBNETS used to be MOBILE_PARAM
//	TODO: prove that FSP is compatible with Identifier-Locator-Addressing
bool CSocketItemEx::HandlePeerSubnets(PFSP_HeaderSignature optHdr)
{
	if (optHdr == NULL || optHdr->opCode != PEER_SUBNETS)
		return false;
	//
#ifndef OVER_UDP_IPv4
	FSP_ConnectParam *pMobileParam = (FSP_ConnectParam *)((uint8_t *)optHdr + sizeof(FSP_HeaderSignature) - sizeof(FSP_ConnectParam));
	// loop roll-out
	SOCKADDR_SUBNET(&sockAddrTo[0]) = pMobileParam->subnets[0];
	SOCKADDR_SUBNET(&sockAddrTo[1]) = pMobileParam->subnets[1];
	SOCKADDR_SUBNET(&sockAddrTo[2]) = pMobileParam->subnets[2];
	SOCKADDR_SUBNET(&sockAddrTo[3]) = pMobileParam->subnets[3];
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("New target address set for host 0x%X (== 0x%X)\n", SOCKADDR_HOSTID(sockAddrTo), pMobileParam->idHost);
#endif
	//
#endif
	//
	return true;
}



// Emit packet in the send queue, by default transmission of new packets takes precedence
// To make life easier assume it has gain unique access to the LLS socket
// for the protocol to work it should allow at least one packet in flight
// TODO: rate-control/quota control
void CSocketItemEx::EmitQ()
{
	const ControlBlock::seq_t sendBufferNextSN = _InterlockedOr((LONG *) & pControlBlock->sendBufferNextSN, 0);
	const ControlBlock::seq_t lastSN
		= int(pControlBlock->sendWindowLimitSN - pControlBlock->sendWindowFirstSN) <= 0
		? pControlBlock->sendWindowFirstSN + 1
		: pControlBlock->sendWindowLimitSN;
	ControlBlock::seq_t & nextSN = pControlBlock->sendWindowNextSN;
	//
	bool shouldRetry = pControlBlock->CountSendBuffered() > 0;
	register ControlBlock::PFSP_SocketBuf skb;
	while (int(nextSN - sendBufferNextSN) < 0 && int(nextSN - lastSN) < 0)
	{
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		if (!skb->GetFlag<IS_COMPLETED>())
		{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("Not ready to send packet SN#%u; next to buffer SN#%u\n", nextSN, sendBufferNextSN);
#endif 
			break;
		}

		if (!skb->Lock())
		{
#ifndef NDEBUG
			printf_s("Should be rare: cannot get the exclusive lock on the packet to send SN#%u\n", nextSN);
#endif
			break;
		}

		if (EmitWithICC(skb, nextSN) <= 0)
		{
			skb->Unlock();
			break;
		}
		skb->SetFlag<IS_SENT>();
		skb->timeSent = NowUTC();	// not necessarily tRecentSend
		pControlBlock->SlideNextToSend();
	}
	if(shouldRetry)
		AddResendTimer(tRoundTrip_us >> 8);
}
