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


// Remark
//	Rekeying every INT_MAX microseconds (about 2147 seconds, i.e. about 35 minutes) due to time-delta limit
UINT64 LOCALAPI CalculateCookie(BYTE *header, int sizeHdr, timestamp_t t0)
{
	static struct
	{
		ALIGN(MAC_ALIGNMENT)
		BYTE		nonce_prefix[FSP_MAC_IV_SIZE - sizeof(timestamp_t)];
		timestamp_t timeStamp;
		ALIGN(MAC_ALIGNMENT)
		timestamp_t timeSign;
		ALIGN(MAC_ALIGNMENT)
		ae_ctx		ctx;
	} prevCookieContext, cookieContext;
	//
	ALIGN(MAC_ALIGNMENT) BYTE m[OCB_KEY_LEN];
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
		BYTE	st[FSP_SESSION_KEY_LEN];	// in bytes
		memcpy(& prevCookieContext, & cookieContext, sizeof(cookieContext));
		//
		cookieContext.timeStamp = t1;
		rand_w32((uint32_t *) & st, sizeof(st) / sizeof(uint32_t));
		//
		ae_init(& cookieContext.ctx, st, FSP_SESSION_KEY_LEN, FSP_MAC_IV_SIZE, FSP_TAG_SIZE);
	}

	ALIGN(MAC_ALIGNMENT) block r;
	if((long long)(t0 - cookieContext.timeStamp) < INT_MAX)
	{
		cookieContext.timeSign = t0;
		ae_encrypt(& cookieContext.ctx, cookieContext.nonce_prefix, m, sizeof(m), & cookieContext.timeSign, sizeof(timestamp_t), & m, & r, 1);
	}
	else
	{
		prevCookieContext.timeSign = t0;
		ae_encrypt(& prevCookieContext.ctx, prevCookieContext.nonce_prefix, m, sizeof(m), & prevCookieContext.timeSign, sizeof(timestamp_t), & m, & r, 1);
	}
	return *(uint64_t *) & r;
}


// Given
//	The header to be filled with 
// Do
//	Set ICC value
// Remark
//	IV = (sequenceNo, expectedSN)
//	AAD = (source fiber ID, destination fiber ID, flags, receive window free pages
//		 , version, OpCode, header stack pointer, optional headers)
void LOCALAPI CSocketItemEx::SetIntegrityCheckCodeP1(FSP_NormalPacketHeader *p1)
{
//#ifdef TRACE
//	printf_s("First 16 bytes to including in calculate ICC:\n");
//	DumpNetworkUInt16((UINT16 *)p1, 16);
//#endif
	// prepare vmac memory alignment and initialize the padding
	ALIGN(MAC_ALIGNMENT) unsigned char nonce[FSP_MAC_IV_SIZE];
	int32_t & mbytes = *((int32_t *)nonce);
	ALIGN(MAC_ALIGNMENT) unsigned char padded[MAX_BLOCK_SIZE];

	mbytes = ntohs(p1->hs.hsp) - FSP_MAC_IV_SIZE;
	if (mbytes > sizeof(padded) || mbytes <= 0)
		return;
	memcpy_s(padded, sizeof(padded), (BYTE *) & p1->integrity.id, mbytes);
	if (mbytes < sizeof(padded))
		memset(padded + mbytes, 0, min(mbytes + MAC_ALIGNMENT, sizeof(padded)));

	// "An i byte nonce, is made as the first 16-i bytes of n being zero, and the final i the nonce."
	// here it is (p1->sequenceNo, p1->expectedSN) of 8 bytes
	memset(nonce, 0, sizeof(nonce) - FSP_MAC_IV_SIZE);
	memcpy(nonce + sizeof(nonce) - FSP_MAC_IV_SIZE, p1, FSP_MAC_IV_SIZE);
	//
//#ifdef TRACE
//	printf_s("Nonce:\n");
//	DumpNetworkUInt16((UINT16 *)nonce, 8);
//	printf_s("Padded data of %d bytes (original: %d):\n", ((mbytes + MAC_ALIGNMENT - 1) & ~(MAC_ALIGNMENT - 1)) / 2, mbytes);
//	DumpNetworkUInt16((UINT16 *)padded, ((mbytes + MAC_ALIGNMENT - 1) & ~(MAC_ALIGNMENT - 1)) / 2);
//	printf_s("VMAC Context: \n");
//	DumpNetworkUInt16((UINT16 *)& pControlBlock->mac_ctx, sizeof(pControlBlock->mac_ctx) / 2);
//#endif
#ifndef NDEBUG
	if (_mac_ctx_protect_prolog[0] != MAC_CTX_PROTECT_SIGN
		|| _mac_ctx_protect_prolog[1] != MAC_CTX_PROTECT_SIGN
		|| _mac_ctx_protect_epilog[0] != MAC_CTX_PROTECT_SIGN
		|| _mac_ctx_protect_epilog[1] != MAC_CTX_PROTECT_SIGN)
	{
		printf_s("Fatal! MAC context is destroyed! Session ID = 0x%X\n", this->fidPair.source);
		return;
	}
#endif
	ALIGN(MAC_ALIGNMENT) block r;
	ae_encrypt(& mac_ctx, nonce, NULL, 0, padded, mbytes, NULL, & r, 1);
	p1->integrity.code = *(uint64_t *) & r;
#undef FSP_MAC_IV_SIZE
}

// TODO: Check Integrity code should apply ae_decrypt

/**
 * Storage location of command header, send/receive: remark
 * ('payload buffer' means that the full FSP packet is stored in the payload buffer)
 *
	INIT_CONNECT		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_INIT_CONNECT	temporary		/ temporary: stateless for responder/transient for initiator
	CONNECT_REQUEST		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_CONNECT_REQ		separate payload/ temporary: responder may retransmit it passively/transient for initiator
	RESET				temporary		/ temporary: one-shot only
	PERSIST				separate payload/ separate payload: fixed and optional headers regenerated on each heartbeat
	COMMIT				separate payload/ separate payload buffer: space reserved for fixed and optional headers
	PURE_DATA			separate payload/ separate payload: without any optional header, fixed header regenerate whenever retransmit
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
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetFirstBufferedSend();
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
		pHdr->integrity.code = htonll(tRecentSend);

		CLowerInterface::Singleton()->EnumEffectiveAddresses(pControlBlock->u.connectParams.allowedPrefixes);
		memcpy((BYTE *)payload, pControlBlock->u.connectParams.allowedPrefixes, sizeof(UINT64) * MAX_PHY_INTERFACES);

		pHdr->hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();
		//
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), payload, skb->len));
		break;
	case PERSIST:	// PERSIST is an in-band control packet with optional payload that confirms a connection
		if(! skb->GetFlag<TO_BE_CONTINUED>())	// which mean it has not been chained with sending
			skb->SetFlag<IS_COMPLETED>();
		if(InState(COMMITTING))
			skb->opCode = COMMIT;
	case RESUME:	// RESUME is an in-band control packet that try re-established a broken/paused connection
	case COMMIT:	// COMMIT is always in the queue
	case MULTIPLY:
		result = EmitWithICC(skb, pControlBlock->GetSendWindowFirstSN());
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
	// UNRESOLVED! retransmission consume key life? of course?
	if(--keyLife <= 0)
	{
		TRACE_HERE("Session key run out of life");
		return false;
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
	pHdr->hs.hsp = htons(sizeof(FSP_NormalPacketHeader));
	// Only when the first acknowledgement is received may the faster Keep-Alive timer started. See also OnGetFullICC()
	SetIntegrityCheckCode(*pHdr);
	if (skb->len > 0)
		result = SendPacket(2, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader), payload, skb->len));
	else
		result = SendPacket(1, ScatteredSendBuffers(pHdr, sizeof(FSP_NormalPacketHeader)));

	return (result > 0);
}


// Remark
//	Designed side-effect for mobility support: automatically refresh the corresponding address list...
bool CSocketItemEx::ValidateICC(FSP_NormalPacketHeader *pkt)
{
	UINT64	savedICC = pkt->integrity.code;
	pkt->integrity.id.source = fidPair.peer;
	pkt->integrity.id.peer = fidPair.source;
	SetIntegrityCheckCodeP1(pkt);
	if(pkt->integrity.code != savedICC)
		return false;
	// TODO: automatically register remote address as the favorite contact address
	// iff the integrity check code has passed the validation
	//if(addrFrom.si_family == AF_INET)
	//{
	//}
	//else if(addrFrom.si_family == AF_INET6)
	//{
	//}
	//addrFrom.si_family = 0;	// AF_UNSPEC;	// as the flag
	sockAddrTo[0] = sockAddrTo[MAX_PHY_INTERFACES];
	return true;
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
	while (int(sendWindowNextSN - sendBufferNextSN) < 0
		&& CheckSendWindowLimit( ((CSocketItemEx *)context)->GetCongestWindow()) )
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



//
ControlBlock::PFSP_SocketBuf ControlBlock::PeekAnteCommit() const
{
	register seq_t seq = sendWindowNextSN;
	register int d = int(seq - sendWindowFirstSN);
	register PFSP_SocketBuf skb;
	if (d < 0)
		return NULL;

	while (int(seq - sendBufferNextSN) < 0)
	{
		d += sendWindowHeadPos;
		//
		skb = HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
		if(skb->opCode == COMMIT)
		{
			if(seq + 1 - sendBufferNextSN >= 0)
				return NULL;
			d++;
			return HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
		}

		seq++;
		d = int(seq - sendWindowFirstSN);
	}
	//
	return NULL;
}
