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
	headFreeSID = p->next;	// might be NULL, to be re-calibrated
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
		timestamp_t timeStamp;
		timestamp_t timeSign;
		GCM_AES_CTX	ctx;
	} prevCookieContext, cookieContext;
	//
	ALIGN(MAC_ALIGNMENT) BYTE m[sizeof(FSP_InitiateRequest)];
	timestamp_t t1 = NowUTC();

#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf("\n**** Cookie Context Time-stamp ****\n");
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

	GCM_AES_CTX *ctx;
	uint64_t tag;
	uint64_t nonce;
	if((long long)(t0 - cookieContext.timeStamp) < INT_MAX)
	{
		nonce = cookieContext.timeSign = t0;
		ctx = &cookieContext.ctx;
	}
	else
	{
		nonce = prevCookieContext.timeSign = t0;
		ctx = &prevCookieContext.ctx;
	}
	GCM_AES_AuthenticatedEncrypt(ctx, nonce
		, NULL, 0,
		(const uint64_t *)m, sizeof(m)
		, NULL
		, (octet *)& tag, sizeof(tag));

	return tag;
}



// The ephemeral key is weakly securely established. It is a 64-bit value meant to make obfuscation of the CRC64 tag
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
	contextOfICC.keyLifeRemain = 0;
	contextOfICC.curr.precomputedCRCS0 
		=  CalculateCRC64(* (uint64_t *) & fidPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);
	ALFIDPair recvFIDPair;
	recvFIDPair.peer = fidPair.source;
	recvFIDPair.source = fidPair.peer;
	contextOfICC.curr.precomputedCRCR1
		=  CalculateCRC64(* (uint64_t *) & recvFIDPair, (uint8_t *) & pControlBlock->connectParams, FSP_MAX_KEY_SIZE);
#if defined(TRACE) && (TRACE & TRACE_SLIDEWIN)
	printf_s("Precomputed ICC 0:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedCRCS0, 4);
	printf_s("Precomputed ICC 1:");
	DumpNetworkUInt16((uint16_t *)  & contextOfICC.curr.precomputedCRCR1, 4);
#endif
}



// Given
//	const CommandInstallKey&	Parameter given by ULA
// Do
//	Put the new session key effective starting from the sequence number designated in the parameter given by ULA
// Remark
//	The key length and the first sequence number exploiting the new session key at the receive side next
//	are designated in the control block while the key life and the first sequence number exploiting
//	the new session key at the send side are given in the parameter
// See @DLL::InstallRawKey
void CSocketItemEx::InstallSessionKey(const CommandInstallKey & cmd)
{
#if defined(TRACE) && (TRACE & (TRACE_SLIDEWIN | TRACE_ULACALL))
	printf_s("\n" __FUNCDNAME__ "\tsendWindowNextSN = %u\n"
		"  sendBufferNextSN = %09u, \trecvWindowNextSN = %09u\n"
		"command.nextSendSN = %09u, \t RecvRE snapshot = %09u\n"
		, pControlBlock->sendWindowNextSN
		, pControlBlock->sendBufferNextSN, pControlBlock->recvWindowNextSN
		, cmd.nextSendSN, pControlBlock->connectParams.nextKey$initialSN);
	printf("Key length: %d bits\t", pControlBlock->connectParams.keyBits);
	DumpHexical(cmd.ikm, pControlBlock->connectParams.keyBits / 8);
#endif
	contextOfICC.isPrevSendCRC = contextOfICC.isPrevRecvCRC
		= (InterlockedExchange64((LONGLONG *)&contextOfICC.keyLifeRemain, cmd.keyLife) == 0);
	contextOfICC.noEncrypt = (pControlBlock->noEncrypt != 0);
	contextOfICC.snFirstSendWithCurrKey = cmd.nextSendSN;
	contextOfICC.snFirstRecvWithCurrKey = pControlBlock->connectParams.nextKey$initialSN;

	contextOfICC.InitiateExternalKey(cmd.ikm, pControlBlock->connectParams.keyBits / 8);
}



// Given
//	const void *	The input key material
//	int				effective length of ikm
// Do
//	Initiate the first session key, given the externally provided key material as the master key
//	Apply RFC5869 key extract to derive the master key firstly,
//	Apply RFC5869 key expand to derive the sub-key of the first connection
//	Apply RFC7963 The BLAKE2 Cryptographic Hash and Message Authentication Code as PRF
// Remark
//	Deliberately some-what hard-coded
//	Works in multi-byte character set/ASCII encoding source only
//	Input Key Material MAY include the whole connect parameter
//	As to key extract, optional salt is not provided (the one generated by the initiator has been overridden)
void ICC_Context::InitiateExternalKey(const void *ikm, int n)
{
#ifndef NDEBUG
	_mac_ctx_protect_prolog[0]
	= _mac_ctx_protect_prolog[1]
	= _mac_ctx_protect_epilog[0]
	= _mac_ctx_protect_epilog[1]
	= MAC_CTX_PROTECT_SIGN;
#endif
	prev = curr;

	if (noEncrypt)
	{
		blake2b(curr.rawKey, 64, NULL, 0, ikm, n);
		curr.keyLength = 64;
		return;
	}
	
	octet keyBuffer[FSP_MAX_KEY_SIZE + GMAC_SALT_LEN];
	octet info[30];
	octet zeros[FSP_MAX_KEY_SIZE];
	blake2b_ctx ctx;

	originalKeyLength = (n > FSP_MIN_KEY_SIZE ? FSP_MAX_KEY_SIZE : FSP_MIN_KEY_SIZE);
	if (n > sizeof(SConnectParam))
		n = sizeof(SConnectParam);
	
	bzero(zeros, FSP_MAX_KEY_SIZE);
	bzero(&ctx, sizeof(ctx));
	if (blake2b_init(&ctx, FSP_MAX_KEY_SIZE, NULL, 0) != 0)
	{
		REPORT_ERRMSG_ON_TRACE("Initiate BLAKE2b for key extract failed");
		return;
	}
	blake2b_update(&ctx, zeros, sizeof(zeros));
	blake2b_update(&ctx, ikm, n);
	blake2b_final(&ctx, masterKey);

	memcpy(info, "Establishes an FSP session", 26);
	iBatchRecv = iBatchSend = 1;
	info[26] = 0;
	info[27] = 0;
	info[28] = 0;
	info[29] = 1;
	// T[0] = "", get T[1]
	blake2b(keyBuffer, originalKeyLength + GMAC_SALT_LEN, masterKey, FSP_MAX_KEY_SIZE, info, 30);

	GCM_AES_SetKey(&curr.gcm_aes, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	memcpy(curr.send.key, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	memcpy(curr.send.H, curr.gcm_aes.H, GCM_BLOCK_LEN);
	bzero(keyBuffer, sizeof(keyBuffer));
}



// Given
//	int		ioFlag == 0, output (send); == 1, input (receive)
// Do
//	Slightly modification of RFC5869: take use of ghash subkey instead of T[i-1] to get T[i]
//	Deliberately some-what hard-coded
//	works in multi-byte character set/ASCII encoding source only
void ICC_Context::ForcefulRekey(int ioFlag)
{
	octet keyBuffer[FSP_MAX_KEY_SIZE + GMAC_SALT_LEN];
	octet info[30];
	blake2b_ctx ctx;

	memcpy(info, "Sustains an FSP connection", 26);
	uint32_t u;
	if (ioFlag == 0)
	{
		snFirstSendWithCurrKey += FSP_REKEY_THRESHOLD;
		++iBatchSend;
		isPrevSendCRC = false;
		u = htobe32(iBatchSend);
	}
	else
	{
		snFirstRecvWithCurrKey += FSP_REKEY_THRESHOLD;
		++iBatchRecv;
		isPrevRecvCRC = false;
		u = htobe32(iBatchRecv);
	}
	info[26] = ((octet *)&u)[0];
	info[27] = ((octet *)&u)[1];
	info[28] = ((octet *)&u)[2];
	info[29] = ((octet *)&u)[3];
#if (TRACE & TRACE_PACKET)
	printf_s("\nForcefulRekey(): ioFlag = %d, iBatch = %d"
		"\noriginalKeyLength = %d\n"
		"Master key: ", ioFlag, be32toh(u), originalKeyLength);
	DumpHexical(masterKey, FSP_MAX_KEY_SIZE);
#endif
	// We assume 'prev' context is useless if ever ForcefulRekey() is called
	// assert(originalKeyLength <= FSP_MAX_KEY_SIZE);
	bzero(&ctx, sizeof(ctx));
	if(blake2b_init(&ctx, originalKeyLength + GMAC_SALT_LEN, masterKey, FSP_MAX_KEY_SIZE) != 0)
	{
		REPORT_ERRMSG_ON_TRACE("Initiate BLAKE2b for re-keying failed");
		return;
	}

	if (ioFlag == 0)
	{
		memcpy(& prev.send, & curr.send, sizeof(prev.send));
		blake2b_update(&ctx, prev.send.H, 16);
	}
	else
	{
		memcpy(& prev.gcm_aes, & curr.gcm_aes, sizeof(GCM_AES_CTX));
		blake2b_update(&ctx, prev.gcm_aes.H, 16);
	}
	blake2b_update(&ctx, info, 30);
	blake2b_final(&ctx, keyBuffer);

	if (ioFlag == 0)
	{
		memcpy(curr.send.key, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
		bzero(curr.send.H, GCM_BLOCK_LEN);
		// See also GCM_AES_SetKey
		GCM_AES_CTX ctx;
		ctx.rounds = rijndaelKeySetupEnc(ctx.K, curr.send.key, originalKeyLength * 8);
		bzero(ctx.X, GCM_BLOCK_LEN);
		rijndaelEncrypt(ctx.K, ctx.rounds, ctx.X, curr.send.H);
		//
		bzero(&ctx, sizeof(ctx));
	}
	else
	{
		GCM_AES_SetKey(&curr.gcm_aes, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	}
#if (TRACE & TRACE_PACKET)
	printf_s("New batch key: ");
	DumpHexical(keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	printf_s("AES-hash key: ");
	DumpHexical(curr.gcm_aes.H, GCM_BLOCK_LEN);
	printf_s("Saved send-hash key: ");
	DumpHexical(curr.send.H, GCM_BLOCK_LEN);
#endif

	bzero(&ctx, sizeof(ctx));
	bzero(keyBuffer, sizeof(keyBuffer));
}



// For very large (roughly up to 2^10 * 2^29 = 512 GB in IPv6) file transfer, automatically re-key
// For most session the first key would live to the end of the connection.
inline
GCM_AES_CTX * ICC_Context::GetGCMContextForSend(GCM_AES_CTX & ctx, ControlBlock::seq_t seqNo)
{
	bool b = int32_t(seqNo - snFirstSendWithCurrKey) < 0;
	if (iBatchSend - iBatchRecv == 0)
		return (b ? &prev.gcm_aes : &curr.gcm_aes);
	// If send advanced one batch more than receive, send before current context reuse current receive context
	if (iBatchSend - iBatchRecv == 1 && b)
		return &curr.gcm_aes;
	// If receive advanced one batch more than send, send in current context reuse previous receive context
	if (iBatchSend - iBatchRecv == -1 && !b)
		return &prev.gcm_aes;
	// prefer clarity over cleverness - if ever there is some cleverness?
	octet *sendKey = (b ? prev.send.key : curr.send.key);
	ctx.rounds = rijndaelKeySetupEnc(ctx.K, sendKey, originalKeyLength * 8);
	//	ctx.X would be zeroed every time GCM_AES_SetIV() is called
	memcpy(ctx.H, (b ? prev.send.H : curr.send.H), GCM_BLOCK_LEN);
	*(uint32_t *)ctx.J = *(uint32_t *)(sendKey + originalKeyLength);	// set the salt
	return &ctx;
}



// Remark
//	And initiate that of the child for sending the very first packet
//	The snFirstRecvWithCurrKey is unset until the first response packet is accepted.
void ICC_Context::InheritS0(const ICC_Context &src, ControlBlock::seq_t seq0)
{
	if ((keyLifeRemain = src.keyLifeRemain) == 0)
	{
		curr.precomputedCRCS0 = src.curr.precomputedCRCS0;
		curr.precomputedCRCR1 = src.curr.precomputedCRCR1;
		return;
	}

	isPrevSendCRC = isPrevRecvCRC = false;
	noEncrypt = src.noEncrypt;
	snFirstSendWithCurrKey = seq0 + 1;

	if (noEncrypt)
	{
		prev = src.curr;
		return;
	}

	memcpy(masterKey, src.masterKey, FSP_MAX_KEY_SIZE);
	originalKeyLength = src.originalKeyLength;

	if (src.iBatchRecv == src.iBatchSend)
	{
		prev.gcm_aes = src.curr.gcm_aes;
	}
	else if (src.iBatchRecv - src.iBatchSend == 1)
	{
		prev.gcm_aes = src.prev.gcm_aes;
	}
	else
	{
		prev.gcm_aes.rounds = rijndaelKeySetupEnc(prev.gcm_aes.K, src.curr.send.key, originalKeyLength * 8);
		//	ctx.X would be zeroed every time GCM_AES_SetIV() is called
		memcpy(prev.gcm_aes.H, src.curr.send.H, GCM_BLOCK_LEN);
		*(uint32_t *)prev.gcm_aes.J = *(uint32_t *)(src.curr.send.key + originalKeyLength);	// set the salt
	}

	iBatchRecv = iBatchSend = 1;
}



// Remark
//	And initiate that of the child for accepting the very first packet
//	The snFirstRecvWithCurrKey is set by the caller directly
//	Unlike InheritS0, it does not necessarily applying the most recent key of the original connection
//	because MULTIPLY is out-of-band and it might be in the race condition
//	that MULTIPLY is received before the ULA installs new key
//	Assume this ICC_Context has been zeroed
void ICC_Context::InheritR1(const ICC_Context &src, ControlBlock::seq_t seq0)
{
	if ((keyLifeRemain = src.keyLifeRemain) == 0)
	{
		curr.precomputedCRCS0 = src.curr.precomputedCRCS0;
		curr.precomputedCRCR1 = src.curr.precomputedCRCR1;
		return;
	}

	isPrevSendCRC = isPrevRecvCRC = false;
	noEncrypt = src.noEncrypt;
	snFirstSendWithCurrKey = seq0;

	if (noEncrypt)
	{
		prev = src.curr;
		return;
	}

	memcpy(masterKey, src.masterKey, FSP_MAX_KEY_SIZE);
	originalKeyLength = src.originalKeyLength;

	iBatchRecv = iBatchSend = 1;
	prev.gcm_aes = src.curr.gcm_aes;
	// MULTIPLY may race with ULA installing session key
	prev.gcm_aes = int32_t(snFirstRecvWithCurrKey - src.snFirstRecvWithCurrKey) < 0
		? src.prev.gcm_aes
		: src.curr.gcm_aes;
}



// Hard coded, as specified by the protocol
void ICC_Context::Derive(const octet *info, int LEN)
{
	if (noEncrypt)
	{
		size_t n = curr.keyLength = prev.keyLength;
		blake2b(curr.rawKey, n, prev.rawKey, n, info, LEN);
		return;
	}

	octet keyBuffer[FSP_MAX_KEY_SIZE + GMAC_SALT_LEN];
	blake2b_ctx ctx;
	bzero(&ctx, sizeof(ctx));
	if (blake2b_init(&ctx, originalKeyLength + GMAC_SALT_LEN, masterKey, FSP_MAX_KEY_SIZE) != 0)
	{
		REPORT_ERRMSG_ON_TRACE("Initiate BLAKE2b for derive key for child connection failed");
		return;
	}
	blake2b_update(&ctx, prev.gcm_aes.H, GCM_BLOCK_LEN);
	blake2b_update(&ctx, info, LEN);
	blake2b_final(&ctx, keyBuffer);

	GCM_AES_SetKey(&curr.gcm_aes, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	memcpy(curr.send.key, keyBuffer, originalKeyLength + GMAC_SALT_LEN);
	memcpy(curr.send.H, curr.gcm_aes.H, GCM_BLOCK_LEN);

	bzero(&ctx, sizeof(ctx));
	bzero(keyBuffer, sizeof(keyBuffer));
}



// Given
//	ALFID_T idInitiator				The initiator's branch ALFID (the new ALFID)
//	ALFID_T idResponder				The responder's original ALFID (the parent ALFID)
// Do
//  Set the session key for the packet next sent and the next received. 
//	K_out = PRF(K, [d] || Label || 0x00 || Context || L)
//	[d]		- Depth. It is alike the KDF counter mode as the NIST SP800-108 (not the feedback mode)
//	Label	¨C A string that identifies the purpose for the derived keying material,
//	          here we set to "Multiply an FSP connection"
//	Context	- idInitiator, idResponder
//	Length	- An integer specifying the length (in bits) of the derived keying material K-output
// Remark
//	Assume other fields of contextOfICC have been filled properly,
//	especially contextOfICC.prev = contextOfICC.curr
//  Assume internal of SConnectParam is properly padded
//	It is a bad idea to access internal round key of AES (to utilize blake2b)!
//	Deliberately hard-coded. Depth of key derivation is always 1 for this version of FSP
void LOCALAPI CSocketItemEx::DeriveKey(ALFID_T idInitiator, ALFID_T idResponder)
{
	ALIGN(8)
	octet paddedData[40];
	paddedData[0] = 1;
	memcpy(paddedData + 1, "Multiply an FSP connection", 26); // works in multi-byte character set/ASCII encoding source only
	paddedData[27] = 0;
	// ALFIDs were transmitted in neutral byte order, actually
	*(uint32_t *)(paddedData + 28) = idInitiator;
	*(uint32_t *)(paddedData + 32) = idResponder;
	*(uint32_t *)(paddedData + 36) = htobe32(contextOfICC.originalKeyLength * 8);
	//
	contextOfICC.Derive(paddedData, 40);
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



// Check whether previous KEEP_ALIVE is implicitly acknowledged on getting a validated packet
// It is conservative in the sense that
// it would not suppress overwhelming KEEP_ALIVE if the change is only removal of some subnet entry
inline void CSocketItemEx::CheckAckToKeepAlive()
{
	if (!mobileNoticeInFlight)
		return;
	// ONLY if the packet is accepted at new edge may mobileNoticeInFlight cleared.
	// It costs a little more KEEP_ALIVE packet in flight but it is safer
	register uint64_t subnet = ((PFSP_IN6_ADDR)& tempAddrAccept)->subnet;
	for (register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		if (newPathsToNearEnd[i] == subnet)
		{
			_InterlockedExchange8(&mobileNoticeInFlight, 0);
			return;
		}
	}
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
//	Retransmission DOES consume the key life of authenticated encryption
void * LOCALAPI CSocketItemEx::SetIntegrityCheckCode(FSP_NormalPacketHeader *p1, void *content, int32_t ptLen, uint32_t salt)
{
	// number of octets that 'additional data' in Galois Counter Mode
	const uint32_t byteA = sizeof(FSP_NormalPacketHeader);
	//
	uint32_t seqNo = be32toh(p1->sequenceNo);
	void * buf = content;
	// CRC64 is the initial integrity check algorithm
	if(contextOfICC.keyLifeRemain == 0)
	{
		p1->integrity.code = contextOfICC.curr.precomputedCRCS0;
		p1->integrity.code = CalculateCRC64(CalculateCRC64(0, p1, byteA), content, ptLen);
	}
	else if(int32_t(seqNo - contextOfICC.snFirstSendWithCurrKey) < 0 && contextOfICC.isPrevSendCRC)
	{
		p1->integrity.code = contextOfICC.prev.precomputedCRCS0;
		p1->integrity.code = CalculateCRC64(CalculateCRC64(0, p1, byteA), content, ptLen);
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
		// assert contextOfICC.keyLifeRemain > 0
		uint32_t m = byteA + ptLen;
		if (contextOfICC.keyLifeRemain < m)
		{
#ifdef TRACE
			printf_s("\nSession#%u key run out of life\n", fidPair.source);
#endif
			return NULL;
		}
		contextOfICC.keyLifeRemain -= m;
		if (contextOfICC.keyLifeRemain == 0)
			contextOfICC.keyLifeRemain = 1;	// As a sentinel

		// assert(pControlBlock->sendBufferBlockN <= FSP_REKEY_THRESHOLD);
		contextOfICC.CheckToRekeyBeforeSend(seqNo);
		GCM_AES_CTX ctx;
		GCM_AES_CTX *pCtx = contextOfICC.GetGCMContextForSend(ctx, seqNo);

		ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
		p1->integrity.id = fidPair;
#ifdef DEBUG_ICC
		printf_s("\nBefore SetIntegrityCheckCode: plain-text Len = %d, salt is %X\n", ptLen, salt);
		printf_s("Context selected: ");
		DumpNetworkUInt16((uint16_t *)pCtx->H, 8);
		DumpNetworkUInt16((uint16_t *)pCtx->J, 8);
		printf_s("Header, len = %d, and at most 8 octets of payload:\n", byteA);
		DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + min(4, ptLen / 2));
#endif
		GCM_AES_XorSalt(pCtx, salt);
		if(GCM_AES_AuthenticatedEncrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)content, ptLen
			, (const uint64_t *)p1, byteA
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

#ifdef DEBUG_ICC
	printf_s("After SetIntegrityCheckCode:\n");
	DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + min(4, ptLen / 2));
#endif
	return buf;
}



// Given
//	FSP_NormalPacketHeader *	The pointer to the fixed header
//	int32_t						The size of the ciphertext
//	ALFID_T						The source ALFID of the received packet
//	uint32_t					The xor'ed salt
// Return
//	true if packet authentication passed and the optional payload successfully decrypted
// Remark
//	Assume the headers are 64-bit aligned
bool LOCALAPI CSocketItemEx::ValidateICC(FSP_NormalPacketHeader *p1, int32_t ctLen, ALFID_T idSource, uint32_t salt)
{
	ALIGN(MAC_ALIGNMENT) uint64_t tag[FSP_TAG_SIZE / sizeof(uint64_t)];
	// number of octets that 'additional data' in Galois Counter Mode
	const uint32_t byteA = sizeof(FSP_NormalPacketHeader);

	tag[0] = p1->integrity.code;

	uint32_t seqNo = be32toh(p1->sequenceNo);
	register bool r;
	// CRC64 is the initial integrity check algorithm
	if(contextOfICC.keyLifeRemain == 0)
	{
		p1->integrity.code = contextOfICC.curr.precomputedCRCR1;
		r = (tag[0] == CalculateCRC64(0, p1, byteA + ctLen));
	}
	else if(int32_t(seqNo - contextOfICC.snFirstRecvWithCurrKey) < 0 && contextOfICC.isPrevRecvCRC)
	{
		p1->integrity.code = contextOfICC.prev.precomputedCRCR1;
		r = (tag[0] == CalculateCRC64(0, p1, byteA + ctLen));
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
		contextOfICC.CheckToRekeyAnteAccept(seqNo);
		//
		GCM_AES_CTX *pCtx = int32_t(seqNo - contextOfICC.snFirstRecvWithCurrKey) < 0
			? & contextOfICC.prev.gcm_aes
			: & contextOfICC.curr.gcm_aes;

		p1->integrity.id.source = idSource;
		p1->integrity.id.peer = fidPair.source;
#ifdef DEBUG_ICC
		printf_s("Before ValidateICC, cipher-text Len = %d, salt is %X\n", ctLen, salt);
		printf_s("Context selected: ");
		DumpNetworkUInt16((uint16_t *)pCtx->H, 8);
		DumpNetworkUInt16((uint16_t *)pCtx->J, 8);
		printf_s("Header, len = %d, and at most 8 octets of payload:\n", byteA);
		DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + min(4, ctLen / 2));
#endif
		GCM_AES_XorSalt(pCtx, salt);
		// assert(byteA) == sizeof(FSP_FixedHeader)
		r = (GCM_AES_AuthenticateAndDecrypt(pCtx, *(uint64_t *)p1
			, (const uint8_t *)p1 + byteA, ctLen
			, (const uint64_t *)p1, byteA
			, (const uint8_t *)tag, FSP_TAG_SIZE
			, (uint64_t *)p1 + byteA / sizeof(uint64_t))
			== 0);
		GCM_AES_XorSalt(pCtx, salt);
	}
	p1->integrity.code = tag[0];
#ifdef DEBUG_ICC
	printf_s("After ValidateICC:\n");
	DumpNetworkUInt16((uint16_t *)p1, byteA / 2 + min(4, ctLen / 2));
#endif
	if(! r)
		return false;

	ChangeRemoteValidatedIP();
	CheckAckToKeepAlive();
	return true;
}



/**
 * Storage location of command header, send/receive: remark
 * ('payload buffer' means that the full FSP packet is stored in the payload buffer)
 *
	INIT_CONNECT		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_INIT_CONNECT	temporary		/ temporary: stateless for responder/transient for initiator
	CONNECT_REQUEST		payload buffer	/ temporary: initiator may retransmit it actively/stateless for responder
	ACK_CONNECT_REQ		separate payload/ separate : responder may retransmit it passively/transient for initiator
	RESET				temporary		/ temporary: one-shot only
	ACK_START			payload buffer	/ payload buffer
							Initiator of CONNECT REQUEST may retransmit it actively
							Responder of MULTIPY may retransmit it on demand
	PURE_DATA			separate payload/ separate payload: fixed header regenerated on retransmission
	PERSIST				separate payload/ separate payload: fixed header regenerated on retransmission
	KEEP_ALIVE			temporary		/ temporary: KEEP_ALIVE is always generate on fly
	ACK_FLUSH			temporary		/ temporary: ACK_FLUSH is always generate on fly
	RELEASE				temporary		/ temporary: one-shot only
	MULTIPLY			payload buffer	/ payload buffer: initiator of clone operation may retransmit it actively
 *
 */
// Do
//	Transmit the head packet in the send queue to the remote end
// Remark
//	Starting packets are NOT counted when sending. See also DoEventLoop()
//  The IP address of the near end may change dynamically
//	The function shall be idempotent
//	And it may only be exploited to send packet whose sequence number is the first in the send queue
bool CSocketItemEx::EmitStart()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
	if (!skb->IsComplete())
		return false;
	BYTE *payload = GetSendPtr(skb);
	if(payload == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("TODO: debug log memory corruption error");
		AbortLLS();			// Used to be HandleMemoryCorruption();
		return false;
	}
	skb->timeSent = NowUTC();
	//^This make the initial RTT including the near end's send delay, including timer slice jitter

	int result;
	switch (skb->opCode)
	{
	case ACK_CONNECT_REQ:
		// ACK_CONNECT_REQ is an in-band packet to start a transmit transaction for the responder
	case NULCOMMIT:
		// NULCOMMIT is an in-band payload-less packet that commits a transmit transaction
		// NULCOMMIT is alias to ACK_START to confirm ACK_CONNECT_REQ or MULTIPLY as well
	case PERSIST:
		// PERSIST is a packet with payload that starts a transmit transaction as well
	case RELEASE:
		// RELEASE is an in-band control packet that has both NULCOMMIT and ACK_FLUSH semantics
		result = EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
		skb->MarkSent();
		break;
	case MULTIPLY:
		// The MULTIPLY command head is stored in the queue while the encrypted payload is buffered in cipherText
		result = SendPacket(2, ScatteredSendBuffers(payload, sizeof(FSP_NormalPacketHeader), this->cipherText, skb->len));
		// Only possible for retransmission
		break;
	case INIT_CONNECT:
	case CONNECT_REQUEST:
		// Header has been included in the payload. See also InitiateConnect() and AffirmConnect()
		result = SendPacket(1, ScatteredSendBuffers(payload, skb->len));
		break;
	default:
		BREAK_ON_DEBUG();
		return false;
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
//	ICC, if required, is always set just before being sent
int CSocketItemEx::EmitWithICC(ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq)
{
	ALIGN(MAC_ALIGNMENT) FSP_FixedHeader hdr;
#ifdef EMULATE_LOSS
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
	if(skb->opCode == INIT_CONNECT || skb->opCode == ACK_INIT_CONNECT || skb->opCode == CONNECT_REQUEST)
	{
		printf_s("Assertion failed! %s (opcode: %d) has no ICC field\n", opCodeStrings[skb->opCode], skb->opCode);
		return -EDOM;
	}
#endif
	void  *payload = (FSP_NormalPacketHeader *)this->GetSendPtr(skb);
	if(payload == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("TODO: debug log memory corruption error");
		AbortLLS();			// Used to be HandleMemoryCorruption();
		return -EFAULT;
	}

	SetHeaderSignature(hdr, skb->opCode);
	skb->CopyFlagsTo(&hdr);
	SetSequenceAndWS(&hdr, seq);

	// here we needn't check memory corruption as misbehavior only harms himself
	void * paidLoad = SetIntegrityCheckCode(&hdr, (BYTE *)payload, skb->len);
	if(paidLoad == NULL)
		return -EPERM;
	//
	int r = skb->len > 0
		? SendPacket(2, ScatteredSendBuffers(&hdr, sizeof(FSP_NormalPacketHeader), paidLoad, skb->len))
		: SendPacket(1, ScatteredSendBuffers(&hdr, sizeof(FSP_NormalPacketHeader)));
	skb->timeSent = tRecentSend;
	return r;
}



// Let the compiler do loop-unrolling and embedding
bool LOCALAPI IsInSubnetSet(uint64_t prefix, TSubnets subnets)
{
	for (register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		if (subnets[i] == prefix)
			return true;
	}
	return false;
}



// Check whether local address of the near end is changed because of, say, reconfiguration or hand-over
// It is conservative in the sense that
// it would not suppress overwhelming KEEP_ALIVE if the change is only removal of some subnet entry
bool CSocketItemEx::IsNearEndMoved()
{
	if (_InterlockedExchange8(&isNearEndHandedOver, 0) == 0)
		return false;

	u_int k = CLowerInterface::Singleton.sdSet.fd_count;
	u_int j = 0;
	LONG & w = CLowerInterface::Singleton.disableFlags;
	TSubnets subnets;
	register u_int i;
	register uint64_t prefix;

	memset(subnets, 0, sizeof(TSubnets));
	for (i = 0; i < k; i++)
	{
		if (!BitTest(&w, i))
		{
			prefix = SOCKADDR_SUBNET(&CLowerInterface::Singleton.addresses[i]);
			if (!IsInSubnetSet(prefix, subnets))
			{
				subnets[j++] = prefix;
				if (j >= MAX_PHY_INTERFACES)
					break;
			}
		}
	}
	if (j <= 0)
	{
#if (TRACE & TRACE_HEARTBEAT)
		printf_s("SendKeepAlive-IsNearEndMoved: temporarily there is no path to the near end.\n");
#endif
		return false;
	}

	if (memcmp(savedPathsToNearEnd, subnets, sizeof(TSubnets)) == 0)
		return false;

	// Scan and find out the really new entry
	memset(newPathsToNearEnd, 0, sizeof(TSubnets));
	k = 0;
	for (i = 0; i < j; i++)
	{
		if(! IsInSubnetSet(subnets[i], savedPathsToNearEnd))
			newPathsToNearEnd[k++] = subnets[i];
	}

	memcpy(savedPathsToNearEnd, subnets, sizeof(TSubnets));
	mobileNoticeInFlight = 1;
	return true;
}



// Given
//	FSP_ConnectParam *	pointer to the PEER_SUBNETS header
// Do
//	Process the getting remote address event
// Remark
//	Although the subnet that the host belong to could be mobile, the hostID should be stable
bool CSocketItemEx::HandlePeerSubnets(FSP_ConnectParam* pMobileParam)
{
	if (pMobileParam == NULL || pMobileParam->_h.opCode != PEER_SUBNETS)
		return false;
	//
#ifndef OVER_UDP_IPv4
	// loop roll-out
	SOCKADDR_SUBNET(&sockAddrTo[0]) = pMobileParam->subnets[0];
	SOCKADDR_SUBNET(&sockAddrTo[1]) = pMobileParam->subnets[1];
	SOCKADDR_SUBNET(&sockAddrTo[2]) = pMobileParam->subnets[2];
	SOCKADDR_SUBNET(&sockAddrTo[3]) = pMobileParam->subnets[3];
	// generally speaking host id should not be changed often
	SOCKADDR_HOSTID(&sockAddrTo[0]) = pMobileParam->idListener;
	SOCKADDR_HOSTID(&sockAddrTo[1]) = pMobileParam->idListener;
	SOCKADDR_HOSTID(&sockAddrTo[2]) = pMobileParam->idListener;
	SOCKADDR_HOSTID(&sockAddrTo[3]) = pMobileParam->idListener;
	//
#endif
	return true;
}
