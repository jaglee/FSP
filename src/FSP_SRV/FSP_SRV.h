/*
 * FSP lower-layer service program, the header file to have common system include file included
 * and declare functions scattered across variable source files
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

#define _CRT_RAND_S
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <time.h>

#include "../endian.h"
#include "../FSP_Impl.h"

#include "gcm-aes.h"

#define COOKIE_KEY_LEN			20	// salt include, as in RFC4543 5.4
#define MULTIPLY_BACKLOG_SIZE	8


 // random generator is somehow dependent on implementation. hardware preferred.
 // might be optimized by loop unrolling
static inline
void rand_w32(uint32_t *p, int n) { for (register int i = 0; i < min(n, 32); i++) { rand_s(p + i); } }


// Return the number of microseconds elapsed since Jan 1, 1970 (unix epoch time)
extern "C" timestamp_t NowUTC();


struct FSP_FixedHeader : public FSP_NormalPacketHeader
{
	void Set(FSPOperationCode code, uint16_t hsp, uint32_t seqThis, uint32_t seqExpected, int32_t advRecvWinSize)
	{
		hs.opCode = code;
		hs.major = THIS_FSP_VERSION;
		hs.offset = htobe16(hsp);
		sequenceNo = htobe32(seqThis);
		ClearFlags();
		SetRecvWS(advRecvWinSize);
		expectedSN = htobe32(seqExpected);
	}
	//
	void ClearFlags() { flags_ws[0] = 0; }
	void SetRecvWS(int32_t v) { flags_ws[1] = (octet)(v >> 16); flags_ws[2] = (octet)(v >> 8); flags_ws[3] = (octet)v; }
};


/**
* It requires Advanced IPv6 API support to get the application layer thread ID from the IP packet control structure
*/
// packet information on local address and interface number
// for IPv6, local fiber ID is derived from local address
struct CtrlMsgHdr
{
#if _WIN32_WINNT >= 0x0600
	CMSGHDR		pktHdr;
#else
	WSACMSGHDR	pktHdr;
#endif
	FSP_SINKINF	u;

	bool IsIPv6() const { return (pktHdr.cmsg_level == IPPROTO_IPV6); }
};


/**
 * Get the application layer thread ID from the (IPv6 raw-)socket address
 */
#define SOCKADDR_SUBNET(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->subnet)
#define SOCKADDR_ALFID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idALF)
#define SOCKADDR_HOSTID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idHost)



// per-host connection mumber and listener limit defined in LLS:
#ifndef MAX_CONNECTION_NUM	// must be some power value of 2
# define MAX_CONNECTION_NUM	256
#endif
#define MAX_LISTENER_NUM	4
#define MAX_RETRANSMISSION	8



class CommandNewSessionSrv: protected CommandToLLS
{
protected:
	friend class ConnectRequestQueue;
	friend class CSocketItemEx;
	friend class CSocketSrvTLB;

	// defined in command.cpp
	friend void LOCALAPI Listen(CommandNewSessionSrv &);
	friend void LOCALAPI Connect(CommandNewSessionSrv &);
	friend void LOCALAPI Accept(CommandNewSessionSrv &);

	HANDLE	hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	HANDLE	hEvent;
	UINT	index;
	CSocketItemEx *pSocket;

public:
	CommandNewSessionSrv(const CommandToLLS *);
	CommandNewSessionSrv() {}

	void DoConnect();
};



class CommandCloneSessionSrv: CommandNewSessionSrv
{
	friend void Multiply(CommandCloneSessionSrv &);
public:
	CommandCloneSessionSrv(const CommandToLLS *p): CommandNewSessionSrv(p)
	{
		// Used to receive 'committing' flag in the command
	}
};




#include <pshpack1.h>


// Implemented in os_....cpp because light-weight IPC mutual-locks are OS-dependent
class ConnectRequestQueue : public CLightMutex
{
	// volatile char mutex;	// in CLightMutex
	char mayFull;
	int	head;
	int tail;
	CommandNewSessionSrv q[CONNECT_BACKLOG_SIZE];
public:
	int Push(const CommandNewSessionSrv *);
	int Remove(int);
};



struct PktBufferBlock
{
	ALIGN(MAC_ALIGNMENT)
	int32_t	lenData;
	ControlBlock::seq_t	pktSeqNo;	// in host byte-order
	ALFIDPair	fidPair;
	FSP_FixedHeader hdr;
	octet	payload[MAX_BLOCK_SIZE];
};



struct ScatteredSendBuffers
{
	WSABUF	scattered[3];	// at most three segments: the fiberID pair, header and payload
	ScatteredSendBuffers() { }
	ScatteredSendBuffers(void * p1, int n1) { scattered[1].buf = (CHAR *)p1; scattered[1].len = n1; }
	ScatteredSendBuffers(void * p1, int n1, void * p2, int n2)
	{
		scattered[1].buf = (CHAR *)p1;
		scattered[1].len = n1;
		scattered[2].buf = (CHAR *)p2;
		scattered[2].len = n2;
	}
};



// Applier should make sure together with the optional header it would be fit in one IPv6 or UDP packet
struct FSP_PreparedKEEP_ALIVE
{
	FSP_SelectiveNACK sentinel;
	FSP_SelectiveNACK::GapDescriptor gaps
		[(MAX_BLOCK_SIZE - sizeof(FSP_SelectiveNACK)) / sizeof(FSP_SelectiveNACK::GapDescriptor)];
	//
	uint32_t		n;	// n >= 0, number of (gapWidth, dataLength) tuples
};


struct FSP_KeepAliveExtension
{
	FSP_FixedHeader			hdr;
	FSP_ConnectParam		mp;
	FSP_PreparedKEEP_ALIVE	snack;
	void SetHostID(PSOCKADDR_IN6 ipi6) { mp.idListener = SOCKADDR_HOSTID(ipi6); }
};




// Context management of integrity check code
struct ICC_Context
{
#ifndef NDEBUG
#define MAC_CTX_PROTECT_SIGN	0xA5A5C3C3A5C3A5C3ULL
	ALIGN(MAC_ALIGNMENT)
	uint64_t	_mac_ctx_protect_prolog[2];
#endif
	// precomputed CRCs are placed in such a way that send and receive direction are managed separately
	union
	{
		// CRC64 with ephemeral key is applied when keyLifeRemain == 0, respective
		// precomputed values are stored in precomputedCRCS0 and precomputedCRCR1
		struct
		{
			octet	rawKey[sizeof(GCM_AES_CTX)];
			int32_t	keyLength;
		};
		//^raw key meant for secure hash mode
		struct
		{
			union
			{
				uint64_t	precomputedCRCR1;	// precomputed CRC value for Receiver role/Input side
				GCM_AES_CTX	gcm_aes;
			};
			union
			{
				uint64_t	precomputedCRCS0;	// precomputed CRC value for Sender role/Output side
				struct
				{
					octet	key[FSP_MAX_KEY_SIZE + GMAC_SALT_LEN];
					uint8_t	H[GCM_BLOCK_LEN];	/* hash subkey, save one block encryption */
				} send;
			};
		};
	} curr, prev;

#ifndef NDEBUG
	uint64_t	_mac_ctx_protect_epilog[2];
#endif
	uint64_t	keyLifeRemain;	// in terms of number of octets that could be encrypted
	octet		masterKey[FSP_MAX_KEY_SIZE];
	uint32_t	iBatchRecv;
	uint32_t	iBatchSend;
	uint8_t		originalKeyLength;
	bool		noEncrypt;
	bool		isPrevSendCRC;
	bool		isPrevRecvCRC;
	// only when there is no packet left applied with previous key may current key changed  
	// the sequence number of the first packet to be sent or received with current key, respectively
	ControlBlock::seq_t	snFirstSendWithCurrKey;
	ControlBlock::seq_t	snFirstRecvWithCurrKey;
	// Given
	//	const void *	the input key material, shall be less than 512 bits for this FSP version
	//	int				the length of the key material in octets, shall be no greater than 64
	// Do
	//	Extract and install internal key for the first batch
	// Remark
	//	Each batch consists of FSP_REKEY_THRESHOLD packets
	void InitiateExternalKey(const void *, int);
	// Given 0 for output (0 appears like o, send), 1 for input(1 appears like i, receive)
	void ForcefulRekey(int);
	// Given the sequence number, check whether it should re-key before send
	// The caller should make sure that re-keying is not too frequent to 
	// keep unacknowledged packets to be resent correctly
	void CheckToRekeyBeforeSend(ControlBlock::seq_t seqNo)
	{
#if (TRACE & TRACE_PACKET)
		printf_s("CheckToRekeyBeforeSend: seq#%u\n"
			"\tsnFirstSendWithCurrKey = %u\n"
			, seqNo
			, snFirstSendWithCurrKey);
#endif
		// From snFirstSendWithCurrKey + FSP_REKEY_THRESHOLD, inclusively, apply new key
		if (int32_t(seqNo - snFirstSendWithCurrKey - FSP_REKEY_THRESHOLD) >= 0)
			ForcefulRekey(0);
	}
	// Before accepting packet, check whether it needs re-keying to validate it. If it does need, do re-key
	// Assume every packet in the receive window is either encrypted in the new re-keyed key
	void CheckToRekeyAnteAccept(ControlBlock::seq_t seqNo)
	{
#if (TRACE & TRACE_PACKET)
		printf_s("CheckToRekeyAnteAccept: seq#%u\n"
			"\tsnFirstSendWithCurrKey = %u\n"
			, seqNo
			, snFirstRecvWithCurrKey);
#endif
		if (int32_t(seqNo - snFirstRecvWithCurrKey - FSP_REKEY_THRESHOLD) < 0
		 || int32_t(seqNo - snFirstRecvWithCurrKey - FSP_REKEY_THRESHOLD * 2) >= 0)
		{
			return;
		}
		ForcefulRekey(1);
	}
	// Given
	//	GCM_AES_CTX &	[out]	Preserved storage of the GCM_AES context
	//	ControlBlock::seq_t		The sequence number of the packet to send	
	// Return
	//	The GCM_AES context selected for send, might be prepared on the fly
	GCM_AES_CTX * GetGCMContextForSend(GCM_AES_CTX &, ControlBlock::seq_t);
	// Given
	//	const ICC_Context &		The ICC context of the parent connection
	//	ControlBlock::seq_t		The sequence number of the first packet to send by the child connection
	// Do
	//	Copy the core parameter of security context of the parent connection
	// Remark
	//	InheritS0 is for send/output/initiative/zero-start direction
	//  InheritR1 is for recv/input/responder/first-ready direction
	void InheritS0(const ICC_Context &, ControlBlock::seq_t);
	void InheritR1(const ICC_Context &, ControlBlock::seq_t);
	//
	void Derive(const octet *, int);
};



class CSocketItemEx : public CSocketItem
{
	friend class CLowerInterface;
	friend class CSocketSrvTLB;

	friend void Multiply(CommandCloneSessionSrv &);

	HANDLE	hSrcMemory;
	DWORD	idSrcProcess;
	//
	void Destroy();	// override that of the base class
	bool IsPassive() const { return lowState == LISTENING; }
	void SetPassive() { lowState = LISTENING; }
	//
	bool IsProcessAlive();
	//
protected:
	PktBufferBlock * headPacket;	// But UNRESOLVED! There used to be an independent packet queue for each SCB for sake of fairness
	TSubnets	savedPathsToNearEnd;
	TSubnets	newPathsToNearEnd;
	char		isNearEndHandedOver;
	char		mobileNoticeInFlight;
	//
	ICC_Context	contextOfICC;
	ALIGN(MAC_ALIGNMENT)
	octet		cipherText[MAX_BLOCK_SIZE];

	// multi-home/mobility/resilience support (see also CInterface::EnumEffectiveAddresses):
	// MAX_PHY_INTERFACES is hard-coded to 4
	// sockAddrTo[0] is the most preferred address (care of address)
	// sockAddrTo[3] is the home-address
	// while sockAddr[1], sockAddr[2] are backup-up/load-balance address
	// the extra one is for saving temporary souce address
	SOCKADDR_INET	sockAddrTo[MAX_PHY_INTERFACES + 1];
	FSP_ADDRINFO_EX	tempAddrAccept;

	const char *lockedAt;	// == NULL if not locked, or else the function name that locked the socket

	char	hasAcceptedRELEASE : 1;
	char	inUse : 1;
	char	delayAckPending : 1;
	char	transactional;	// The cache value of the EoT flag of the very first packet
	FSP_Session_State lowState;

	ALFID_T		idParent;

	// chainlist on the collision entry of the remote ALFID TLB
	CSocketItemEx * prevRemote;

	// chainlist on the collision entry of the near ALFID TLB
	CSocketItemEx * next;
	CSocketItemEx * prevSame;

	uint32_t	tRoundTrip_us;	// round trip time evaluated in microsecond
	uint32_t	rttVar_us;		// Variance of RTT
	uint32_t	tRTO_us;		// Retransmission time out value in microsecond. SHOULD be shorter than 60 seconds

	bool		increaSlow;		// Whether in it is started in a slow rate which is to be incremented exponentially, default false
	int8_t		countRTTincreasement;
	double		sendRate_Bpus;	// current send rate, byte per microsecond (!)
	double		quotaLeft;		// in bytes
	timestamp_t tPreviousTimeSlot;

	//- There used to be tKeepAlive_ms here. now reserved
	HANDLE		timer;			// the repeating timer

	timestamp_t	tSessionBegin;
	timestamp_t	tLastRecv;
	timestamp_t tMigrate;
	timestamp_t tRecentSend;
	ControlBlock::FSP_SocketBuf skbRecvClone;

	uint32_t	nextOOBSN;	// host byte order for near end. if it overflow the session MUST be terminated
	uint32_t	lastOOBSN;	// host byte order, the serial number of peer's last out-of-band packet

	ControlBlock::seq_t		savedAckedSN;	// Peer's SN acknowedged by the near end
	ControlBlock::seq_t		savedSendSN;	// SN of the packet carrying SNACK
	struct SAckFlushCache
	{
		FSP_FixedHeader		hdr;
		FSP_SelectiveNACK	snack;
	} ALIGN(MAC_ALIGNMENT) cacheAckFlush;

	void AbortLLS(bool haveTLBLocked = false);

	void EnableDelayAck() { delayAckPending = 1; }
	void RemoveTimers();
	bool LOCALAPI ReplaceTimer(uint32_t);

	// The minimum round-trip time allowable depends on timer resolution,
	// but do not bother to guess delay caused by near-end task-scheduling
	void SetFirstRTT(int64_t tDiff)
	{
		if (tDiff <= 0)
			tRoundTrip_us = 1;
		else if (tDiff > UINT32_MAX)
			tRoundTrip_us = UINT32_MAX;
		else
			tRoundTrip_us = (uint32_t)tDiff;
		rttVar_us = tRoundTrip_us >> 1;
		sendRate_Bpus = double(MAX_BLOCK_SIZE * SLOW_START_WINDOW_SIZE) / tRoundTrip_us;
		// TODO: to check: initially quotaPerTick is zero, and noQuotaAlloc is false.
	}
	// Given
	//	int64_t		the round trip time of the packet due
	// Do
	//	Update the smoothed RTT
	void UpdateRTT(int64_t);

	bool InState(FSP_Session_State s) { return lowState == s; }
	bool InStates(int n, ...);
	// synchronize the state in the 'cache' and the real state in the session control block
	void SyncState()
	{
		register FSP_Session_State s = pControlBlock->state;
		if (_InterlockedExchange8((char *)& lowState, s) != s)
			tMigrate = NowUTC();
	}
	void SetState(FSP_Session_State s) { _InterlockedExchange8((char *)& pControlBlock->state, s); SyncState(); }

	void SetSequenceAndWS(struct FSP_FixedHeader* pHdr, ControlBlock::seq_t seq1)
	{
		ControlBlock::seq_t snExpected = pControlBlock->recvWindowExpectedSN;
		pHdr->sequenceNo = htobe32(seq1);
		pHdr->expectedSN = htobe32(snExpected);
		pHdr->SetRecvWS(int32_t(GetRecvWindowLastSN() - snExpected));
	}

	void SignHeaderWith(FSP_FixedHeader* p, FSPOperationCode code, uint16_t hsp, uint32_t seqThis, uint32_t snExpected)
	{
		p->Set(code, hsp, seqThis, snExpected, int32_t(GetRecvWindowLastSN() - snExpected));
	}
 

	bool HasBeenCommitted() { return pControlBlock->HasBeenCommitted(); }
	// Return true if really transit, false if the (half) connection is finised and to notify
	inline bool TransitOnPeerCommit();

	bool HandlePeerSubnets(struct FSP_ConnectParam*);

	// return -EEXIST if overridden, -EFAULT if memory error, or payload effectively placed
	int	PlacePayload();

	int	 SendPacket(register ULONG, ScatteredSendBuffers);
	bool EmitStart();
	bool SendAckFlush();
	bool SendKeepAlive();
	void SendReset();

	bool IsNearEndMoved();
	int	 EmitWithICC(ControlBlock::PFSP_SocketBuf, ControlBlock::seq_t);

	void KeepAlive();
	void DoEventLoop();

	static VOID NTAPI KeepAlive(PVOID c, BOOLEAN) { ((CSocketItemEx *)c)->KeepAlive(); }
	//
public:
#ifdef _DEBUG
	void SetTouchTime(timestamp_t t) { tLastRecv = tRecentSend = t; }
#endif
	bool MapControlBlock(const CommandNewSessionSrv &);
	void InitAssociation();

#define LockWithActiveULA() LockWithActiveULAt(__func__)
#define WaitUseMutex()		WaitUseMutexAt(__func__)
	bool WaitUseMutexAt(const char *);
	bool LockWithActiveULAt(const char *);
	void SetMutexFree() { lockedAt = NULL; }

	bool IsInUse() { return inUse != 0 && pControlBlock != NULL; }
	void ClearInUse() { inUse = 0; }
	bool TestSetInUse() { if (inUse != 0) { return false; } else { inUse = 1; return true; } }
	//^We need no interlocked bitfield operation because the whole TLB is locked on allocating the socket

	void InstallEphemeralKey();
	void InstallSessionKey(const CommandInstallKey &);
	void LOCALAPI DeriveKey(ALFID_T idInitiator, ALFID_T idResponder);

	bool CheckMemoryBorder(ControlBlock::PFSP_SocketBuf p)
	{
		uint32_t d = uint32_t((BYTE *)p - (BYTE*)pControlBlock);
		return (d >= sizeof(ControlBlock) && d < dwMemorySize);
	}

	// Convert the relative address in the control block to the address in process space
	// checked, so that ill-behaviored ULA may not cheat LLS to access data of others
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb)
	{
		uint32_t offset;
		BYTE * p = pControlBlock->GetSendPtr(skb, offset);
		return (offset < sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
	}
	BYTE * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb)
	{
		uint32_t offset;
		BYTE * p = pControlBlock->GetRecvPtr(skb, offset);
		return (offset < sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
	}

	ControlBlock::seq_t GetRecvWindowFirstSN() { return (ControlBlock::seq_t)LCKREAD(pControlBlock->recvWindowFirstSN); }
	ControlBlock::seq_t GetRecvWindowLastSN()
	{
		return (ControlBlock::seq_t)LCKREAD(pControlBlock->recvWindowFirstSN) + pControlBlock->recvBufferBlockN;
	}
	int32_t GetRecvWindowHeadPos() { return LCKREAD(pControlBlock->recvWindowHeadPos); }

	void SetNearEndInfo(const CtrlMsgHdr & nearInfo)
	{
		pControlBlock->nearEndInfo.cmsg_level = nearInfo.pktHdr.cmsg_level;
		*(FSP_SINKINF *)& pControlBlock->nearEndInfo = nearInfo.u;
	}
	void SetRemoteFiberID(ALFID_T id);

	char *PeerName() const { return (char *)pControlBlock->peerAddr.name; }

	int ResolveToIPv6(const char *);
	int ResolveToFSPoverIPv4(const char *, const char *);

	bool Notify(FSP_ServiceCode);
	void SignalEvent() { ::SetEvent(hEvent); }
	void SignalFirstEvent(FSP_ServiceCode code) { pControlBlock->notices.SetHead(code); ::SetEvent(hEvent); }
	//
	int LOCALAPI AcceptSNACK(ControlBlock::seq_t, FSP_SelectiveNACK::GapDescriptor *, int);
	int32_t LOCALAPI GenerateSNACK(FSP_PreparedKEEP_ALIVE &, ControlBlock::seq_t &, int);
	//
	void InitiateConnect();
	void DisposeOnReset();
	void Reject(uint32_t);
	void InitiateMultiply(CSocketItemEx *);
	bool FinalizeMultiply();

	void AffirmConnect(const SConnectParam &, ALFID_T);

	// Calculate offset of the given sequence number to the left edge of the receive window
	int32_t OffsetToRecvWinLeftEdge(ControlBlock::seq_t seq1)
	{
		return int32_t(seq1 - LCKREAD(pControlBlock->recvWindowFirstSN));
	}

	// Given
	//	ControlBlock::seq_t	The sequence number of the packet that mostly expected by the remote end
	// Return
	//	true if the sequence number of the expected packet fall in the send window of the near end
	//	false if otherwise
	// Apply this function to counter back some replay-attack
	bool IsAckExpected(ControlBlock::seq_t seq1)
	{
		int32_t d = int32_t(seq1 - pControlBlock->sendWindowNextSN);
		return (0 <= d + pControlBlock->sendBufferBlockN && d <= 0);
	}

	// Given the fixed header, the content (plain-text), the length of the context and the xor-value of salt
	void * LOCALAPI SetIntegrityCheckCode(FSP_NormalPacketHeader *, void * = NULL, int32_t = 0, uint32_t = 0);

	// Solid input,  the payload, if any, is copied later
	bool LOCALAPI ValidateICC(FSP_NormalPacketHeader *, int32_t, ALFID_T, uint32_t);
	bool ValidateICC() { return ValidateICC(&headPacket->hdr, headPacket->lenData, fidPair.peer, 0); }

	int ValidateSNACK(ControlBlock::seq_t&, FSP_SelectiveNACK*);
	// Register source IPv6 address of a validated received packet as the favorite returning IP address
	inline void ChangeRemoteValidatedIP();
	// Check whether previous KEEP_ALIVE is implicitly acknowledged on getting a validated packet
	inline void CheckAckToKeepAlive();

	void ScheduleConnect(CommandNewSessionSrv *);
	// On Feb.17, 2019 Semantics of KeepAlive was fundamentally changed. Now it is the heartbeat of the local side
	// Send-pacing is a yet-to-implement feature of the rate-control based congestion control sublayer/manager
	void RestartKeepAlive() { ReplaceTimer(TIMER_SLICE_ms * 2); }

	// Command of ULA
	void ProcessCommand(CommandToLLS *);
	void Listen();
	void Connect();
	void Accept();

	// Event triggered by the remote peer
	void OnConnectRequestAck();
	void OnGetNulCommit();
	void OnGetPersist();
	void OnGetPureData();	// PURE_DATA
	void OnAckFlush();		// ACK_FLUSH is always out-of-band
	void OnGetRelease();	// RELEASE may not carry payload
	void OnGetMultiply();	// MULTIPLY is in-band at the initiative side, out-of-band at the passive side
	void OnGetKeepAlive();	// KEEP_ALIVE is always out-of-band
	void LOCALAPI OnGetReset(FSP_RejectConnect &);

	void HandleFullICC(PktBufferBlock *, FSPOperationCode);
};

#include <poppack.h>


// The backlog of connection multiplication, for buffering the payload piggybacked by the MULTIPLY packet
// By reuse the fields 'cipherText' and 'skbRecvClone' of CSocketItemEx
//	contextOfICC.snFirstRecvWithCurrKey => initialSN
//	SOCKADDR_ALFID and SOCKADDR_HOSTID of sockAddrTo: idRemote and remoteHostID
class CMultiplyBacklogItem: public CSocketItemEx
{
	friend	class CSocketSrvTLB;
public:
	// copy in the payload, reuse the encryption buffer as the plaintext buffer. left-aligned as normal
	void	CopyInPlainText(const uint8_t *buf, int32_t n) { skbRecvClone.len = n; if(n > 0) memcpy(cipherText, buf, n); }
	// copy out the flag, version and opcode fields. assume 32-bit alignment
	void	CopyOutFVO(ControlBlock::PFSP_SocketBuf skb) { *(int32_t *)&skb->marks = *(int32_t *)& skbRecvClone.marks; }
	// copy out the payload
	int		CopyOutPlainText(uint8_t *buf)
	{
		int32_t n = skbRecvClone.len;
		if (n < 0 || n > MAX_BLOCK_SIZE)
			return -EPERM;
		if (n > 0)
			memcpy(buf, cipherText, n);
		return n;
	}
	//
	void	ResponseToMultiply();
};



// The translate look-aside buffer of the server's socket pool
class CSocketSrvTLB
{
protected:
	SRWLOCK rtSRWLock;	// runtime Slim-Read-Write Lock

	ALIGN(MAC_ALIGNMENT)
	CSocketItemEx listenerSlots[MAX_LISTENER_NUM];
	ALIGN(MAC_ALIGNMENT)
	CSocketItemEx itemStorage[MAX_CONNECTION_NUM];

	// The translation look-aside buffer of the socket items
	CSocketItemEx *tlbSockets[MAX_CONNECTION_NUM];
	CSocketItemEx *tlbSocketsByRemote[MAX_CONNECTION_NUM];

	// The free list
	CSocketItemEx *headFreeSID, *tailFreeSID;

	// The scanvenge cache; it does waste some space, but saves much time
	struct
	{
		CSocketItemEx	*pSocket;
		timestamp_t		timeRecycled;
	}		scavengeCache[MAX_CONNECTION_NUM];
	LONG	topOfSC;
	bool	PutToScavengeCache(CSocketItemEx *, timestamp_t);

	void InitMutex() { InitializeSRWLock(&rtSRWLock); }
public:
	CSocketSrvTLB();
#ifdef NDEBUG
	void AcquireMutex() { AcquireSRWLockExclusive(& rtSRWLock); }
#else
	void AcquireMutex();
#endif
	void ReleaseMutex() { ReleaseSRWLockExclusive(& rtSRWLock); }

	CSocketItemEx * AllocItem(const CommandNewSessionSrv &);
	CSocketItemEx * AllocItem(ALFID_T);
	CSocketItemEx * AllocItem();
	void FreeItemDonotCareLock(CSocketItemEx *r);
	void FreeItem(CSocketItemEx *r) { AcquireMutex(); FreeItemDonotCareLock(r); ReleaseMutex(); }

	CSocketItemEx * operator[](ALFID_T);

	void PutToListenTLB(CSocketItemEx *, int);
	bool PutToRemoteTLB(CMultiplyBacklogItem *);
	// Given the remote host Id, the remote ALFID and the near end's parent id return the matching
	CMultiplyBacklogItem * FindByRemoteId(uint32_t, ALFID_T, ALFID_T);
};



// A singleton
class CLowerInterface: public CSocketSrvTLB
{
private:
	friend class CSocketItemEx;

	static const u_int SD_SETSIZE = 32;	// hard-coded, bit number of LONG; assume FD_SETSIZE >= 32

	HANDLE	thReceiver;	// the handle of the thread that listens
	HANDLE	hMobililty;	// handling mobility, the handle of the address-changed event

	SOCKET	sdSend;		// the socket descriptor, would at last be unbound for sending only
	fd_set	sdSet;		// set of socket descriptor for listening, one element for each physical interface
	DWORD	interfaces[FD_SETSIZE];
	SOCKADDR_IN6 addresses[FD_SETSIZE];	// by default IPv6 addresses, but an entry might be a UDP over IPv4 address
#if defined(_DEBUG) && defined(_WINDLL)
	friend void UnitTestSelectPath();
#endif

	LONG	disableFlags;	// harf of the default FD_SETSIZE
#ifndef OVER_UDP_IPv4
	ULONG	iRecvAddr;		// index into addresses
	inline	void DisableSocket(SOCKET);
#else
	// For FSP over UDP/IPv4 bind the UDP-socket
	void DisableSocket(SOCKET) {}
	int BindSendRecv(const SOCKADDR_IN *, int);
#endif

	// intermediate buffer to hold the fixed packet header, the optional header and the data
	PktBufferBlock	pktBuf[1];
	DWORD	countRecv;

	// storage location part of the particular receipt of a remote packet, respectively
	// remote-end address and near-end address
	SOCKADDR_INET	addrFrom;
	CtrlMsgHdr		nearInfo;
	// descriptor of what is received, i.e. the particular receipt of a remote packet
	WSAMSG			mesgInfo;

	template<typename THdr> THdr * FSP_OperationHeader() { return (THdr *) & pktBuf->hdr; }

	ALFID_T			GetLocalFiberID() const { return nearInfo.u.idALF; }
	ALFID_T			SetLocalFiberID(ALFID_T);
	ALFID_T			GetRemoteFiberID() const  { return SOCKADDR_ALFID(mesgInfo.name); }

	CSocketItemEx	*MapSocket() { return (*this)[GetLocalFiberID()]; }

protected:
	// defined in remote.cpp
	// processing individual type of packet header
	void LOCALAPI OnGetInitConnect();
	void LOCALAPI OnInitConnectAck();
	void LOCALAPI OnGetConnectRequest();

	// defined in mobile.cpp
	int LOCALAPI EnumEffectiveAddresses(uint64_t *);
	int	AcceptAndProcess(SOCKET);

	// defined in os-dependent source file
	inline int SetInterfaceOptions(SOCKET);
	static DWORD WINAPI ProcessRemotePacket(LPVOID);

public:
	~CLowerInterface() { Destroy(); }
	bool Initialize();
	void Destroy();

	// return the least possible overriden random fiber ID:
	ALFID_T LOCALAPI RandALFID(PIN6_ADDR);
	ALFID_T LOCALAPI RandALFID();
	int LOCALAPI SendBack(char *, int);
	// It might be necessary to send reset BEFORE a connection context is established
	void LOCALAPI SendPrematureReset(uint32_t = 0, CSocketItemEx * = NULL);

	inline bool IsPrefixDuplicated(int, PIN6_ADDR);
	inline bool LearnAddresses();
	inline void MakeALFIDsPool();
	inline void ProcessRemotePacket();
	//^ the thread entry function for processing packet sent from the remote-end peer

#ifndef OVER_UDP_IPv4
	// For FSP over IPv6 raw-socket, preconfigure an IPv6 interface with ALFID pool
	inline void SetLocalApplicationLayerFiberIDs(int);
	//
	inline void RemoveALFIDAddressPool(ULONG);		// ULONG: NET_IFINDEX
	// When an interface is removed/disabled, e.g. due to administrative shutdown at least one IPv6 address is unregistered
	inline void OnRemoveIPv6Address(ULONG, const IN6_ADDR &);	// ULONG: NET_IFINDEX
	// When an interface is enabled, at least one new IPv6 address is added. More detail needed here than OnRemove
	inline void OnAddingIPv6Address(ULONG, const SOCKADDR_IN6 &);	// ULONG: NET_IFINDEX
	inline void OnIPv6AddressMayAdded(ULONG, const SOCKADDR_IN6 &);	// ULONG: NET_IFINDEX
	//
	bool LOCALAPI SelectPath(PFSP_SINKINF, ALFID_T, ULONG, const SOCKADDR_INET *);
#else
	// No, in IPv4 network FSP does not support multi-path
	bool SelectPath(PFSP_SINKINF, ALFID_T, ULONG, const SOCKADDR_INET *) { return false; }
#endif

	static CLowerInterface Singleton;	// this class is effectively a namespace
};



// OS-specific time wheel management
class TimerWheel
{
	static HANDLE	timerQueue;
public:
	static HANDLE	Singleton() { return timerQueue; }
	TimerWheel();
	~TimerWheel();
};


// defined in socket.cpp
void LOCALAPI DumpHexical(const void *, int);
void LOCALAPI DumpNetworkUInt16(uint16_t *, int);

// defined in mobile.cpp
uint64_t LOCALAPI CalculateCookie(const void *, int, timestamp_t);

// defined in CRC64.c
extern "C" uint64_t CalculateCRC64(register uint64_t, register const void *, size_t);

// power(3, a) 	// less stringent than pow(3, a) ?
inline double CubicPower(double a) { return a * a * a; }
