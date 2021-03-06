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


#include "../FSP_Impl.h"
#include "gcm-aes.h"

#define COOKIE_KEY_LEN			20	// salt include, as in RFC4543 5.4

#if _MSC_VER

// random generator is somehow dependent on implementation. hardware preferred.
// might be optimized by loop unrolling
static inline
void rand_w32(uint32_t *p, int n) { for (register int i = 0; i < min(n, 32); i++) { rand_s(p + i); } }

#elif defined(__linux__) || defined(__CYGWIN__) || defined(__MINGW32__)

extern "C" void rand_w32(u32 *, int);

#endif

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

	FSP_FixedHeader(FSP_NormalPacketHeader &r): FSP_NormalPacketHeader(r) {}
	FSP_FixedHeader() {}
};


// packet information on local address and interface number
// for IPv6, local fiber ID is derived from local address
struct CtrlMsgHdr
{

#if defined(__WINDOWS__)
# if _WIN32_WINNT >= 0x0600
	CMSGHDR		pktHdr;
# else
	WSACMSGHDR	pktHdr;
# endif
#elif defined(__linux__) || defined(__CYGWIN__)
	/**
	 * It requires Advanced IPv6 API support [RFC2292]
	 * to get the application layer thread ID from the IP packet control structure
	 */
	struct {
		socklen_t  cmsg_len;   /* #bytes, including this header */
		int        cmsg_level; /* originating protocol */
		int        cmsg_type;  /* protocol-specific type */
				   /* followed by unsigned char cmsg_data[]; */
	} pktHdr;
#endif

	FSP_SINKINF	u;
	void CopySinkInfTo(PFSP_SINKINF tgt) const { *tgt = u; }
	bool IsIPv6() const { return (pktHdr.cmsg_level == IPPROTO_IPV6); }
};


/**
 * Get the application layer thread ID from the (IPv6 raw-)socket address
 */
#define SOCKADDR_SUBNET(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->subnet)
#define SOCKADDR_ALFID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idALF)
#define SOCKADDR_HOSTID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idHost)



// per-host connection number and listener limit defined in LLS:
#ifndef MAX_CONNECTION_NUM	// must be some power value of 2
# define MAX_CONNECTION_NUM	256
#endif
#define MAX_LISTENER_NUM	4
#define MAX_RETRANSMISSION	8

class CSocketItemEx;
struct SProcessRoot;

struct CommandNewSessionSrvEntry: CommandNewSessionCommon
{
#if defined(__linux__) || defined(__CYGWIN__)
	int		hShm;			// handle of the shared memory, open by name
	pthread_t	idThread;	// working thread associated with the new session request
#elif defined(__WINDOWS__)
	DWORD	idProcess;
	HANDLE	hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
#endif

	int		index;
	class	CSocketItemEx* pSocket;
};


class CommandNewSessionSrv: protected CommandNewSessionSrvEntry
{
	friend class ConnectRequestQueue;
	friend class CSocketItemEx;
	friend class CSocketSrvTLB;

	// defined in command.cpp
	friend CSocketItemEx* LOCALAPI Connect(const CommandNewSessionSrv&, SProcessRoot *);
	friend CSocketItemEx* LOCALAPI Listen(const CommandNewSessionSrv&, SProcessRoot *);
	friend CSocketItemEx* LOCALAPI Accept(const CommandNewSessionSrv&);
public:
	CommandNewSessionSrv(const CommandNewSession*);
	CommandNewSessionSrv() {}

	void DoConnect();
};



class CommandCloneSessionSrv: public CommandNewSessionSrv
{
	friend CSocketItemEx * Multiply(const CommandCloneSessionSrv &);
public:
	CommandCloneSessionSrv(const CommandNewSession *p) : CommandNewSessionSrv(p)
	{
		// Used to receive 'committing' flag in the command
	}
};



// Implemented in os_....cpp because light-weight IPC mutual-locks are OS-dependent
class ConnectRequestQueue : public CLightMutex
{
	char mayFull;
	int	head;
	int tail;
	CommandNewSessionSrvEntry q[CONNECT_BACKLOG_SIZE];
public:
	static ConnectRequestQueue requests;
	ConnectRequestQueue() { memset(this, 0, sizeof(ConnectRequestQueue)); }
	int Push(const CommandNewSessionSrv *);
	int Remove(int);
	CommandNewSessionSrv & operator [](int i)
	{
		return *(CommandNewSessionSrv *)&q[i < 0 ? 0 : i % CONNECT_BACKLOG_SIZE];
	}
};



struct PktBufferBlock
{
	ALIGN(FSP_ALIGNMENT)
	ALFIDPair	fidPair;
	FSP_FixedHeader hdr;
	octet	payload[MAX_BLOCK_SIZE];
};



struct ScatteredSendBuffers
{
#if defined(__WINDOWS__)
	WSABUF	scattered[3];	// at most three segments: the fiberID pair, header and payload
	ScatteredSendBuffers(void * p1, int n1) { scattered[1].buf = (CHAR *)p1; scattered[1].len = n1; }
	ScatteredSendBuffers(void * p1, int n1, void * p2, int n2)
	{
		scattered[1].buf = (CHAR *)p1;
		scattered[1].len = n1;
		scattered[2].buf = (CHAR *)p2;
		scattered[2].len = n2;
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	struct iovec scattered[3];
	ScatteredSendBuffers(void * p1, int n1) { scattered[1].iov_base = p1; scattered[1].iov_len = n1; }
	ScatteredSendBuffers(void * p1, int n1, void * p2, int n2)
	{
		scattered[1].iov_base = p1;
		scattered[1].iov_len = n1;
		scattered[2].iov_base = p2;
		scattered[2].iov_len = n2;
	}
#endif
	ScatteredSendBuffers() { }
};


struct SAckFlushCache
{
	FSP_FixedHeader		hdr;
	FSP_SelectiveNACK	snack;
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
	ALIGN(MAC_ALIGNMENT)
	uint64_t	_mac_ctx_protect_epilog[2];
#endif
	uint64_t	keyLifeRemain;	// in terms of number of octets that could be encrypted
	octet		masterKey[FSP_MAX_KEY_SIZE];
	int32_t		iBatchRecv;
	int32_t		iBatchSend;
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
	// Do
	//	Copy the core parameter of security context of the parent connection
	// Remark
	//	InheritS0 is for send/output/initiative/zero-start direction
	//  InheritR1 is for recv/input/responder/first-ready direction
	void InheritS0(const ICC_Context &);
	void InheritR1(const ICC_Context &);
	//
	void Derive(const octet *, int);
};



/**
 *	Socket entries for different ULA processes form a forest of socket kinship tree.
 *	In the forest each ULA process is mapped to a socket kinship tree whose root
 *	is the socket either created on setting up the first connection
 *	to some service end point, or on activating a passive FSP end point
 *	to accept some remote connection request.
 */
struct SProcessRoot
{
	pthread_t		hThreadWait;
	HPIPE_T			sdPipe;
	unsigned long	index;
	CSocketItemEx	*latest;
	//
	void LoopOnULACommand();
	int  RecvFromPipe(void* buffer, int capacity);
	int  SendNotificationTo(ALFID_T fiberID, FSP_NoticeCode code);
};



struct SocketItemEx : CSocketItem
{
	// Control blocks of the same ULA's session consitute a forest
	SProcessRoot	*rootULA;
	// chained list on the collision entry of the remote ALFID TLB
	CSocketItemEx	*prevRemote;
	// chained list on the collision entry of the near ALFID TLB
	CSocketItemEx	*prevSame;

	timer_t			timer;
	int				countULACommand;

	PktBufferBlock* headPacket;	// But UNRESOLVED! There used to be an independent packet queue for each SCB for sake of fairness
	int32_t			lenPktData;
	ControlBlock::seq_t	pktSeqNo;	// in host byte-order

	// temporary state for mobile management
	TSubnets	savedPathsToNearEnd;
	TSubnets	newPathsToNearEnd;
	char		isNearEndHandedOver;
	char		mobileNoticeInFlight;

	ALFID_T		idParent;

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

	const char* lockedAt;	// == NULL if not locked, or else the function name that locked the socket

	// Cached 'trunk' state
	union
	{
	char	allFlags;
	struct
	{
	char	resetPending : 1;
	char	markInUse : 1;
	char	hasAcceptedRELEASE : 1;
	char	delayAckPending : 1;
	char	callbackTimerPending : 1;
	};
	};

	FSP_Session_State lowState;

	// State variables for RTT and rate management
	ControlBlock::seq_t snLastRecv;

	uint32_t	tRoundTrip_us;	// round trip time evaluated in microsecond
	uint32_t	rttVar_us;		// Variance of RTT
	uint32_t	tRTO_us;		// Retransmission time out value in microsecond. SHOULD be shorter than 60 seconds

	bool		increaSlow;		// Whether in it is started in a slow rate which is to be incremented exponentially, default false
	int8_t		countRTTincreasement;

	double		sendRate_Bpus;	// current send rate, byte per microsecond (!)
	double		quotaLeft;		// in bytes
	timestamp_t tPreviousTimeSlot;
	timestamp_t tPreviousLifeDetection;

	timestamp_t	tSessionBegin;
	timestamp_t	tLastRecv;
	timestamp_t tMigrate;
	timestamp_t tRecentSend;
	timestamp_t tLastRecvAny;
	ControlBlock::FSP_SocketBuf skbRecvClone;

	uint32_t	nextOOBSN;	// host byte order for near end. if it overflow the session MUST be terminated
	uint32_t	lastOOBSN;	// host byte order, the serial number of peer's last out-of-band packet
};



class CSocketItemEx : protected SocketItemEx
{
	friend class CLowerInterface;
	friend class CSocketSrvTLB;

	friend CSocketItemEx * Multiply(const CommandCloneSessionSrv&);

	bool IsPassive() const { return lowState == LISTENING; }
	void SetPassive() { lowState = LISTENING; }
	//
protected:
	// But `Free` does NOT `SetMutexFree`
	void Free();
	// Means to keep the context of the socket in the reusable queue
	// NOT implemented in this LLS which is of heavy-weight state
	void PutToResurrectable()
	{
		Free();
		assert(lockedAt != NULL);
	}

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
		tRTO_us = max(RETRANSMIT_MIN_TIMEOUT_us, uint32_t(tDiff + max(TIMER_SLICE_ms * 1000, tDiff * 4)));
		tRTO_us = min(RETRANSMIT_MAX_TIMEOUT_us, tRTO_us);
		sendRate_Bpus = double(MAX_BLOCK_SIZE * SLOW_START_WINDOW_SIZE) / tRoundTrip_us;
		// TODO: to check: initially quotaPerTick is zero, and noQuotaAlloc is false.
	}

	// Given
	//	ControlBlock::seq_t		the sequence number of the packet that the acknowledgement delay was reported
	//	uint32_t				the acknowledgement delay in microseconds (SHOULD be less than 200,000)
	// Do
	//	Update the smoothed RTT
	void UpdateRTT(ControlBlock::seq_t, uint32_t);

	bool InState(FSP_Session_State s) { return lowState == s; }
	bool InStates(FSP_Session_State s1, FSP_Session_State s2, FSP_Session_State s3, FSP_Session_State s4)
	{
		return (lowState == s1 || lowState == s2 || lowState == s3 || lowState == s4);
	}

#if __GNUC__ || _MSC_VER >= 1800
	template<typename... States>
	bool InStates(FSP_Session_State first, States ... rest)
	{
		return lowState == first || InStates(rest...);
	}
#else
	// do some loop-unrolling
	bool InStates(FSP_Session_State s1, FSP_Session_State s2, FSP_Session_State s3, FSP_Session_State s4
		, FSP_Session_State s5)
	{
		return (lowState == s1 || InStates(s2, s3, s4, s5));
	}
	bool InStates(FSP_Session_State s1, FSP_Session_State s2, FSP_Session_State s3, FSP_Session_State s4
		, FSP_Session_State s5, FSP_Session_State s6)
	{
		return (lowState == s1 || lowState == s2 || InStates(s3, s4, s5, s6));
	}
	bool InStates(FSP_Session_State s1, FSP_Session_State s2, FSP_Session_State s3, FSP_Session_State s4
		, FSP_Session_State s5, FSP_Session_State s6, FSP_Session_State s7)
	{
		return (lowState == s1 || lowState == s2 || lowState == s3 || InStates(s4, s5, s6, s7));
	}
#endif

	// synchronize the state in the 'cache' and the real state in the session control block
	void SyncState()
	{
		register FSP_Session_State s = pControlBlock->state;
		if (_InterlockedExchange8((char *)& lowState, s) != s)
			tMigrate = NowUTC();
	}
	void SetState(FSP_Session_State s)
	{
		if (_InterlockedExchange8((char*)&pControlBlock->state, s) != s)
			tMigrate = NowUTC();
		lowState = s;
	}

	void SetSequenceAndWS(FSP_FixedHeader *pHdr, ControlBlock::seq_t seq1)
	{
		ControlBlock::seq_t snExpected = pControlBlock->recvWindowExpectedSN;
		pHdr->sequenceNo = htobe32(seq1);
		pHdr->expectedSN = htobe32(snExpected);
		pHdr->SetRecvWS(int32_t(GetRecvWindowLastSN() - snExpected));
	}

	void SignHeaderWith(FSP_FixedHeader *p, FSPOperationCode code, uint16_t hsp, uint32_t seqThis, uint32_t snAckOrOOB)
	{
		p->Set(code, hsp, seqThis, snAckOrOOB, int32_t(GetRecvWindowLastSN() - pControlBlock->recvWindowExpectedSN));
	}

	// Make state transition on getting NUL_COMMIT or PERSIST which is acknowledgement
	// to responder's initiative of new transmit transaction
	// Attention please! Call this function before slide the send window
	void TransitOnAckStart();

	bool PeerCommitted() { return pControlBlock->PeerCommitted(); }
	// Return true if really transit, false if the (half) connection is finished and to notify
	bool TransitOnPeerCommit();

	bool HandlePeerSubnets(const FSP_ConnectParam *);

	// return -EEXIST if overridden, -EFAULT if memory error, or payload effectively placed
	int	PlacePayload();

	int	 SendPacket(u32, ScatteredSendBuffers);
	bool EmitStart();
	bool EmitRelease();
	bool SendAckFlush();
	bool SendKeepAlive();
	void SendReset();

	bool IsNearEndMoved();
	int	 EmitWithICC(ControlBlock::PFSP_SocketBuf, ControlBlock::seq_t);

	void KeepAlive();
	void DoEventLoop();

#if defined(__WINDOWS__)
	static VOID NTAPI KeepAlive(PVOID c, BOOLEAN) { ((CSocketItemEx*)c)->KeepAlive(); }
#elif defined(__linux__) || defined(__CYGWIN__)
	static void KeepAlive(union sigval v) { ((CSocketItemEx *)v.sival_ptr)->KeepAlive(); }
#endif

	static uint32_t GetSalt(const FSP_FixedHeader& h) { return *(uint32_t*)& h; }
	//
public:
	void AddKinshipTo(SProcessRoot *pULA)
	{
		SProcessRoot& r = *pULA;
		prev = r.latest;
		next = NULL;
		if (r.latest != NULL)
			r.latest->next = this;
		r.latest = this;
		rootULA = &r;
	}

	// The caller should make sure the socket is in kinship with some ULA, i.e. rootULA != NULL
	// Detach it from the latest inUse queue which is in kinship with some ULA at first,
	// then reset `prev` and `next` automatically.
	void RemoveULAKinship()
	{
		if (prev != NULL)
			prev->next = next;
		if (next != NULL)
			next->prev = prev, next = NULL;
		else
			rootULA->latest = (CSocketItemEx*)prev;
		prev = NULL;
		rootULA = NULL;
	}

#ifdef _DEBUG
	void SetTouchTime(timestamp_t t) { tLastRecv = tRecentSend = tLastRecvAny = t; }
#endif
	bool MapControlBlock(const CommandNewSessionSrv &);

	void InitAssociation();

#define WaitUseMutex()		WaitUseMutexAt(__FUNCTION__)		//  __func__
	bool WaitUseMutexAt(const char *);
	void SetMutexFree();

	bool IsInUse() { return (markInUse != 0); }

#if defined(__WINDOWS__)
	bool TestSetState(FSP_Session_State s0) { return (_InterlockedCompareExchange8((char*)&lowState, s0, 0) == 0); }
#elif defined(__GNUC__)
	bool TestSetState(FSP_Session_State s0)
	{
		char zero = 0;
		return (__atomic_compare_exchange_n((char*)&lowState, &zero, s0, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
	}
#endif

	void InstallEphemeralKey();
	void InstallSessionKey(const CommandInstallKey &);
	void LOCALAPI DeriveKey(ALFID_T idInitiator, ALFID_T idResponder);

	bool CheckMemoryBorder(ControlBlock::PFSP_SocketBuf p)
	{
		long d = long((octet*)p - (octet*)pControlBlock);
		return (d >= (long)sizeof(ControlBlock) && d < dwMemorySize);
	}

	// Convert the relative address in the control block to the address in process space
	// checked, so that ill-behaviored ULA may not cheat LLS to access data of others
	octet* GetSendPtr(const ControlBlock::PFSP_SocketBuf skb)
	{
		long offset;
		octet* p = pControlBlock->GetSendPtr(skb, offset);
		return (offset < (long)sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
	}
	octet* GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb)
	{
		long offset;
		octet* p = pControlBlock->GetRecvPtr(skb, offset);
		return (offset < (long)sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
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
		nearInfo.CopySinkInfTo(&pControlBlock->nearEndInfo);
	}
	void SetRemoteFiberID(ALFID_T id);

	char *PeerName() const { return (char *)pControlBlock->peerAddr.name; }

	int ResolveToIPv6(const char *);
	int ResolveToFSPoverIPv4(const char *, const char *);

	void Notify(FSP_NoticeCode c)
	{
#if ((TRACE & TRACE_PACKET) || (TRACE & TRACE_ULACALL))
		printf_s("\nSession #%u, raise soft interrupt %s(%d).\n", fidPair.source, noticeNames[c], c);
#endif
		_InterlockedExchange8((char*)&pControlBlock->singletonotice, c);
	}
	// Given
	//	FSP_NoticeCode		the code of the notification to alert DLL
	// Do
	//	Send the notification through the bi-direction message pipe to the ULA
	void SignalNMI(FSP_NoticeCode code)
	{
#if ((TRACE & TRACE_PACKET) || (TRACE & TRACE_ULACALL))
		printf_s("\nSession #%u, raise NMI %s(%d).\n", fidPair.source, noticeNames[code], code);
#endif
		if (rootULA != NULL)
			rootULA->SendNotificationTo(fidPair.source, code);
	}

	// Emulate 'Large receive offload'
	void NotifyDataReady(FSP_NoticeCode c = FSP_NotifyDataReady)
	{
		if (c == FSP_NotifyDataReady)
			_InterlockedCompareExchange8((char*)&pControlBlock->receiveNotice, c, 0);
		else
			_InterlockedExchange8((char*)&pControlBlock->receiveNotice, c);
	}
	// Emulate 'Large send offload'
	void NotifyBufferReady(FSP_NoticeCode c = FSP_NotifyBufferReady)
	{
		if (c == FSP_NotifyBufferReady)
			_InterlockedCompareExchange8((char*)&pControlBlock->sendAllowedNotice, c, 0);
		else
			_InterlockedExchange8((char*)&pControlBlock->sendAllowedNotice, c);
	}

	//
	int LOCALAPI AcceptSNACK(ControlBlock::seq_t, FSP_SelectiveNACK::GapDescriptor *, int);
	//
	void InitiateConnect();
	void DisposeOnReset();
	void Reject(const CommandRejectRequest&);
	void Reset();
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
	bool ValidateICC() { return ValidateICC(&headPacket->hdr, lenPktData, fidPair.peer, 0); }

	int ValidateSNACK(ControlBlock::seq_t&, FSP_SelectiveNACK*);
	// Register source IPv6 address of a validated received packet as the favorite returning IP address
	inline void ChangeRemoteValidatedIP();
	// Check whether previous KEEP_ALIVE is implicitly acknowledged on getting a validated packet
	inline void CheckAckToKeepAlive();

	bool ScheduleConnect(int);

	// On Feb.18, 2020 to prepare implementation of session hibernation/adjournment
	void Adjourn() { SetState(CLOSABLE); }

	// On Feb.17, 2019 Semantics of KeepAlive was fundamentally changed. Now it is the heartbeat of the local side
	// Send-pacing is a yet-to-implement feature of the rate-control based congestion control sublayer/manager
	void RestartKeepAlive() { ReplaceTimer(TIMER_SLICE_ms * 2); }

	// Command of ULA
	void ProcessCommand(const UCommandToLLS &);
	void Listen();
	void Connect();
	void Accept();
	void RefuseToMultiply(uint32_t);

	// Event triggered by the remote peer
	void OnInitConnectAck(FSP_Challenge*);
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
	void	RespondToMultiply();
};



// The translate look-aside buffer of the server's socket pool
class CSocketSrvTLB: CSRWLock
{
protected:
	friend class CSocketItemEx;

	CSocketItemEx listenerSlots[MAX_LISTENER_NUM];
	CSocketItemEx itemStorage[MAX_CONNECTION_NUM];

	// The translation look-aside buffer of the socket items
	CSocketItemEx *tlbSockets[MAX_CONNECTION_NUM];
	CSocketItemEx *tlbSocketsByRemote[MAX_CONNECTION_NUM];

	// The free list
	CSocketItemEx *headFreeSID, *tailFreeSID;

	// List of socket allocated on INIT_CONNECT. The list is meant to be auto-recycled
	CSocketItemEx* headLRUitem, * tailLRUitem;

	// The ULA forest, for this implementation we use bit field to manage ULA mapping
	// Number of ULA is hard limitted to bit field length of unsigned long
	SProcessRoot	forestULA[sizeof(unsigned long) * 8];
	unsigned long	forestFreeFlags;

public:
	CSocketSrvTLB();

	// To pre-allocate a socket to accept connect request with an arbitrary local ALFID
	ALFID_T			AllocItemReserve();
	// 
	CSocketItemEx * AllocItemCommit(SProcessRoot *, ALFID_T);

	// To allocate a proactive socket entry of random ALFID
	CSocketItemEx * AllocItem(SProcessRoot *);

	// To allocate a passive socket entry of the given ALFID
	CSocketItemEx * AllocItem(ALFID_T);

	// To add a new process tree with the given communication channel to ULA
	bool AddULAChannel(HPIPE_T);
	// To free all the socket entries of the same process tree
	bool FreeULAChannel(SProcessRoot *);

	void FreeItemDonotCareLock(CSocketItemEx *);
	void FreeItem(CSocketItemEx *p) { AcquireMutex(); FreeItemDonotCareLock(p); ReleaseMutex(); }

	CSocketItemEx * operator[](ALFID_T);

	bool PutToListenTLB(CSocketItemEx *, int);
	bool DetachFromListenTLB(CSocketItemEx *);

	bool PutToRemoteTLB(CMultiplyBacklogItem *);
	bool DetachFromRemoteTLB(CSocketItemEx *);

	// Given the remote host Id, the remote ALFID and the near end's parent id return the matching
	CMultiplyBacklogItem * FindByRemoteId(uint32_t, ALFID_T, ALFID_T);
};



// Let the compiler do loop-unrolling and embedding
static inline bool LOCALAPI IsInSubnetSet(uint64_t prefix, const TSubnets subnets)
{
	for (register int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		if (subnets[i] == prefix)
			return true;
	}
	return false;
}



// A singleton
class CLowerInterface: public CSocketSrvTLB
{
private:
	friend class CSocketItemEx;

	// limit socket set size to no greater than bit number of long integer
	static const int SD_SETSIZE = 31;
	int		interfaces[SD_SETSIZE];
	long	disableFlags;
	SOCKADDR_IN6 addresses[SD_SETSIZE];	// by default IPv6 addresses, but an entry might be a UDP over IPv4 address

#if defined(__WINDOWS__)
	HANDLE	thReceiver;	// the handle of the thread that listens
	HANDLE	hMobililty;	// handling mobility, the handle of the address-changed event
	fd_set	sdSet;		// set of socket descriptor for listening, one element for each physical interface
	SOCKET	sdSend;		// the socket descriptor, would at last be unbound for sending only

# define	LOOP_FOR_ENABLED_INTERFACE(stmt)	\
	for (register u_int i = 0;		\
		i < sdSet.fd_count;			\
		i++)						\
	{ if (!BitTest(&disableFlags, i)) stmt }

	int SetEffectiveALFID(PIN6_ADDR hintAddr, ALFID_T id1)
	{
		for (register u_int j = 0; j < sdSet.fd_count; j++)
		{
			if (*(uint64_t*)hintAddr == *(uint64_t*)&addresses[j].sin6_addr)
			{
				*(ALFID_T*)((octet *)hintAddr + 12) = id1;
				return interfaces[j];
			}
		}
		return -1;
	}

# ifndef OVER_UDP_IPv4
	DWORD	iRecvAddr;		// index into addresses
	inline	void DisableSocket(SOCKET);
#else
	void	DisableSocket(SOCKET) {}
# endif

#elif defined(__linux__) || defined(__CYGWIN__)
	const octet in6addr_linklocalprefix[8] = { 0xFE, 0x80, 00, 00, 00, 00, 00, 00 };
	const octet in6addr_6to4prefix[2] = { 0x20, 0x02 };
	const octet in6addr_teredoprefix[4] = { 0x20, 0x01, 0, 0};

	pthread_t	thReceiver;	// the handle of the thread that listens
	sigevent_t	hMobililty;	// handling mobility, the handle of the address-changed event
	int		sdSet[SD_SETSIZE];
	int		sdSend;		// the socket descriptor, would at last be unbound for sending only
	int		countInterfaces;	// Should be less than SD_SETSIZE

# define	LOOP_FOR_ENABLED_INTERFACE(stmt)	\
	for (register int i = 0;	\
		i < countInterfaces;	\
		i++)					\
	{ if ((disableFlags & (i << 1)) == 0) stmt }

	int SetEffectiveALFID(PIN6_ADDR hintAddr, ALFID_T id1)
	{
		for (register int j = 0; j < countInterfaces; j++)
		{
			if (*(uint64_t*)hintAddr == *(uint64_t*)&addresses[j].sin6_addr)
			{
				*(ALFID_T*)((octet *)hintAddr + 12) = id1;
				return interfaces[j];
			}
		}
		return -1;
	}
#endif

	int GetSubnets(TSubnets& subnets, const TSubnets& savedPathNearEnds)
	{
		memset(subnets, 0, sizeof(TSubnets));
		int j = 0;
		LOOP_FOR_ENABLED_INTERFACE
		({
			register uint64_t prefix = SOCKADDR_SUBNET(&addresses[i]);
			if (!IsInSubnetSet(prefix, savedPathNearEnds))
			{
				subnets[j++] = prefix;
				if (j >= MAX_PHY_INTERFACES)
					break;
			}
		})
		return j;
	}

	int		BindSendRecv(const SOCKADDR_IN *, int);
#if defined(_DEBUG) && defined(_WINDLL)
	friend void UnitTestSelectPath();
#endif

	// intermediate buffer to hold the fixed packet header, the optional header and the data
	PktBufferBlock	pktBuf[1];
	int32_t			countRecv;

	// storage location part of the particular receipt of a remote packet, respectively
	// remote-end address and near-end address
	SOCKADDR_INET	addrFrom;
	CtrlMsgHdr		nearInfo;

	// descriptor of what is received, i.e. the particular receipt of a remote packet
#if defined(__WINDOWS__)
	WSABUF			iovec[2];
	WSAMSG			mesgInfo;
	LPSOCKADDR		GetPacketSource() const { return LPSOCKADDR(mesgInfo.name); }
	ALFID_T			GetRemoteFiberID() const  { return SOCKADDR_ALFID(mesgInfo.name); }
	const CtrlMsgHdr* GetPacketNearInfo() const { return (CtrlMsgHdr*)mesgInfo.Control.buf; }
	void			CopySinkInfTo(CtrlMsgHdr& hdrInfo)
	{
		memcpy(&hdrInfo, mesgInfo.Control.buf, min(mesgInfo.Control.len, sizeof(hdrInfo)));
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	struct iovec  	iovec[2];
	struct msghdr	mesgInfo;
	const struct sockaddr* GetPacketSource() const { return (const struct sockaddr*)mesgInfo.msg_name; }
	ALFID_T			GetRemoteFiberID() const  { return SOCKADDR_ALFID(mesgInfo.msg_name); }
	const CtrlMsgHdr* GetPacketNearInfo() const { return (CtrlMsgHdr*)mesgInfo.msg_control; }
	void			CopySinkInfTo(CtrlMsgHdr& hdrInfo)
	{
		memcpy(&hdrInfo, mesgInfo.msg_control, min((size_t)mesgInfo.msg_controllen, sizeof(hdrInfo)));
	}
#endif

	template<typename THdr> THdr * FSP_OperationHeader() { return (THdr *) & pktBuf->hdr; }

	ALFID_T			GetLocalFiberID() const { return nearInfo.u.idALF; }
	ALFID_T			SetLocalFiberID(ALFID_T);

	CSocketItemEx	*MapSocket() { return (*this)[GetLocalFiberID()]; }

protected:
	// defined in remote.cpp
	int	 ProcessReceived();
	// processing individual type of packet header
	void OnGetInitConnect();
	void OnGetConnectRequest();

	// FSP over IPv6 and FSP over UDP/IPv4 have different implementation
	// defined in os-dependent source file
	int LOCALAPI EnumEffectiveAddresses(uint64_t *);
#if defined(__WINDOWS__)
	inline	int SetInterfaceOptions(SOCKET);
	static	DWORD WINAPI ProcessRemotePacket(LPVOID);
#elif defined(__linux__) || defined(__CYGWIN__)
	static	void * ProcessRemotePacket(void *);
#endif

public:
	~CLowerInterface() { Destroy(); }
	bool Initialize();
	void Destroy();

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
	inline void RemoveALFIDAddressPool(u32);		// ULONG: NET_IFINDEX
	// When an interface is removed/disabled, e.g. due to administrative shutdown at least one IPv6 address is unregistered
	inline void OnRemoveIPv6Address(u32, const IN6_ADDR &);	// ULONG: NET_IFINDEX
	// When an interface is enabled, at least one new IPv6 address is added. More detail needed here than OnRemove
	inline void OnAddingIPv6Address(u32, const SOCKADDR_IN6 &);	// ULONG: NET_IFINDEX
	inline void OnIPv6AddressMayAdded(u32, const SOCKADDR_IN6 &);	// ULONG: NET_IFINDEX
	//
	bool LOCALAPI SelectPath(PFSP_SINKINF, ALFID_T, u32, const SOCKADDR_INET *);
#else
	// No, in IPv4 network FSP does not support multi-path
	bool SelectPath(PFSP_SINKINF, ALFID_T, u32, const SOCKADDR_INET *) { return false; }
#endif

	static CLowerInterface Singleton;	// this class is effectively a namespace
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
