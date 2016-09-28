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

#include "../FSP.h"
#include "../FSP_Impl.h"

#pragma intrinsic(_InterlockedCompareExchange, _InterlockedCompareExchange8)
#pragma intrinsic(_InterlockedExchange, _InterlockedExchange16, _InterlockedExchange8)
#pragma intrinsic(_InterlockedIncrement, _InterlockedOr, _InterlockedOr8)

#define MULTIPLY_BACKLOG_SIZE	8

 // For testability
#define TRACE_ADDRESS	1
#define TRACE_HEARTBEAT	2
#define TRACE_PACKET	4
#define TRACE_SLIDEWIN	8
#define TRACE_ULACALL	16
#define TRACE_OUTBAND	32	// Other than KEEP_ALIVE
// Return the number of microseconds elapsed since Jan 1, 1970 (unix epoch time)
timestamp_t NowUTC();	// it seems that a global property 'Now' is not as clear as this function format


// random generatator is somehow dependent on implementation. hardware prefered.
// might be optimized by loop unrolling
inline void	 rand_w32(uint32_t *p, int n) { for (register int i = 0; i < min(n, 32); i++) { rand_s(p + i); } }


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



// local header, does not send out
struct FSP_PreparedKEEP_ALIVE
{
	FSP_SelectiveNACK::GapDescriptor gaps[(MAX_BLOCK_SIZE - sizeof(FSP_SelectiveNACK)) / sizeof(FSP_SelectiveNACK::GapDescriptor)];
	FSP_SelectiveNACK sentinel;
	uint32_t		n;	// n >= 0, number of (gapWidth, dataLength) tuples
	uint32_t		GetSaltValue() const { return gaps[n].gapWidth; }	// it overlays on serialNo
};


#if _WIN32_WINNT < 0x0602
/**
 * Windows 8/Server 2012, with support of Visual Studio 2012, provide native support of htonll and ntohll
 */
inline uint64_t htonll(uint64_t u) 
{
	register uint64_t L = (uint64_t)htonl(*(uint32_t *)&u) << 32;
	return L | htonl(*((uint32_t *)&u + 1));
}

inline uint64_t ntohll(uint64_t h)
{
	register uint64_t L = (uint64_t)ntohl(*(uint32_t *)&h) << 32;
	return L | ntohl(*((uint32_t *)&h + 1));
}
/*
 *
 */
#endif


/**
 * Get the application layer thread ID from the (IPv6 raw-)socket address
 */
#define SOCKADDR_SUBNET(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->u.subnet)
#define SOCKADDR_ALFID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idALF)
#define SOCKADDR_HOSTID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idHost)


// per-host connection mumber and listener limit defined in LLS:
#define MAX_CONNECTION_NUM	16	// 256	// must be some power value of 2
#define MAX_LISTENER_NUM	4
#define MAX_RETRANSMISSION	8
#define	MAX_BUFFER_BLOCKS	64	// 65~66KiB, 64bit CPU consumes more // Implementation shall override this



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
	ALFID_T idParent;
public:
	CommandCloneSessionSrv(const CommandToLLS *p): CommandNewSessionSrv(p) { idParent = ((CommandCloneSession *)p)->idParent; }
};



// Implemented in os_....cpp because light-weight IPC mutual-locks are OS-dependent
class ConnectRequestQueue
{
	CommandNewSessionSrv q[CONNECT_BACKLOG_SIZE];
	int	head;
	int tail;
	char mayFull;
	volatile char mutex;
public:
	// ConnectRequestQueue() { head = tail = 0; mayFull = 0; mutex = SHARED_FREE; }
	int Push(const CommandNewSessionSrv *);
	int Remove(int);
	// Connect to remote end might be time-consuming
	void WaitSetMutex() { while(_InterlockedCompareExchange8(& mutex, 1, 0)) Sleep(0); }
	void SetMutexFree() { _InterlockedExchange8(& mutex, 0); }
};



#include <pshpack1.h>

// we prefer productivity over 'cleverness': read buffer block itself is of fixed size
struct PktSignature
{
	ALIGN(8)
	struct PktBufferBlock *next;
	ALIGN(8)
	int32_t	lenData;
	ControlBlock::seq_t	pktSeqNo;	// in host byte-order
};



struct PktBufferBlock: PktSignature
{
	PairALFID	idPair;
	FSP_NormalPacketHeader hdr;
	BYTE	payload[MAX_BLOCK_SIZE];
	//
	FSP_NormalPacketHeader *GetHeaderFSP() { return &(this->hdr); }
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



// Context management of 
struct ICC_Context
{
#ifndef NDEBUG
#define MAC_CTX_PROTECT_SIGN	0xA5A5C3C3A5C3A5C3ULL
	ALIGN(MAC_ALIGNMENT)
	uint64_t	_mac_ctx_protect_prolog[2];
#endif
	union
	{
		uint64_t	precomputedICC[2];	// [0] is for output/send, [1] is for input/receive
		ALIGN(MAC_ALIGNMENT)
		GCM_AES_CTX	gcm_aes;
	} curr, prev;

#ifndef NDEBUG
	uint64_t	_mac_ctx_protect_epilog[2];
#endif
	// Only life of current ICC key is cared about 
	int32_t		keyLife;
	// Previous key is applied for CRC only
	bool		savedCRC;
	// only when there is no packet left applied with previous key may current key changed  
	// the sequence number of the first packet to be sent or received with current key, respectively
	ControlBlock::seq_t	snFirstSendWithCurrKey;
	ControlBlock::seq_t	snFirstRecvWithCurrKey;
};



class CSocketItemEx: public CSocketItem
{
	friend class CLowerInterface;
	friend class CSocketSrvTLB;

	// any packet with full-weight integrity-check-code except aforementioned
	friend DWORD WINAPI HandleFullICC(LPVOID);
	friend void Multiply(CommandCloneSessionSrv &);

	HANDLE	hSrcMemory;
	DWORD	idSrcProcess;
	//
protected:
	ICC_Context	contextOfICC;
	uint8_t	cipherText[MAX_BLOCK_SIZE];
	//
	PktBufferBlock * volatile headPacket;
	PktBufferBlock * volatile tailPacket;

	// multihome/mobility/resilence support (see also CInterface::EnumEffectiveAddresses):
	// MAX_PHY_INTERFACES is hard-coded to 4
	// sockAddrTo[0] is the most preferred address (care of address)
	// sockAddrTo[3] is the home-address
	// while sockAddr[1], sockAddr[2] are backup-up/load-balance address
	// the extra one is for saving temporary souce address
	SOCKADDR_INET	sockAddrTo[MAX_PHY_INTERFACES + 1];

	char	locked;	// emulate spinlock linux-kernel
	char	inUse;
	char	shouldAppendCommit;
	FSP_Session_State lowState;

	ALFID_T		idParent;

	// chainlist on the collision entry of the remote ALFID TLB
	CSocketItemEx * prevRemote;

	// chainlist on the collision entry of the near ALFID TLB
	CSocketItemEx * next;
	CSocketItemEx * prevSame;

	uint32_t	tRoundTrip_us;	// round trip time evaluated in microseconds
	uint32_t	tKeepAlive_ms;	// keep-alive time-out limit in milliseconds
	HANDLE		timer;			// the repeating timer
	HANDLE		resendTimer;	// retransmission timer
	HANDLE		lazyAckTimer;	// an one-shot timer, typically for sending snack lazily
	timestamp_t	tSessionBegin;
	timestamp_t	tLastRecv;
	timestamp_t tRecentSend;
	timestamp_t tMigrate;

	uint32_t	nextOOBSN;	// host byte order for near end. if it overflow the session MUST be terminated
	uint32_t	lastOOBSN;	// host byte order, the serial number of peer's last out-of-band packet

	int8_t		lazyAckTimeoutRetryCount;
	int8_t		resendTimeoutRetryCount;
	//
	bool AddLazyAckTimer();
	bool AddResendTimer(uint32_t);
	bool AddTimer();
	void RemoveTimers();
	bool LOCALAPI ReplaceTimer(uint32_t);

	void RestartKeepAlive() { ReplaceTimer(KEEP_ALIVE_TIMEOUT_ms); }
	void StopKeepAlive() { ReplaceTimer(SCAVENGE_THRESHOLD_ms); }
	void CalibrateRTT()
	{ 
		tLastRecv = NowUTC();
		// The timer was already started for transient state management when Accept(), Multiply() or sending MULTIPLY
		tRoundTrip_us = (uint32_t)min(UINT32_MAX, tLastRecv - tRecentSend);
	}
	// Note that the raw round trip time includes the lazy-acknowledgement delay
	// We hard-coded the lazy-acknowledgement delay as one RTT
	void RecalibrateRTT(uint64_t rtt64_us)
	{
		if(rtt64_us > LAZY_ACK_DELAY_MIN_ms * 2000)
			tRoundTrip_us = uint32_t((min(rtt64_us >> 1, UINT32_MAX) + tRoundTrip_us + 1) >> 1);
		else if(rtt64_us > LAZY_ACK_DELAY_MIN_ms * 1000)
			tRoundTrip_us = uint32_t((rtt64_us + tRoundTrip_us + 1) >> 1);
		else
			tRoundTrip_us = uint32_t((LAZY_ACK_DELAY_MIN_ms * 1000 + tRoundTrip_us + 1) >> 1);
	}

	bool IsPassive() const { return lowState == LISTENING; }
	void SetPassive() { lowState = LISTENING; }
	void SetState(FSP_Session_State s) 
	{
		_InterlockedExchange8((char *) & pControlBlock->state, s);
		lowState = s;
		tMigrate = NowUTC();
	}
	bool InState(FSP_Session_State s) { return lowState == s; }
	bool InStates(int n, ...);

	bool HandlePeerSubnets(PFSP_HeaderSignature);

	PktBufferBlock *PushPacketBuffer(PktBufferBlock *);
	FSP_NormalPacketHeader *PeekLockPacketBuffer();
	void PopUnlockPacketBuffer();

	// return -EEXIST if overriden, -EFAULT if memory error, or payload effectively placed
	int	PlacePayload();

	int	 SendPacket(register ULONG, ScatteredSendBuffers);
	bool EmitStart();
	void EmitStartAndSlide()
	{
		ControlBlock::seq_t k = pControlBlock->sendWindowFirstSN;
		if(EmitStart() 
		&& _InterlockedCompareExchange((LONG *) & pControlBlock->sendWindowNextSN, k + 1, k) == k)
		{
			++pControlBlock->sendWindowNextPos;
			pControlBlock->RoundSendWindowNextPos();
		}
	}
	bool SendAckFlush();
	bool SendKeepAlive();
	int	 EmitWithICC(ControlBlock::PFSP_SocketBuf, ControlBlock::seq_t);

	void Destroy();	// override that of the base class
	void DoResend();
	void KeepAlive();
	void LazilySendSNACK();

	static VOID NTAPI DoResend(PVOID c, BOOLEAN) { ((CSocketItemEx *)c)->DoResend(); }
	static VOID NTAPI KeepAlive(PVOID c, BOOLEAN) { ((CSocketItemEx *)c)->KeepAlive(); }
	static VOID NTAPI LazilySendSNACK(PVOID c, BOOLEAN) { ((CSocketItemEx *)c)->LazilySendSNACK(); }

	//
public:
	//
	bool MapControlBlock(const CommandNewSessionSrv &);
	void InitAssociation();

	bool WaitUseMutex();
#ifdef NDEBUG
	void SetMutexFree() { _InterlockedExchange8(& locked, 0); }
#else
	void SetMutexFree();
#endif
	bool IsInUse() { return (_InterlockedOr8(& inUse, 0) != 0); }
	void SetInUse() { _InterlockedExchange8(& inUse, 1); }

	void InstallEphemeralKey();
	void InstallSessionKey();
	void DeriveNextKey();

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
	int LOCALAPI RespondToSNACK(ControlBlock::seq_t, FSP_SelectiveNACK::GapDescriptor *, int);
	int32_t LOCALAPI GenerateSNACK(FSP_PreparedKEEP_ALIVE &, ControlBlock::seq_t &, int);
	//
	void InitiateConnect();
	void RejectOrReset();
	void DisposeOnReset();
	void Recycle();
	void InitiateMultiply(CSocketItemEx *);
	bool FinalizeMultiply();

	void HandleMemoryCorruption() {	Destroy(); }
	void AffirmConnect(const SConnectParam &, ALFID_T);

	// Compare the given sequence with the left and right edge of the receive window
	// Return 0 if it falls in the window (not out of window),
	// or the offset if it is out of window, negative if on the left, positive if on the right
	// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
	int32_t IsOutOfWindow(ControlBlock::seq_t seq1) const
	{
		register int32_t d = int32_t(seq1 - pControlBlock->recvWindowFirstSN);
		return ((0 <= d) && (d < pControlBlock->recvBufferBlockN)) ? 0 : d;
	}
	// With replay-attack suppression. It could be true while still be out of window
	bool ICCSeqValid();

	// Given
	//	ControlBlock::seq_t	The sequence number of the packet that mostly expected by the remote end
	//	unsigned int		The advertised size of the receive window, start from aforementioned most expected packet
	// Return
	//	Whether the given sequence number is legitimate
	// Remark
	//	If the given sequence number is legitimate, send window size of the near end is adjusted
	bool LOCALAPI ResizeSendWindow(ControlBlock::seq_t seq1, unsigned int adRecvWS)
	{
		return pControlBlock->ResizeSendWindow(seq1, adRecvWS);
	}

	template<FSPOperationCode c> int SendPacket()
	{
		// See also SendKeepAlive, AffirmConnect and SendAckFlush
		FSP_NormalPacketHeader hdr;
		pControlBlock->SetSequenceFlags(& hdr);
		hdr.hs.Set<FSP_NormalPacketHeader, c>();
		SetIntegrityCheckCode(& hdr);
		return SendPacket(1, ScatteredSendBuffers(&hdr, sizeof(hdr)));
	}

	// Given the fixed header, the content (plaintext), the length of the context and the xor-value of salt
	void * LOCALAPI SetIntegrityCheckCode(FSP_NormalPacketHeader *, void * = NULL, int32_t = 0, uint32_t = 0);
	// Solid input,  the payload, if any, is copied later
	bool LOCALAPI ValidateICC(FSP_NormalPacketHeader *, int32_t, ALFID_T, uint32_t);
	bool ValidateICC() { return ValidateICC(headPacket->GetHeaderFSP(), headPacket->lenData, fidPair.peer, 0); }

	bool LOCALAPI ValidateSNACK(ControlBlock::seq_t &, FSP_SelectiveNACK::GapDescriptor * &, int &);
	// On near end's IPv6 address changed automatically send an out-of-sync KEEP_ALIVE
	void OnLocalAddressChanged();
	// On got valid ICC automatically register source IP address as the favorite returning IP address
	inline void ChangeRemoteValidatedIP();

	void EmitQ();
	void ScheduleEmitQ();
	void ScheduleConnect(CommandNewSessionSrv *);

	// Command of ULA
	// Connect and Send are special in the sense that it may take such a long time to complete that
	// if it gains exclusive access of the socket too many packets might be lost
	// when there are too many packets in the send queue
	void ProcessCommand(FSP_ServiceCode);
	void Connect();
	void Accept();
	void Start();
	void UrgeCommit();
	void Listen(CommandNewSessionSrv &);

	// Event triggered by the remote peer
	void OnConnectRequestAck(FSP_AckConnectRequest &, int lenData);
	void OnGetPersist();	// PERSIST packet might be apparently out-of-band as it might be payloadless
	void OnGetPureData();	// PURE_DATA
	void OnGetEOT();		// Used to be a standalone COMMIT packet, now the EoT flag
	void OnAckFlush();		// ACK_FLUSH is always out-of-band
	void OnGetRelease();	// RELEASE may not carry payload
	void OnGetMultiply();	// MULTIPLY is in-band at the initiative side, out-of-band at the passive side
	void OnGetKeepAlive();	// KEEP_ALIVE is always out-of-band
};

#include <poppack.h>


// The backlog of connection multiplication, for buffering the payload piggybacked by the MULTIPLY packet
// By reuse
//	cipherText field of CSocketItemEx
//	tSessionBegin => first two bytes: lenData, last byte: EOM
//	contextOfICC.snFirstRecvWithCurrKey => initialSN
//	SOCKADDR_ALFID and SOCKADDR_HOSTID of sockAddrTo: idRemote and remoteHostID
class CMultiplyBacklogItem: public CSocketItemEx
{
	friend	class CSocketSrvTLB;
public:
	void	CopyInPlainText(const uint8_t *buf, int n) { *((uint16_t *)& tSessionBegin) = (uint16_t)n; if(n > 0) memcpy(cipherText, buf, n); }
	int		CopyOutPlainText(uint8_t *buf) { int n = *((uint16_t *)& tSessionBegin); if(n > 0) memcpy(buf, cipherText, n); return n; }
	bool	IsEndOfMessage() const { return *((uint8_t *)& tSessionBegin + 3) != 0; }
	void	SetEndOfMessage(bool value) { *((uint8_t *)& tSessionBegin + 3) = (uint8_t)value; }
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

public:
	CSocketSrvTLB();
	void InitMutex() { InitializeSRWLock(& rtSRWLock); } 
#ifdef NDEBUG
	void AcquireMutex() { AcquireSRWLockExclusive(& rtSRWLock); }
#else
	void AcquireMutex();
#endif
	void ReleaseMutex() { ReleaseSRWLockExclusive(& rtSRWLock); }

	CSocketItemEx * AllocItem(const CommandNewSessionSrv &);
	CSocketItemEx * AllocItem(ALFID_T);
	CSocketItemEx * AllocItem();
	void FreeItem(CSocketItemEx *r);

	CSocketItemEx * operator[](ALFID_T);

	bool PutToRemoteTLB(CMultiplyBacklogItem *);
	// Given the remote host Id, the remote ALFID and the near end's parent id return the matching
	CMultiplyBacklogItem * FindByRemoteId(uint32_t, ALFID_T, ALFID_T);
};



// Dual stack support: FSP over UDP/IPv4 and FSP over IPv6 require buffer block of different size
struct CPacketBuffers
{
	ALIGN(8) PktBufferBlock bufferMemory[MAX_BUFFER_BLOCKS];
	PktBufferBlock *freeBufferHead;

	PktBufferBlock	*GetBuffer()
	{
		register PktBufferBlock *p = freeBufferHead;
		if(p == NULL)
			return NULL;
		//
		freeBufferHead = p->next;
		return p;
	}

	void	FreeBuffer(PktBufferBlock *p)
	{
		p->next = freeBufferHead;
		freeBufferHead = p;
	}

	// OS-dependent
	CPacketBuffers();
};



// A singleton
class CLowerInterface: public CSocketSrvTLB, protected CPacketBuffers
{
private:
	friend class CSocketItemEx;

	static const u_int SD_SETSIZE = 32;	// hard-coded, bit number of LONG; assume FD_SETSIZE >= 32
	static CLowerInterface *pSingleInstance;

	HANDLE	thReceiver;	// the handle of the thread that listens
	HANDLE	hMobililty;	// handling mobility, the handle of the address-changed event

	SOCKET	sdSend;		// the socket descriptor, would at last be unbound for sending only
	fd_set	sdSet;		// set of socket descriptor for listening, one element for each physical interface
	DWORD	interfaces[FD_SETSIZE];
	SOCKADDR_IN6 addresses[FD_SETSIZE];	// by default IPv6 addresses, but an entry might be a UDP over IPv4 address
#if defined(_DEBUG) && defined(_WINDLL)
	friend void UnitTestSelectPath();
#endif

#ifndef OVER_UDP_IPv4
	ULONG	iRecvAddr;		// index into addresses
	LONG	disableFlags;	// harf of the default FD_SETSIZE
	inline	void DisableSocket(SOCKET);
#else
	// For FSP over UDP/IPv4 bind the UDP-socket
	void DisableSocket(SOCKET) {}
	int BindSendRecv(const SOCKADDR_IN *, int);
#endif

	// intermediate buffer to hold the fixed packet header, the optional header and the data
	DWORD	countRecv;
	PktBufferBlock *pktBuf;

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
	void LOCALAPI OnGetResetSignal();

	// defined in mobile.cpp
	int LOCALAPI EnumEffectiveAddresses(uint64_t *);
	int	AcceptAndProcess(SOCKET);

	// defined in os-dependent source file
	inline int SetInterfaceOptions(SOCKET);
	static DWORD WINAPI ProcessRemotePacket(LPVOID);

public:
	CLowerInterface();
	~CLowerInterface();

	// return the least possible overriden random fiber ID:
	ALFID_T LOCALAPI RandALFID(PIN6_ADDR);
	ALFID_T LOCALAPI RandALFID();
	int LOCALAPI SendBack(char *, int);
	// It might be necessary to send reset BEFORE a connection context is established
	void LOCALAPI SendPrematureReset(uint32_t = 0, CSocketItemEx * = NULL);

	inline bool IsPrefixDuplicated(int, PIN6_ADDR);
	inline void LearnAddresses();
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

	static CLowerInterface * Singleton() { return pSingleInstance; }
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


// OS-specific thread-pool related, for Windows LPTHREAD_START_ROUTINE function
DWORD WINAPI HandleConnect(LPVOID);
DWORD WINAPI HandleSendQ(LPVOID);
DWORD WINAPI HandleFullICC(LPVOID);

// defined in socket.cpp
void LOCALAPI DumpHexical(BYTE *, int);
void LOCALAPI DumpNetworkUInt16(uint16_t *, int);


// defined in mobile.cpp
uint64_t LOCALAPI CalculateCookie(BYTE *, int, timestamp_t);

// defined in CRC64.c
extern "C" uint64_t CalculateCRC64(register uint64_t, register uint8_t *, size_t);

// power(3, a) 	// less stringent than pow(3, a) ?
inline double CubicPower(double a) { return a * a * a; }
