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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "../FSP.h"
#include "../FSP_Impl.h"


// Return the number of microseconds elapsed since Jan 1, 1970 (unix epoch time)
timestamp_t NowUTC();	// it seems that a global property 'Now' is not as clear as this function format

// random generatator is somehow dependent on implementation. hardware prefered.
void		rand_w32(uint32_t *p, int n);

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
	FSP_PKTINFO	u;

	bool IsIPv6() const { return (pktHdr.cmsg_level == IPPROTO_IPV6); }
};


#if _WIN32_WINNT < 0x0602
/**
 * Windows 8/Server 2012, with support of Visual Studio 2012, provide native support of htonll and ntohll
 */
inline UINT64 htonll(UINT64 u) 
{
	register UINT64 L = (UINT64)htonl(*(UINT32 *)&u) << 32;
	return L | htonl(*((UINT32 *)&u + 1));
}

inline UINT64 ntohll(UINT64 h)
{
	register UINT64 L = (UINT64)ntohl(*(UINT32 *)&h) << 32;
	return L | ntohl(*((UINT32 *)&h + 1));
}
/*
 *
 */
#endif


/**
 * Get the application layer thread ID from the (IPv6 raw-)socket address
 */
#define SOCKADDR_ALFID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idALF)
#define SOCKADDR_HOST_ID(s)  (((PFSP_IN6_ADDR) & ((PSOCKADDR_IN6)(s))->sin6_addr)->idHost)


// per-host connection mumber and listener limit defined in LLS:
#define MAX_CONNECTION_NUM	16	// 256	// must be some power value of 2
#define MAX_LISTENER_NUM	4
#define MAX_RETRANSMISSION	8
#define	MAX_BUFFER_MEMORY	70536	// 69KiB  // Implementation shall override this


// In Microsoft C++, the result of a modulus expression is always the same as the sign of the first operand.
// Provide a 'safe' code to implement a double-in-single-out circular queue...
struct RetransmitBacklog
{
	ControlBlock::seq_t q[MAX_RETRANSMISSION];
	ControlBlock::seq_t & operator[](int i)
	{
		i %= MAX_RETRANSMISSION;
		return q[i < 0 ? MAX_RETRANSMISSION + i : i];
	}
};


class CommandNewSessionSrv: CommandToLLS
{
	friend class ConnectRequestQueue;
	friend class CSocketItemEx;
	friend class CSocketSrvTLB;

	HANDLE	hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	HANDLE	hEvent;
	UINT	index;
	CSocketItemEx *pSocket;

	bool	isValid() const { return (hEvent != NULL); }

	// defined in command.cpp
	friend void LOCALAPI Listen(CommandNewSessionSrv &);
	friend void LOCALAPI Connect(CommandNewSessionSrv &);
	friend void LOCALAPI SyncSession(CommandNewSessionSrv &);

public:
	CommandNewSessionSrv(const CommandToLLS *);
	CommandNewSessionSrv() {}

	void DoConnect();
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
};




#include <pshpack1.h>

struct PktSignature
{
	PktSignature			*next;
	FSP_NormalPacketHeader	*pkt;
	ControlBlock::seq_t		pktSeqNo;
	int		lenData;
	size_t	size;
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



class CSocketItemEx: public CSocketItem
{
	PktSignature * volatile headPacket;
	PktSignature * volatile tailPacket;

	// multihome/mobility/resilence support (see also CInterface::EnumEffectiveAddresses):
	// MAX_PHY_INTERFACES is hard-coded to 4
	// sockAddrTo[0] is the most preferred address (care of address)
	// sockAddrTo[3] is the home-address
	// while sockAddr[1], sockAddr[2] are backup-up/load-balance address
	// the extra one is for saving temporary souce address
	SOCKADDR_INET	sockAddrTo[MAX_PHY_INTERFACES + 1];

protected:
	DWORD	idSrcProcess;
	HANDLE	hSrcMemory;
	//
	ALIGN(2)
	char	inUse;
	char	isReady;
	//
	char	isMilky;	// ULA cannot change it on the fly;
	char	mutex;
	bool	toUpdateTimer;
	//
	int32_t	keyLife;
	//
	CSocketItemEx *next;
	CSocketItemEx *prevSame;
	//
	RetransmitBacklog retransBackLog;
	int			retransHead;
	int			retransTail;

	UINT32		tRoundTrip_us;	// round trip time evaluated in microseconds
	UINT32		tKeepAlive_ms;	// keep-alive time-out limit in milliseconds
	HANDLE		timer;
	timestamp_t	tSessionBegin;
	timestamp_t tRecentSend;
	timestamp_t	tLastRecv;
	timestamp_t tEarliestSend;
	//
	struct CubicRate
	{
		uint32_t	ssthresh;
		uint32_t	cwnd;
		uint32_t	cwndFraction;
		uint32_t	cwndMax;
		uint32_t	cwndMin;
		uint32_t	originPoint;
		double		Wmax;
		double		K;
		uint64_t	dMin;
		timestamp_t T0;
		//
		inline void CheckTimeout(timestamp_t);
		inline void OnCongested();
		inline void Reset();
		inline float Update(timestamp_t);
		//
	}	congestCtrl;
	//
	struct
	{
		timestamp_t tMigrate;
		timestamp_t tKeepAlive;
	}	clockCheckPoint;

	FSP_Session_State lowState;

	void RestartKeepAlive() { ReplaceTimer(tKeepAlive_ms); }
	void StopKeepAlive() { ReplaceTimer(SCAVENGE_THRESHOLD_ms); }
	void RecalibrateKeepAlive(timestamp_t);

	bool IsPassive() const { return lowState == LISTENING; }
	void SetPassive() { lowState = LISTENING; }
	void SetState(FSP_Session_State s) 
	{
		pControlBlock->state = lowState = s;
		clockCheckPoint.tMigrate = NowUTC();
	}
	bool InState(FSP_Session_State s) { return lowState == s; }
	bool InStates(int n, ...);

	void LOCALAPI InstallSessionKey()
	{
#ifndef NDEBUG
		pControlBlock->_mac_ctx_protect_prolog[0]
			= pControlBlock->_mac_ctx_protect_prolog[1]
			= pControlBlock->_mac_ctx_protect_epilog[0]
			= pControlBlock->_mac_ctx_protect_epilog[1]
			= MAC_CTX_PROTECT_SIGN;
#endif
		vmac_set_key(pControlBlock->u.sessionKey, & pControlBlock->mac_ctx); 
	}

	// On got valid ICC automatically register source IP address as the favorite returning IP address
	bool ValidateICC(FSP_NormalPacketHeader *);
	bool ValidateICC() { return ValidateICC(headPacket->pkt); }
	bool LOCALAPI HandleMobileParam(PFSP_HeaderSignature);

	PktSignature *PushPacketBuffer(PktSignature *);
	FSP_NormalPacketHeader *PeekLockPacketBuffer();
	void PopUnlockPacketBuffer();
	void UnlockPacketBuffer() { mutex = SHARED_FREE; }

	int  LOCALAPI PlacePayload(ControlBlock::PFSP_SocketBuf);

	int	 SendPacket(register ULONG, ScatteredSendBuffers);
	bool EmitStart();
	bool LOCALAPI EmitWithICC(ControlBlock::PFSP_SocketBuf, ControlBlock::seq_t);

	void Extinguish();
	void TimeOut();

	static VOID NTAPI TimeOut(PVOID c, BOOLEAN) { ((CSocketItemEx *)c)->TimeOut(); } 
public:
	//
	bool MapControlBlock(const CommandNewSessionSrv &);
	void InitAssociation();
	bool IsInUse() { return inUse != 0; }
	void SetReady() { isReady = 1; }
	// It is assumed that the socket is set ready only after it is put into use
	// though inUse may be cleared before isReady is cleared
	bool TestAndLockReady();
	bool TestAndWaitReady();
	void SetEarliestSendTime() { tEarliestSend = tRecentSend; }
	int32_t GetCongestWindow() const { return congestCtrl.cwnd; }

	bool CheckMemoryBorder(ControlBlock::PFSP_SocketBuf p)
	{
		uint32_t d = uint32_t((BYTE *)p - (BYTE*)pControlBlock);
		return (d >= sizeof(ControlBlock) && d < dwMemorySize);
	}

	// Convert the relative address in the control block to the address in process space
	// checked, so that ill-behaviored ULA may not cheat LLS to access data of others
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		uint32_t offset;
		BYTE * p = pControlBlock->GetSendPtr(skb, offset);
		return (offset < sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
	}
	BYTE * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb) const
	{
		uint32_t offset;
		BYTE * p = pControlBlock->GetRecvPtr(skb, offset);
		return (offset < sizeof(ControlBlock) || offset >= dwMemorySize) ? NULL : p;
	}


	void LOCALAPI SetRemoteFiberID(ALFID_T id);
	char *PeerName() const { return (char *)pControlBlock->peerAddr.name; }
	int LOCALAPI ResolveToIPv6(const char *);
	int LOCALAPI ResolveToFSPoverIPv4(const char *, const char *);

	bool Notify(FSP_ServiceCode);
	void SignalEvent() { ::SetEvent(hEvent); }
	void SignalReturned() { pControlBlock->notices[0] = FSP_NotifyAccepting; SignalEvent(); }
	//
	int LOCALAPI RespondSNACK(ControlBlock::seq_t, const FSP_SelectiveNACK::GapDescriptor *, int);
	int LOCALAPI RespondSNACK(ControlBlock::seq_t, const PFSP_HeaderSignature);
	int LOCALAPI GenerateSNACK(BYTE *, ControlBlock::seq_t &);
	//
	void InitiateConnect();
	void CloseSocket();
	void CloseToNotify();
	void Disconnect();
	void DisposeOnReset();
	void OnMultiply();
	void OnResume();
	void OnResurrect();
	void HandleMemoryCorruption() {	Extinguish(); }
	void LOCALAPI AffirmConnect(const SConnectParam &, ALFID_T);

	bool IsValidSequence(ControlBlock::seq_t seq1) { return pControlBlock->IsValidSequence(seq1); }

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

	//
	template<FSPOperationCode c> int SendPacket()
	{
		// See also KeepAlive, AffirmConnect and OnAckFlush
		FSP_NormalPacketHeader hdr;
		pControlBlock->SetSequenceFlags(& hdr);
		hdr.hs.Set<FSP_NormalPacketHeader, c>();
		SetIntegrityCheckCode(hdr);
		return SendPacket(1, ScatteredSendBuffers(&hdr, sizeof(hdr)));
	}

	void LOCALAPI SetIntegrityCheckCodeP1(FSP_NormalPacketHeader *);
	void LOCALAPI SetIntegrityCheckCode(FSP_NormalPacketHeader & hdr)
	{
		hdr.integrity.id = fidPair;
		SetIntegrityCheckCodeP1(& hdr);
	}

	void EmitQ() { pControlBlock->EmitQ(this); }
	void PeerCommit();
	void KeepAlive();
	void ScheduleEmitQ();
	void ScheduleConnect(CommandNewSessionSrv *);
	// Send COMMIT or KEEP_ALIVE in heartbeat interval
	void SendHeartbeat();

	//
	bool AddTimer();
	bool RemoveTimer();
	void EarlierKeepAlive();
	bool LOCALAPI ReplaceTimer(uint32_t);
#ifdef TRACE
	int DumpTimerInfo(timestamp_t t1) const
	{
		return printf_s("\tRound Trip Time = %uus, Keep-alive period = %ums\n"
			"\tTime elapsed since earlist sent = %lluus\n"
			"\tNext relative keep-alive shot time=%lluus\n"
			"\tCongest origin-point time = %llx Congest Window = %d\n"
			, tRoundTrip_us
			, tKeepAlive_ms
			, t1 - tEarliestSend
			, clockCheckPoint.tKeepAlive - t1
			, congestCtrl.T0
			, congestCtrl.cwnd);
	}
#else
	int DumpTimerInfo(timestamp_t) const {}
#endif

	// Command of ULA
	void Shutdown();
	//
	// Connect and Send are special in the sense that it may take such a long time to complete that
	// if it gains exclusive access of the socket too many packets might be lost
	// when there are too many packets in the send queue
	void Connect();
	void Start();
	void UrgeCommit();
	void Resume();
	void SynConnect();
	void LOCALAPI Listen(CommandNewSessionSrv &);

	// Event triggered by the remote peer
	void LOCALAPI OnConnectRequestAck(FSP_AckConnectRequest &, int lenData);
	void OnGetPersist();	// PERSIST packet might be apparently out-of-band/out-of-order
	void OnGetPureData();	// PURE_DATA
	void OnGetCommit();		// COMMIT packet might be apparently out-of-band/out-of-order as well
	void OnAckFlush();		// ACK_FLUSH is always out-of-band
	void OnGetResume();		// RESUME may resume or resurrect
	void OnGetRelease();	// RELEASE may not carry payload
	void OnGetMultiply();	// MULTIPLY is treated out-of-band
	void OnGetKeepAlive();	// KEEP_ALIVE is usually out-of-band

	// A public accessible method of emitting the specified packet in the given LLS socket context
	static bool LOCALAPI Emit(CSocketItemEx *context, ControlBlock::PFSP_SocketBuf skb, ControlBlock::seq_t seq1)
	{
		return context->EmitWithICC(skb, seq1);
	}

	// any packet with full-weight integrity-check-code except aforementioned
	friend DWORD WINAPI HandleFullICC(LPVOID p);
	friend class CSocketSrvTLB;
	friend class CLowerInterface;
};

#include <poppack.h>


class CSocketSrvTLB
{
protected:
	CSocketItemEx listenerSlots[MAX_LISTENER_NUM];
	CSocketItemEx itemStorage[MAX_CONNECTION_NUM];
	CSocketItemEx *poolFiberID[MAX_CONNECTION_NUM];
	CSocketItemEx *headFreeSID, *tailFreeSID;
	char	mutex;
public:
	CSocketSrvTLB();

	CSocketItemEx * AllocItem(ALFID_T);
	CSocketItemEx * AllocItem();
	void FreeItem(CSocketItemEx *r);
	CSocketItemEx * operator[](ALFID_T);
	CSocketItemEx * operator[](const CommandNewSessionSrv &);
};


struct _CookieMaterial
{
	UINT32	salt;
	ALFID_T	idALF;
	ALFID_T	idListener;
};



// A singleton
class CLowerInterface: public CSocketSrvTLB
{
private:
	struct FSPoverUDP_Header: PairALFID, FSP_Header { };

	static CLowerInterface *pSingleInstance;

	HANDLE	thReceiver;	// the handle of the thread that listens
	HANDLE	hMobililty;	// handling mobility, the handle of the address-changed event
	SOCKET	sdSend;		// the socket descriptor, would at last be unbound for sending only
	SOCKET	sdRecv;		// the socket that received message most recently
	fd_set	sdSet;		// set of socket descriptor for listening, one element for each physical interface
	DWORD	interfaces[FD_SETSIZE];
	SOCKADDR_IN6 addresses[FD_SETSIZE];	// by default IPv6 addresses, but an entry might be a UDP over IPv4 address
	int		nAddress;
	char	mutex;		// Utilize _InterlockedCompareExchange8 to manage critical resource

	// intermediate buffer to hold the fixed packet header, the optional header and the data
	DWORD	countRecv;
	BYTE	*pktBuf;

	FSPoverUDP_Header &	HeaderFSPoverUDP() const { return *(FSPoverUDP_Header *)pktBuf; }
	FSP_Header &		HeaderFSP() const { return *(FSP_Header *)pktBuf; }
	template<typename THdr> THdr * FSP_OperationHeader()
	{
		return (THdr *)(nearInfo.IsIPv6() ? pktBuf : &pktBuf[sizeof(PairALFID)]);
	}

	// remote-end address and near-end address
	SOCKADDR_INET		addrFrom;
	CtrlMsgHdr			nearInfo;
	WSAMSG				sinkInfo;	// descriptor of what is received

	// For sending back a packet responding to a received packet only
	ALFID_T			GetLocalFiberID()
	{
		return nearInfo.IsIPv6() ? nearInfo.u.idALF : HeaderFSPoverUDP().peer;
	}
	ALFID_T			SetLocalFiberID(ALFID_T);

	// only valid for received message
	ALFID_T			GetRemoteFiberID() const
	{
		return nearInfo.IsIPv6() ? SOCKADDR_ALFID(sinkInfo.name) : HeaderFSPoverUDP().source;
	}

	// For FSP over IPv6 raw-socket, preconfigure IPv6 interfaces with ALFID pool
	inline void SetLocalApplicationLayerFiberID(ALFID_T);
	// For FSP over UDP/IPv4 bind the UDP-socket
	inline int BindInterface(SOCKET, PSOCKADDR_IN, int);
	CSocketItemEx *		MapSocket() { return (*this)[GetLocalFiberID()]; }

protected:
	static DWORD WINAPI ProcessRemotePacket(LPVOID lpParameter);

	int		bufTail;
	int		bufHead;
	ALIGN(8) BYTE bufferMemory[MAX_BUFFER_MEMORY];

	// OS-dependent
	BYTE	*BeginGetBuffer();
	void	LOCALAPI CommitGetBuffer(BYTE *, size_t);
	void	LOCALAPI FreeBuffer(BYTE *);

	// defined in remote.cpp
	// processing individual type of packet header
	void LOCALAPI OnGetInitConnect();
	void LOCALAPI OnInitConnectAck();
	void LOCALAPI OnGetConnectRequest();
	void LOCALAPI OnGetResetSignal();

	// define in mobile.cpp
	int LOCALAPI EnumEffectiveAddresses(UINT64 *);
	int	AcceptAndProcess();

	friend class CSocketItemEx;
public:
	static CLowerInterface * Singleton() { return pSingleInstance; }
	CLowerInterface();
	~CLowerInterface();

	// return the least possible overriden random fiber ID:
	ALFID_T LOCALAPI RandALFID(PIN6_ADDR);
	ALFID_T LOCALAPI RandALFID();
	int LOCALAPI SendBack(char *, int);
	// It might be necessary to send reset BEFORE a connection context is established
	void LOCALAPI SendPrematureReset(UINT32 = 0, CSocketItemEx * = NULL);

	inline void LearnAddresses();
	inline void PoolingALFIDs();
	inline void ProcessRemotePacket();
	//^ the thread entry function for processing packet sent from the remote-end peer
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
void LOCALAPI DumpCMsgHdr(CtrlMsgHdr &);
void LOCALAPI DumpHexical(BYTE *, int);
void LOCALAPI DumpNetworkUInt16(UINT16 *, int);


// defined in mobile.cpp
UINT64 LOCALAPI CalculateCookie(BYTE *, int, timestamp_t);

// defined in CubicRoot.c
extern "C" double CubicRoot(double);

// power(3, a) 	// less stringent than pow(3, a) ?
inline double CubicPower(double a) { return a * a * a; }
