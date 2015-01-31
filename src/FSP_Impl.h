#ifndef _FSP_IMPLEMENTATION_H
#define _FSP_IMPLEMENTATION_H

/*
 * Flexible Session Protocol, implementation-dependent definitions
 * shared between the service process and the upper layer application procoess
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

//// Comment the whole block of the three lines to disable forcing FSP over IPv6
//#ifdef OVER_UDP_IPv4
//#undef OVER_UDP_IPv4
//#endif

#ifdef _MSC_VER
#include <ws2tcpip.h>
#include <mswsock.h>
#else
#include <netinet/in.h>
#include <netinet/ip6.h>
#endif

#include <limits.h>
#include <errno.h>

#include "vmac.h"
#define	MAC_ALIGNMENT 16

// X86 intrinsic, support by ARM
// TODO: gcc equivalence?
#include <intrin.h>
#pragma intrinsic(memset, memcpy)

#if (_MSC_VER >= 1600)
#pragma intrinsic(_InterlockedCompareExchange8, _InterlockedExchange8)
#else
FORCEINLINE char _InterlockedCompareExchange8(volatile char *dest, char newval, char oldval)
{
    __asm
    {
        mov     al, oldval
        mov     edx,dest
        mov     cl,	newval
        lock cmpxchg byte ptr [edx], cl
    }
}

FORCEINLINE char _InterlockedExchange8(volatile char * a, char b)
{
	__asm mov	ecx, a;
	__asm mov	AL, b;
	__asm xchg	AL, byte ptr[ecx];
}
#endif


/**
 * For testability
 */
#ifdef TRACE
# include <stdio.h>
# define TRACE_HERE(s) printf("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", __FILE__, __LINE__, __FUNCDNAME__, s)
# define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, "ERROR REPORT")
# define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, (s1))
void TraceLastError(char * fileName, int lineNo, char *funcName, char *s1);
#else
# define TRACE_HERE
# define REPORT_ERROR_ON_TRACE()
# define REPORT_ERRMSG_ON_TRACE(s) (s)
#endif

// Reflexing string representation of operation code, for debug purpose
class CStringizeOpCode
{
	static const char * names[LARGEST_OP_CODE + 1];
public:
	const char * operator[](int);
};


// Reflexing string representation of FSP_Session_State and FSP_ServiceCode, for debug purpose
class CStringizeState
{
	static const char * names[LARGEST_FSP_STATE + 1];
public:
	const char * operator[](int);
};

class CStringizeNotice
{
	static const char * names[LARGEST_FSP_NOTICE + 1];
public:
	const char * operator[](int);
};

extern CStringizeOpCode opCodeStrings;

extern CStringizeState stateNames;

extern CStringizeNotice noticeNames;

/**
 * IPC
 */
#define SERVICE_MAILSLOT_NAME "\\\\.\\mailslot\\flexible\\session\\protocol"
#define MAX_CTRLBUF_LEN		424	// maximum message passing structure/mailslot size
#define REVERSE_EVENT_NAME	"Global\\FlexibleSessionProtocolEvent"
#define MAX_NAME_LENGTH		64	// considerably less than MAX_PATH

#ifdef _DEBUG
#define	CONNECT_BACKLOG_SIZE	2
#else
#define	CONNECT_BACKLOG_SIZE	512
#endif

// value space of mutex defined by this application
#define SHARED_BUSY 1
#define SHARED_FREE 0

/**
 * Implementation defined timeout
 */
#define MAXIMUM_SESSION_LIFE_ms		43200000	// 12 hours

#ifdef TRACE
# define KEEP_ALIVE_TIMEOUT_MIN_us	1000000	// 1 second
# define SCAVENGE_THRESHOLD_ms		180000	// 3 minutes
#else
# define KEEP_ALIVE_TIMEOUT_MIN_us	500		// 0.5 millisecond
# define SCAVENGE_THRESHOLD_ms		1800000	// 30 minutes
#endif

/**
 * Implemented system limit
 */
#ifndef OVER_UDP_IPv4
// IPv6 requires that every link in the internet have an MTU of 1280 octets or greater. 
# define MAX_BLOCK_SIZE		1024
# define MAX_LLS_BLOCK_SIZE	(MAX_BLOCK_SIZE + sizeof(FSP_Header))		// 1048
#else
# define MAX_BLOCK_SIZE		512
# define MAX_LLS_BLOCK_SIZE	(MAX_BLOCK_SIZE + sizeof(FSP_Header) + 8)	// 544
#endif

#define MAX_PHY_INTERFACES	4	// maximum number of physical interfaces that might be multihomed
#define MIN_QUEUED_INTR		2	// minimum number of queued (soft) interrupt, must be some power value of 2
#define FSP_BACKLOG_SIZE	4	// shall be some power of 2
#define FSP_MAX_NUM_NOTICE	8	// shall be some multiple of 8
#define	MIN_RESERVED_BUF	(MAX_BLOCK_SIZE * 2)

#define LOCALAPI __fastcall

// This implement's congestion control parameters
#define CONGEST_CONTROL_C	0.4
#define CONGEST_CONTROL_BETA 0.2

/**
 * platform-dependent fundamental utility functions
 */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

/**
 * Parameter data-structure and Session Control Block data-structure
 */
#include <pshpack1.h>

struct $FSP_HeaderSignature: FSP_HeaderSignature
{
	template<typename THdr, BYTE opCode1> void Set()
	{
		version = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = uint16BE(sizeof(THdr));
	}
	template<BYTE opCode1> void Set(int len1)
	{
		version = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = uint16BE(len1);
	}
};


// position start from 0, the rightmost one
enum FSP_FlagPosition: UINT8
{
	ToBeContinued = 0,
	Compressed = 1,
	Encrypted = 2,
	Unauthenticated = 3,
	FirstInFirstDrop = 4,
	ExplicitCongestion = 7
};


struct FSP_NormalPacketHeader
{
	UINT32 sequenceNo;
	UINT32 expectedSN;
	union
	{
		UINT64		code;
		PairALFID	id;
	} integrity;
	//
	UINT8	flags_ws[4];
/**
	For IPv4, maximum buffer size = 512 * 65536 = 32MB
	For IPv6 normal packet, maximum buffer size = 1024 * 65536 = 64MB
	However, for IPv6 jumbo packet it can easily reach 512MB or even more
 */
	$FSP_HeaderSignature hs;

	// A bruteforce but safe method of set or retrieve recvWS, with byte order translation
	int32_t GetRecvWS() const { return ((int32_t)flags_ws[0] << 16) + (flags_ws[1] << 8) + flags_ws[2]; }
	void SetRecvWS(int32_t v) { flags_ws[0] = (UINT8)(v >> 16); flags_ws[1] = (UINT8)(v >> 8); flags_ws[2] = (UINT8)v; }
	void ClearFlags() { flags_ws[3] = 0; }
	template<FSP_FlagPosition pos> void SetFlag() { flags_ws[3] |= (1 << pos); }
	template<FSP_FlagPosition pos> void ClearFlag() { flags_ws[3] &= ~(1 << pos); }
	template<FSP_FlagPosition pos> int GetFlag() const { return flags_ws[3] & (1 << pos); }
};


struct FSP_InitiateRequest
{
	timestamp_t timeStamp;
	UINT64		initCheckCode;
	UINT32		salt;
	$FSP_HeaderSignature hs;
};


// acknowledgement to the connect bootstrap request, works as a challenge against the initiator
// to be followed by the certificate optional header
struct FSP_Challenge
{
	UINT64		cookie;
	UINT64		initCheckCode;
	int32_t		timeDelta;
	$FSP_HeaderSignature hs;
};



// FSP_ConnectParam assists in renegotiating session key in a PERSIST packet
// while specifies the parent connection in a MULTIPLY or CONNECT_REQUEST packet
// MOBILE_PARAM used to be CONNECT_PARAM and it is perfect OK to treat the latter as the canonical alias of the former
struct FSP_ConnectParam
{
	uint64_t	subnets[MAX_PHY_INTERFACES];
	ALFID_T		listenerID;
	//
	// host id of the application layer fiber, alias of listenerID
	__declspec(property(get=getHostID, put=setHostID))
	UINT32	idHostALF;
	UINT32	getHostID() const { return listenerID; }
	void	setHostID(UINT32 value) { listenerID = value; }
	//
	$FSP_HeaderSignature hs;
};



struct FSP_ConnectRequest: FSP_InitiateRequest
{
	uint32_t	initialSN;		// initial sequence number, I->R, for this session segment
	int32_t		timeDelta;
	uint64_t	cookie;
	//
	FSP_ConnectParam params;
};



struct FSP_AckConnectRequest: FSP_NormalPacketHeader
{
	FSP_ConnectParam params;
};



struct FSP_SelectiveNACK
{
	struct GapDescriptor
	{
		UINT16	gapWidth;	// in packets
		UINT16	dataLength;	// in packets
	};
	uint32_t	lastGap;	// assert(sizeof(GapDescriptor) == sizeof(lastGap));
	$FSP_HeaderSignature hs;
};



struct FSP_RejectConnect
{
	union
	{
		timestamp_t timeStamp;
		struct
		{
			UINT32 initial;
			UINT32 expected;
		} sn;
	} u;
	//
	union
	{
		UINT64 integrityCode;
		UINT64 cookie;
		UINT64 initCheckCode;
		PairALFID fidPair;
	} u2;
	//
	UINT32 reasons;	// bit field(?)
	$FSP_HeaderSignature hs;
};



/**
 * Command to lower layer service
 * Try to make a 32-bit process calling the 64-bit FSP lower-level service possible
 * by exploiting POST-FIX(!) ALIGN(8)
 * Feasible in a little-endian CPU, provided that the structure is pre-zeroed
 */
struct CommandToLLS
{
	DWORD			idProcess;
	ALIGN(8)
	ALFID_T		fiberID;
	FSP_ServiceCode	opCode;	// operation code

	CommandToLLS() { memset(this, 0, sizeof(CommandToLLS)); }
};


struct CommandNewSession: CommandToLLS
{
	HANDLE			hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
	ALIGN(8)
	DWORD			dwMemorySize;	// size of the shared memory, in the mapped view
	char			szEventName[MAX_NAME_LENGTH];	// name of the callback event

	CommandNewSession() { memset(this, 0, sizeof(CommandNewSession)); }
};



struct FSP_PKTINFO_EX : FSP_PKTINFO
{
	int32_t	cmsg_level;
	//
	void InitUDPoverIPv4(ULONG if1)
	{
		memset(this, 0, sizeof(FSP_PKTINFO));		// inaddr_any
		ipi_ifindex = if1;
		cmsg_level = IPPROTO_IP;	/* originating protocol */
	}
	//
	void InitNativeIPv6(ULONG if1)
	{
		memset(this, 0, sizeof(FSP_PKTINFO));		// in6addr_any;
		ipi6_ifindex = if1;
		cmsg_level = IPPROTO_IPV6;	/* originating protocol */
	}
	//
	bool IsIPv6() const { return (cmsg_level == IPPROTO_IPV6); }
};



struct SConnectParam	// MUST be aligned on 64-bit words!
{
	UINT64		initCheckCode;
	UINT64		cookie;
	//
	UINT32		salt;
	UINT32		initialSN;	// the initial sequence number of the packet to send
	//
	ALFID_T		idRemote;	// ID of the listener or the new forked, depending on context
	UINT32		remoteHostID;
	//
	int32_t		timeDelta;		// delay of peer to peer timestamp, delta of clock 
	int32_t		reserved0;
	timestamp_t timeStamp;
	//
	UINT64		allowedPrefixes[MAX_PHY_INTERFACES];
};	// totally 56 bytes, 448 bits



struct BackLogItem: SConnectParam
{
	FSP_PKTINFO	acceptAddr;	// including the interface number AND the local fiber ID
	ALFID_T		idParent;
	//^ 0 if it is the 'root' acceptor, otherwise the local fiber ID of the cloned connection
	UINT32		expectedSN;	// the expected sequence number of the packet to receive by order
};



// 
template<typename TLogItem> class TSingleProviderMultipleConsumerQ
{
	volatile char		mutex;
	ALIGN(4)
	volatile LONG		nProvider;
	ALIGN(8)
	int32_t				capacity;
	volatile int32_t	headQ;
	volatile int32_t	tailQ;
	volatile int32_t	count;
	//
	ALIGN(8)
	TLogItem			q[MIN_QUEUED_INTR];
	//
	void InitSize() { capacity = MIN_QUEUED_INTR; }	// assume memory has been zeroized
	int InitSize(int);

	friend struct ControlBlock;
public:
	int LOCALAPI Push(const TLogItem *p);
	int LOCALAPI Pop(TLogItem *p);
};




/**
 * Session Control Block is meant to be shared by LLS and DLL. Shall be prefixed with 'volatile' if LLS is implemented in hardware
 */
enum SocketBufFlagBitPosition
{
	EXCLUSIVE_LOCK = 0,
	IS_ACKNOWLEDGED = 1,
	IS_COMPLETED = 2,
	IS_DELIVERED = 3,
	IS_FULFILLED = 4,	// IS_COMPLETED is for sending. Could reuse bit #2
	// 5: reserved
	IS_COMPRESSED = 6,
	TO_BE_CONTINUED = 7
};



class CSocketItem;	// forward declaration for sake of declaring ControlBlock


// It heavily depends on Address Space Layout Randomization and user-space memory segment isolation
// or similar measures to pretect sensive information, integrity and privacy, of user process
volatile struct ControlBlock
{
	ALIGN(8)
	FSP_Session_State state;

	// By design only a sparned/branched(multiplexed/cloned) connection may be milky
	ALIGN(4)	// sizeof(LONG)
	UINT32		allowedDelay;	// 0 if it is wine-alike payload, non-zero if milky; in microseconds

	ALFID_T	idParent;

	ALIGN(8)	// 64-bit aligment
	FSP_NormalPacketHeader tmpHeader;	// for sending; assume sending is single-threaded for a single session

	// 1, 2.
	// Used to be the matched list of local and remote addresses.
	// for security reason the remote addresses were moved to LLS
	char			nearEndName[INET6_ADDRSTRLEN + 7];	// 72 bytes, in UTF-8
	FSP_PKTINFO_EX	nearEnd[MAX_PHY_INTERFACES];
	union
	{
		char		name[INET6_ADDRSTRLEN + 7];	// 72 bytes
		struct
		{
			UINT64	allowedPrefixes[MAX_PHY_INTERFACES];
			UINT32	hostID;
			ALFID_T fiberID;
		} ipFSP;
	} peerAddr;

	// 3: The negotiated connection parameter
	ALIGN(8)	// 64-bit aligment, make sure that the session key overlays 'initCheckCode' and 'cookie' only
	union
	{
		SConnectParam connectParams;
		BYTE sessionKey[FSP_SESSION_KEY_LEN];	// overlay with 'initCheckCode' and 'cookie'
	} u;
#ifndef NDEBUG
#define MAC_CTX_PROTECT_SIGN	0xA5A5C3C3A5C3A5C3ULL
	ALIGN(MAC_ALIGNMENT)
	uint64_t	_mac_ctx_protect_prolog[2];
#endif
	vmac_ctx_t	mac_ctx;
#ifndef NDEBUG
	uint64_t	_mac_ctx_protect_epilog[2];
#endif

	// 4: The (very short, roll-out) queue of returned notices
	FSP_ServiceCode notices[FSP_MAX_NUM_NOTICE];
	// A lock for DLL or LLS to gain mutually exclusive access on send or receive buffer
	char	dllsmutex;	// 2014.6.7 not used yet UNRESOLVED!
	// Backlog for listening/connected socket [for client it could be an alternate of Web Socket]
	TSingleProviderMultipleConsumerQ<BackLogItem>	backLog;

	// 5, 6: Send window and receive window descriptor
	typedef uint32_t seq_t;
private:
	seq_t		sendWindowFirstSN;	// left-border of the send window
	seq_t		sendWindowNextSN;	// the sequence number of the next packet to send
	// it means that the send queue is empty when sendWindowFirstSN == sendWindowSN2Recv
	int32_t		sendWindowSize;		// in blocks, width of the send window
	// (next position, send buffer next sn) (head position, send window first sn)
	// are managed independently for maximum parallism in DLL and LLS
	int32_t		sendWindowHeadPos;	// the index number of the block with sendWindowFirstSN
	seq_t		sendBufferNextSN;
	int32_t		sendBufferNextPos;	// the index number of the block with sendBufferNextSN
	//
	int32_t		sendBufferBlockN;	// capacity of the send buffer
	uint32_t	sendBuffer;			// relative to start of the control block
	uint32_t	sendBufDescriptors;	// relative to start of the control block,

	seq_t		recvWindowNextSN;	// the next to the right-border of the received area
	int32_t		recvWindowNextPos;	// the index number of the block with recvWindowNextSN
	seq_t		recvWindowFirstSN;	// left-border of the receive window (receive queue), may be empty or may be filled but not delivered
	// it means that the receive queue is empty when recvWindowFirstSN == recvWindowNextSN
	// (next position, receive buffer maximum sn) (head position, receive window first sn)
	// are managed independently for maximum parallism in DLL and LLS
	int32_t		recvWindowHeadPos;	// the index number of the block with recvWindowFirstSN
	//
	seq_t		welcomedNextSNtoSend;
	//
	int32_t		recvBufferBlockN;	// capacity of the receive buffer
	uint32_t	recvBuffer;			// relative to start of the control block
	uint32_t	recvBufDescriptors;	// relative to start of the control block

public:
	// Total size of FSP_SocketBuf (descriptor): 8 bytes (a 64-bit word)
	typedef struct FSP_SocketBuf
	{
		volatile int32_t		len;
		volatile uint16_t		flags;
		volatile uint8_t		version;	// should be the same as in the FSP fixed header
		volatile uint8_t		opCode;		// should be the same as in the FSP fixed header
		//
		template<SocketBufFlagBitPosition i>
		void SetFlag(bool value = true)
		{
			if(value)
				flags |= (1 << i);
			else
				flags &= ~(uint16_t)(1 << i); 
		}
		template<SocketBufFlagBitPosition i>
		bool GetFlag() const { return (flags & (1 << i)) != 0; }
		// TestSetFlag return false if the bit is already set. Works for little-endian CPU only
		template<SocketBufFlagBitPosition i>
		bool TestSetFlag() { return _interlockedbittestandset((LONG *) & flags, i) == FALSE; }
		//
		bool Lock();
		void Unlock() { SetFlag<EXCLUSIVE_LOCK>(false); }
		//
		void InitFlags() { flags = 1 << EXCLUSIVE_LOCK; }
	} *PFSP_SocketBuf;

	// Convert the relative address in the control block to the address in process space, unchecked
	BYTE * GetSendPtr(const PFSP_SocketBuf skb) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((BYTE *)this + sendBufDescriptors);
		uint32_t offset = sendBuffer + MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb, uint32_t &offset) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((BYTE *)this + sendBufDescriptors);
		offset = sendBuffer	+ MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}

	BYTE * GetRecvPtr(const PFSP_SocketBuf skb) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((BYTE *)this + recvBufDescriptors);
		uint32_t offset = recvBuffer + MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}
	BYTE * GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb, uint32_t &offset) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((BYTE *)this + recvBufDescriptors);
		offset = recvBuffer	+ MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}

	// 7, 8 Send buffer and Receive buffer
	// See ControlBlock::Init()

	//
	int CountSendBuffered() const { return int(sendBufferNextSN - sendWindowFirstSN); }
	int CountUnacknowledged() const { return int(sendWindowNextSN - sendWindowFirstSN); }
	int CountUnacknowledged(seq_t expectedSN) const { return int(sendWindowNextSN - expectedSN); }
#ifdef TRACE
	int DumpSendRecvWindowInfo() const
	{
		return printf_s("\tSend[head, tail] = [%d, %d], packets on flight = %d\n"
			"\tSN next to send = %u, welcomedNextSNtoSend = %u\n"
			"\tRecv[head, tail] = [%d, %d], receive window size = %d\n"
			"\tSN first received = %u, max expected = %u\n"
			, sendWindowHeadPos
			, sendBufferNextPos
			, int(sendWindowNextSN - sendWindowFirstSN)
			, sendWindowNextSN
			, welcomedNextSNtoSend
			, recvWindowHeadPos
			, recvWindowNextPos
			, int(recvWindowNextSN - recvWindowFirstSN)
			, recvWindowFirstSN
			, recvWindowNextSN);
	}
#else
	int DumpSendRecvWindowInfo() const {}
#endif

	PFSP_SocketBuf HeadSend() const { return (PFSP_SocketBuf)((BYTE *)this + sendBufDescriptors); }
	PFSP_SocketBuf HeadRecv() const { return (PFSP_SocketBuf)((BYTE *)this + recvBufDescriptors); }

	seq_t GetSendWindowFirstSN() const { return sendWindowFirstSN; }
	seq_t GetSendWindowFirstSN(register int32_t &capacity, register int32_t &iHead) const 
	{
		capacity = sendBufferBlockN;
		iHead = sendWindowHeadPos;
		return sendWindowFirstSN; 
	}
	//
	PFSP_SocketBuf GetFirstBufferedSend() const { return HeadSend() + sendWindowHeadPos; }
	// Return the descriptor of the last buffered packet in the send buffer, NULL if the send queue is empty
	PFSP_SocketBuf GetLastBufferedSend() const
	{
		if (CountSendBuffered() <= 0)
			return NULL;
		//
		register int i = sendBufferNextPos - 1;
		return HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i);
	}
	// Allocate a new send buffer
	PFSP_SocketBuf	GetSendBuf();
	PFSP_SocketBuf	GetNextToSend() const
	{
		register int i = sendWindowHeadPos + (sendWindowNextSN - sendWindowFirstSN);
		if(i - sendBufferBlockN >= 0)
			i -= sendBufferBlockN;
		return HeadSend() + i;
	}
	PFSP_SocketBuf	PeekAnteCommit() const;
	bool CheckSendWindowLimit(int32_t cwnd) const { return int(sendWindowNextSN - sendWindowFirstSN) <= min(sendWindowSize, cwnd); }

	void RoundSendBufferNextPos() { int32_t m = sendBufferNextPos - sendBufferBlockN; if(m >= 0) sendBufferNextPos = m; }

	// UNRESOLVED! Do we have to maintain the last buffered send packet, however?
	int ClearSendWindow() { sendWindowHeadPos = sendBufferNextPos = 0; return sendBufferBlockN; }

	int CountReceived() const { return int(recvWindowNextSN - recvWindowFirstSN); }
	bool IsValidSequence(seq_t seq1) const
	{
		register int d = int(seq1 - recvWindowFirstSN);
		// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
		return (0 <= d) && (d < recvBufferBlockN);
	}
	bool IsRetriableStale(seq_t seq1) const
	{
		register int d = int(seq1 - recvWindowFirstSN);
		// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
		return (d < -1) || (d >= recvBufferBlockN);
	}

	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *, PFSP_SocketBuf, seq_t);
	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *, seq_t);
	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *);

	void LOCALAPI EmitQ(CSocketItem *);	// ONLY implemented in LLS
	void * LOCALAPI InquireSendBuf(int &);
	int	LOCALAPI MarkSendQueue(void *, int, bool);

	PFSP_SocketBuf GetFirstReceived() const { return HeadRecv() + recvWindowHeadPos; }
	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int) const;

	// Return the last received packet, which might be already delivered
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);
	// Slide the left border of the receive window by one slot
	void SlideRecvWindowByOne()	// shall be atomic!
	{
		recvWindowFirstSN++;
		if(++recvWindowHeadPos - recvBufferBlockN >= 0)
			recvWindowHeadPos -= recvBufferBlockN;
	}
	void * LOCALAPI InquireRecvBuf(int &, bool &);

	void SetRecvWindowHead(seq_t pktSeqNo)	{ recvWindowNextSN = recvWindowFirstSN = pktSeqNo; }
	void SetSendWindowWithHeadReserved(seq_t initialSN)
	{
		PFSP_SocketBuf skb = HeadSend();
		skb->InitFlags(); // and locked
		skb->version = THIS_FSP_VERSION;
		sendWindowHeadPos = 0;
		welcomedNextSNtoSend = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextSN = initialSN + 1;
		sendBufferNextPos = 1;
		sendWindowSize = 1;
	}
	void SetSendWindowSize(int32_t sz1) { sendWindowSize = min(sendBufferBlockN, sz1); }

	// Check the receive queue to test whether it could migrate to the CLOSABLE state
	bool IsClosable() const;

	seq_t MoveNextToSend() { return sendWindowNextSN++; }
	// Slide the send window to skip all of the acknowledged
	void SlideSendWindow();
	// Slide the send window to skip the head slot, supposing that it has been acknowledged
	void SlideSendWindowByOne()	// shall be atomic!
	{
		sendWindowFirstSN++;
		if(++sendWindowHeadPos - sendBufferBlockN >= 0)
			sendWindowHeadPos -= sendBufferBlockN;
	}
	//
	bool LOCALAPI ResizeSendWindow(seq_t, unsigned int);

	// Width of the advertisable receive window (i.e. free receive buffers to advertize), in blocks
	INT32 RecvWindowSize() const
	{
		int d = CountReceived();
		return (d < 0 ? -1 : recvBufferBlockN - d);
	}

	bool HasBacklog() const { return backLog.count > 0; }
	bool LOCALAPI	HasBacklog(const BackLogItem *p);
	int LOCALAPI	PushBacklog(const BackLogItem *p);
	int LOCALAPI	PopBacklog(BackLogItem *p);
	int LOCALAPI	PushNotice(FSP_ServiceCode);
	FSP_ServiceCode PopNotice();

	int LOCALAPI	Init(int32_t, int32_t);
	int	LOCALAPI	Init(uint16_t);

	friend void UnitTestSendRecvWnd();
	friend void UnitTestResendQueue();
	friend void UnitTestGenerateSNACK();
	friend void UnitTestAcknowledge();
};

#include <poppack.h>


class CSocketItem
{
protected:
	PairALFID	fidPair;
	HANDLE	hEvent;
	HANDLE	hMemoryMap;
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	ControlBlock *pControlBlock;

	void SetReturned() { pControlBlock->notices[0] = NullCommand; }	// clear the 'NOT-returned' notice

	~CSocketItem() { Destroy(); }
	void Destroy()
	{
		if(hMemoryMap != NULL)
		{
			::UnmapViewOfFile(pControlBlock);
			::CloseHandle(hMemoryMap);
			hMemoryMap = NULL;
			pControlBlock = NULL;
		}
		if(hEvent != NULL)
		{
			::CloseHandle(hEvent);
			hEvent = NULL;
		}
	}
};



class FSP_Header_Manager
{
	BYTE		*pHdr;
	UINT16		pStackPointer;
public:
	// Initialize the FSP_Header manager for pushing operations
	// Given
	//	void *		point to the fixed part of FSP header
	//	int			length of the header
	FSP_Header_Manager(void *p1, int len)
	{
		pHdr = (BYTE *)p1;
		pStackPointer = (len + 7) & 0xFFF8;
		// header of stack pointer to be set in the future
	}
	// Tnitialize the FSP_Header manager for popping operations
	// Given
	//	void *	pointer to the fixed part of FSP header in the receiving buffer
	// Remark
	//	The caller should check validity of pStackPointer with calling 'NextHeaderOffset'
	FSP_Header_Manager(void *p1)
	{
		pHdr = (BYTE *)p1;
		pStackPointer = ntohs(((FSP_Header *)p1)->hs.hsp);
	}
	//
	// Push an extension header
	// Given
	//	THdr *	the pointer to the buffer that holds the extension header
	// Return
	//	The value of the new top of the last header
	// Remark
	//	THdr is a template class/struct type that must be 64-bit aligned
	//	If the first header is not the fixed header, what returned may not be treated as the final stack pointer
	template<typename THdr> UINT16 PushExtHeader(THdr *pExtHdr)
	{
		memcpy(pHdr + pStackPointer, pExtHdr, sizeof(THdr));
		pStackPointer += sizeof(THdr);
		return pStackPointer;
	}
	// Pop an extension header
	// Return
	//	The pointer to the optional header
	// Remark
	//	The caller should check that pStackPointer does not fall into dead-loop
	template<typename THdr>	THdr * PopExtHeader()
	{
		UINT16 prevOffset = pStackPointer - sizeof(FSP_HeaderSignature);
		pStackPointer = ntohs( ( (PFSP_HeaderSignature)(pHdr + prevOffset) )->hsp );
		if(pStackPointer < sizeof(FSP_NormalPacketHeader) || pStackPointer >= prevOffset)
			return NULL;
		return (THdr *)(pHdr + pStackPointer - sizeof(THdr));
	}
	//
	// Push a data block, does not change the value of the top of the last header
	// Given
	//	BYTE *	the data buffer
	//	int		the length of the data block to be pushed
	// Remark
	//	the given length is not necessary 64-bit aligned,
	//	but the pointer to the stack header pointer would be aligned automatically
	void PushDataBlock(BYTE *buf, int len)
	{
		memcpy(pHdr + pStackPointer, buf, len);
		pStackPointer += (len + 7) & 0xFFF8;
	}
	// Conver the FSP header stack pointer to a data block pointer
	void * TopAsDataBlock() const { return pHdr + pStackPointer; }
	//
	int	NextHeaderOffset() const { return (int)pStackPointer; }
};

#endif
