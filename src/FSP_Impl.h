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
#include <stdio.h>

// borrow intrinsic pragmas
#include "gcm-aes.h"
#define	MAC_ALIGNMENT	16
#define COOKIE_KEY_LEN	16

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

FORCEINLINE char _InterlockedExchange16(volatile short * a, short b)
{
	__asm mov	ecx, a;
	__asm mov	AX, b;
	__asm xchg	AX, word ptr[ecx];
}
#endif



/**
 * For testability
 */
#ifdef TRACE
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



/**
 * IPC
 */
#define SERVICE_MAILSLOT_NAME	"\\\\.\\mailslot\\flexible\\session\\protocol"
#define MAX_CTRLBUF_LEN		424	// maximum message passing structure/mailslot size
#define REVERSE_EVENT_PREFIX	"Global\\FlexibleSessionProtocolEvent"
#define MAX_NAME_LENGTH		64	// considerably less than MAX_PATH

#ifdef _DEBUG
#define	CONNECT_BACKLOG_SIZE	2
#else
#define	CONNECT_BACKLOG_SIZE	512
#endif



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



#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
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
#define FSP_MAX_NUM_NOTICE	15	// should be a reasonable value, shall be some multiple of 8 minus 1
#define	MIN_RESERVED_BUF	(MAX_BLOCK_SIZE * 2)



/**
 * Reflexing string representation of operation code, for debug purpose
 */
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

// Reflexing string 
class CStringizeNotice
{
	static const char * names[LARGEST_FSP_NOTICE + 1];
public:
	const char * operator[](int);
};

extern CStringizeOpCode opCodeStrings;

extern CStringizeState	stateNames;

extern CStringizeNotice noticeNames;



/**
 * platform-dependent fundamental utility functions
 */
#define LOCALAPI __fastcall



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
		hsp = htobe16(sizeof(THdr));
	}
	void Set(BYTE opCode1, int len1)
	{
		version = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = htobe16(len1);
	}
};


// position start from 0, the rightmost one
enum FSP_FlagPosition: UINT8
{
	ToBeContinued = 0,
	Compressed = 1,
	RESERVED_AT_2,
	RESERVED_AT_3,
	FirstInFirstDrop = 4,
};



struct FSP_NormalPacketHeader
{
	uint32_t sequenceNo;
	uint32_t expectedSN;
	union
	{
		uint64_t	code;
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

	// Given sequenceNo, expectedNo, receive window size and total length of all the headers
	void LOCALAPI Set(uint32_t, uint32_t, int32_t, uint8_t, uint16_t);

	// A bruteforce but safe method of set or retrieve recvWS, with byte order translation
	int32_t GetRecvWS() const { return ((int32_t)flags_ws[0] << 16) + (flags_ws[1] << 8) + flags_ws[2]; }
	void SetRecvWS(int32_t v) { flags_ws[0] = (UINT8)(v >> 16); flags_ws[1] = (UINT8)(v >> 8); flags_ws[2] = (UINT8)v; }

	void ClearFlags() { flags_ws[3] = 0; }
	template<FSP_FlagPosition pos> void SetFlag() { flags_ws[3] |= (1 << pos); }
	template<FSP_FlagPosition pos> void ClearFlag() { flags_ws[3] &= ~(1 << pos); }
	template<FSP_FlagPosition pos> int GetFlag() const { return flags_ws[3] & (1 << pos); }

	// Get the first extension header
	PFSP_HeaderSignature PFirstExtHeader() const { return (PFSP_HeaderSignature)((uint8_t *)this + be16toh(hs.hsp) - sizeof(FSP_HeaderSignature)); }

	// Get next extension header
	// Given
	//	The pointer to the current extension header
	// Return
	//	The pointer to the next optional header, NULL if it is illegal
	// Remark
	//	The caller should check that pStackPointer does not fall into dead-loop
	template<typename THdr>	PFSP_HeaderSignature PHeaderNextTo(void *p0) const
	{
		uint16_t sp = be16toh(((THdr *)p0)->hs.hsp);
		if(sp < sizeof(FSP_NormalPacketHeader) || sp > (uint8_t *)p0 - (uint8_t *)this)
			return NULL;
		return (PFSP_HeaderSignature)((uint8_t *)this + sp - sizeof(FSP_HeaderSignature));
	}
};



struct FSP_InitiateRequest
{
	timestamp_t timeStamp;
	uint64_t	initCheckCode;
	uint32_t	salt;
	$FSP_HeaderSignature hs;
};



// acknowledgement to the connect bootstrap request, works as a challenge against the initiator
// to be followed by the certificate optional header
struct FSP_Challenge
{
	uint64_t	cookie;
	uint64_t	initCheckCode;
	int32_t		timeDelta;
	$FSP_HeaderSignature hs;
};



// FSP_ConnectParam specifies the parent connection in a MULTIPLY or CONNECT_REQUEST packet
// while alias as the mobile parameters
// MOBILE_PARAM used to be CONNECT_PARAM and it is perfect OK to treat the latter as the canonical alias of the former
struct FSP_ConnectParam
{
	uint64_t	subnets[MAX_PHY_INTERFACES];
	ALFID_T		listenerID;
	//
	// host id of the application layer fiber, alias of listenerID
	__declspec(property(get=getHostID, put=setHostID))
	uint32_t	idHost;
	uint32_t	getHostID() const { return listenerID; }
	void		setHostID(uint32_t value) { listenerID = value; }
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



// Mandatory additional header for KEEP_ALIVE
// minumum constituent of a SNACK header
struct FSP_SelectiveNACK
{
	struct GapDescriptor
	{
		uint32_t	gapWidth;	// in packets
		uint32_t	dataLength;	// in packets
	};
	uint32_t		serialNo;
	$FSP_HeaderSignature hs;
};



struct FSP_RejectConnect
{
	union
	{
		timestamp_t timeStamp;
		struct
		{
			uint32_t initial;
			uint32_t expected;
		} sn;
	} u;
	//
	union
	{
		uint64_t integrityCode;
		uint64_t cookie;
		uint64_t initCheckCode;
		PairALFID fidPair;
	} u2;
	//
	uint32_t reasons;	// bit field(?)
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
	ALFID_T			fiberID;
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



struct FSP_PKTINFO_EX : FSP_SINKINF
{
	int32_t	cmsg_level;
	//
	void InitUDPoverIPv4(ULONG if1)
	{
		memset(this, 0, sizeof(FSP_SINKINF));		// inaddr_any
		ipi_ifindex = if1;
		cmsg_level = IPPROTO_IP;	/* originating protocol */
	}
	//
	void InitNativeIPv6(ULONG if1)
	{
		memset(this, 0, sizeof(FSP_SINKINF));		// in6addr_any;
		ipi6_ifindex = if1;
		cmsg_level = IPPROTO_IPV6;	/* originating protocol */
	}
	//
	bool IsIPv6() const { return (cmsg_level == IPPROTO_IPV6); }
};



struct SConnectParam	// MUST be aligned on 64-bit words!
{
	// the first four fields are to be initiaized with random value
	uint64_t	initCheckCode;
	uint64_t	cookie;
	uint32_t	salt;
	int32_t		timeDelta;	// delay of peer to peer timestamp, delta of clock 
	timestamp_t nboTimeStamp;
	//^ Timestamp in network byte order, together with the first four fields, totally 256 bits could be overlaid
	//

	// For sake of SCB reuse we arranged to save remained key life in the timeDelta field
	__declspec(property(get = getKeyLife, put = setKeyLife))
		int32_t	keyLife;
	int32_t getKeyLife() const { return timeDelta; }
	void setKeyLife(int32_t value) { timeDelta = value; } 

	uint32_t	initialSN;	// the initial sequence number of the packet to send
	int32_t		keyLength;	// by default 16 bytes
	ALFID_T		idRemote;	// ID of the listener or the new forked, depending on context
	uint32_t	remoteHostID;
	//
	uint64_t	allowedPrefixes[MAX_PHY_INTERFACES];
};	// totally 56 bytes, 448 bits



struct BackLogItem: SConnectParam
{
	FSP_SINKINF	acceptAddr;	// including the interface number AND the local fiber ID
	ALFID_T		idParent;
	//^ 0 if it is the 'root' acceptor, otherwise the local fiber ID of the cloned connection
	uint32_t	expectedSN;	// the expected sequence number of the packet to receive by order
	//
	BackLogItem() { } // default constructor
	BackLogItem(ALFID_T id1, uint32_t salt1) { idRemote = id1; salt = salt1; } 
};



class LLSNotice
{
	friend struct ControlBlock;
protected:
	// 4: The (very short, roll-out) queue of returned notices
	FSP_ServiceCode q[FSP_MAX_NUM_NOTICE];
	volatile char	mutex;
public:
	void SetHead(FSP_ServiceCode c) { q[0] = c; }
	FSP_ServiceCode GetHead() { return q[0]; }
	// put a new notice at the tail of the queue
	int LOCALAPI	Put(FSP_ServiceCode);
	// pop the notice from the top
	FSP_ServiceCode Pop();
};



class LLSBackLog
{
	friend struct ControlBlock;

	volatile char		mutex;
	ALIGN(8)
	int32_t				capacity;
	volatile int32_t	headQ;
	volatile int32_t	tailQ;
	volatile int32_t	count;
	//
	ALIGN(8)
	BackLogItem			q[MIN_QUEUED_INTR];
	//
	void InitSize() { capacity = MIN_QUEUED_INTR; mutex = 0; }	// assume memory has been zeroized
	int	InitSize(int);

	void WaitSetMutex() { while(_InterlockedCompareExchange8(& mutex, 1, 0)) Sleep(0); }
	void SetMutexFree() { _InterlockedExchange8(& mutex, 0); }
public:
	void Clear() { count = 0; headQ = tailQ; mutex = 0; }
	bool LOCALAPI Has(const BackLogItem *p);
	BackLogItem * Peek() { return count <= 0 ? NULL : q  + headQ; }
	int Pop();
	int LOCALAPI Put(const BackLogItem *p);
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
	IS_FULFILLED = IS_COMPLETED,// mutual-mirroring flags for send and receive
	IS_SENT = IS_DELIVERED,		// IS_SENT is for send while IS_DELIVERED is for receive 
	// 4, 5: reserved
	IS_COMPRESSED = 6,
	TO_BE_CONTINUED = 7
};



enum PendingKeyMask
{
	HAS_PENDING_KEY_FOR_SEND = 1,
	HAS_PENDING_KEY_FOR_RECV = 2
};



class CSocketItem;	// forward declaration for sake of declaring ControlBlock



// It heavily depends on Address Space Layout Randomization and user-space memory segment isolation
// or similar measures to pretect sensive information, integrity and privacy, of user process
struct ControlBlock
{
	ALIGN(8)
	volatile FSP_Session_State state;
	char			hasPendingKey;
	ALFID_T			idParent;

	ALIGN(8)	// 64-bit aligment
	FSP_NormalPacketHeader tmpHeader;	// for sending; assume sending is single-threaded for a single session

	// 1, 2.
	// Used to be the matched list of local and remote addresses.
	// for security reason the remote addresses were moved to LLS
	char			nearEndName[INET6_ADDRSTRLEN + 7];	// 72 bytes, in UTF-8
	FSP_PKTINFO_EX	nearEndInfo;
	struct
	{
		char		name[INET6_ADDRSTRLEN + 7];	// 72 bytes
		struct
		{
			uint64_t	allowedPrefixes[MAX_PHY_INTERFACES];
			uint32_t	hostID;
			ALFID_T		fiberID;
		} ipFSP;
	} peerAddr;

	// 3: The negotiated connection parameter
	ALIGN(8)	// 64-bit aligment, make sure that the session key overlays 'initCheckCode' and 'cookie' only
	SConnectParam connectParams;

	// 4: The queue of returned notices
	LLSNotice	notices;
	// Backlog for listening/connected socket [for client it could be an alternate of Web Socket]
	LLSBackLog	backLog;

	// 5, 6: Send window and receive window descriptor
	typedef uint32_t seq_t;

	//
	// BEGIN REGION: buffer descriptors 
	//
	// (head position, send window first sn), (send window next posistion, send window next sequence nuber)
	// and (buffer next position, send buffer next sequence number) are managed independently
	// for maximum parallism in DLL and LLS
	// the send queue is empty when sendWindowFirstSN == sendWindowNextSN
	seq_t		sendWindowFirstSN;	// left-border of the send window
	int32_t		sendWindowHeadPos;	// the index number of the block with sendWindowFirstSN
	seq_t		sendWindowNextSN;	// the sequence number of the next packet to send
	int32_t		sendWindowNextPos;	// the index number of the block with sendWindowNextSN
	seq_t		sendBufferNextSN;
	int32_t		sendBufferNextPos;	// the index number of the block with sendBufferNextSN
	//
	int32_t		sendWindowSize;		// width of the send window in blocks
	int32_t		sendBufferBlockN;	// capacity of the send buffer in blocks

	// (head position, receive window first sn) (next position, receive buffer maximum sn)
	// are managed independently for maximum parallism in DLL and LLS
	// the receive queue is empty when recvWindowFirstSN == recvWindowNextSN
	seq_t		recvWindowFirstSN;	// left-border of the receive window (receive queue), may be empty or may be filled but not delivered
	int32_t		recvWindowHeadPos;	// the index number of the block with recvWindowFirstSN
	seq_t		recvWindowNextSN;	// the next to the right-border of the received area
	int32_t		recvWindowNextPos;	// the index number of the block with recvWindowNextSN
	//
	seq_t		welcomedNextSNtoSend;
	//
	int32_t		recvBufferBlockN;	// capacity of the receive buffer

	int32_t		sendBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		recvBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		sendBuffer;			// relative to start of the control block
	int32_t		recvBuffer;			// relative to start of the control block

	// Total size of FSP_SocketBuf (descriptor): 8 bytes (a 64-bit word)
	typedef struct FSP_SocketBuf
	{
		int32_t		len;
		uint16_t	flags;
		uint8_t		version;	// should be the same as in the FSP fixed header
		uint8_t		opCode;		// should be the same as in the FSP fixed header
		//
#if ARCH_BIG_ENDIAN
		template<SocketBufFlagBitPosition i>
		bool SetFlag(bool value = true)
		{
			return (value
				? InterlockedBitTestAndSet((LONG *) & flags, i + 16) 
				: InterlockedBitTestAndReset((LONG *) & flags, i + 16)
				) != 0;
		}
		template<SocketBufFlagBitPosition i>
		bool GetFlag() { return BitTest((LONG *) & flags, i + 16) != 0; }
#else
		template<SocketBufFlagBitPosition i>
		bool SetFlag(bool value = true)
		{
			return (value
				? InterlockedBitTestAndSet((LONG *) & flags, i) 
				: InterlockedBitTestAndReset((LONG *) & flags, i)
				) != 0;
		}
		//
		template<SocketBufFlagBitPosition i>
		bool GetFlag() { return BitTest((LONG *) & flags, i) != 0; }
#endif
		bool Lock()	{ return ! SetFlag<EXCLUSIVE_LOCK>(); }
		void Unlock() { SetFlag<EXCLUSIVE_LOCK>(false); }
		//
		void InitFlags() { _InterlockedExchange16((SHORT *) & flags, 1 << EXCLUSIVE_LOCK); }
	} *PFSP_SocketBuf;
	//
	// END REGION: buffer descriptors
	//

	// Convert the relative address in the control block to the address in process space, unchecked
	BYTE * GetSendPtr(const PFSP_SocketBuf skb)
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((BYTE *)this + sendBufDescriptors);
		uint32_t offset = sendBuffer + MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}
	BYTE * GetSendPtr(const ControlBlock::PFSP_SocketBuf skb, uint32_t &offset)
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
	int CountSentInFlight() const { return int(sendWindowNextSN - sendWindowFirstSN); }
#if defined(TRACE) || defined(TRACE_HEARTBEAT)
	int DumpSendRecvWindowInfo() const
	{
		return printf_s("\tSend[head, tail] = [%d, %d], packets on flight = %d\n"
			"\tSN next to send = %u(@%d), welcomedNextSNtoSend = %u\n"
			"\tRecv[head, tail] = [%d, %d], receive window size = %d\n"
			"\tSN first received = %u, max expected = %u\n"
			, sendWindowHeadPos, sendBufferNextPos, int(sendWindowNextSN - sendWindowFirstSN)
			, sendWindowNextSN, sendWindowNextPos, welcomedNextSNtoSend
			, recvWindowHeadPos, recvWindowNextPos, int(recvWindowNextSN - recvWindowFirstSN)
			, recvWindowFirstSN, recvWindowNextSN);
	}
#else
	int DumpSendRecvWindowInfo() const { return 0; }
#endif

	PFSP_SocketBuf HeadSend() const { return (PFSP_SocketBuf)((BYTE *)this + sendBufDescriptors); }
	PFSP_SocketBuf HeadRecv() const { return (PFSP_SocketBuf)((BYTE *)this + recvBufDescriptors); }

	// Return the head packet even if the send queue is empty
	PFSP_SocketBuf GetSendQueueHead() const { return HeadSend() + sendWindowHeadPos; }
	// Return the descriptor of the last buffered packet in the send buffer, NULL if the send queue is empty or cannot obtain the lock
	// The imcomplete last buffered packet, if any, is implictly locked
	// but a complete packet MUST be explicitly locked at first here to make the send queue stable enough
	PFSP_SocketBuf LockLastBufferedSend() const
	{
		register int i = sendBufferNextPos - 1;
		register PFSP_SocketBuf p = HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i);
		if(! p->Lock())
			return NULL;
		// An invalid packet buffer might be locked
		return CountSendBuffered() <= 0 ? NULL : p;
	}
	// Return 0 if there is no COMMIT packet at the tail and there is no error on appending one
	//	1 if there is already a COMMIT packet at the tail of the send queue
	//	-1 if failed
	int ReplaceSendQueueTailToCommit();

	// Allocate a new send buffer
	PFSP_SocketBuf	GetSendBuf();

	void RoundSendBufferNextPos() { int32_t m = sendBufferNextPos - sendBufferBlockN; if(m >= 0) sendBufferNextPos = m; }
	void RoundSendWindowNextPos() { int32_t m = sendWindowNextPos - sendBufferBlockN; if(m >= 0) sendWindowNextPos = m; }

	int32_t CountReceived() const { return int32_t(recvWindowNextSN - recvWindowFirstSN); }
	bool IsValidSequence(seq_t seq1) const
	{
		register int32_t d = int32_t(seq1 - recvWindowFirstSN);
		// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
		return (0 <= d) && (d < recvBufferBlockN);
	}
	bool IsRetriableStale(seq_t seq1) const
	{
		register int32_t d = int32_t(seq1 - recvWindowFirstSN);
		// somewhat 'be free to accept' as we didnot enforce 'announced receive window size'
		return (d < -1) || (d >= recvBufferBlockN);
	}

	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *, PFSP_SocketBuf, seq_t);
	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *, seq_t);
	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *);

	void * LOCALAPI InquireSendBuf(int &);

	PFSP_SocketBuf GetFirstReceived() const { return HeadRecv() + recvWindowHeadPos; }
	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int) const;
	int LOCALAPI DealWithSNACK(seq_t, FSP_SelectiveNACK::GapDescriptor *, int & n);

	// Return the last received packet, which might be already delivered
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);
	// Slide the left border of the receive window by one slot
	void SlideRecvWindowByOne()	// shall be atomic!
	{
		if(++recvWindowHeadPos - recvBufferBlockN >= 0)
			recvWindowHeadPos -= recvBufferBlockN;
		InterlockedIncrement((LONG *) & recvWindowFirstSN);
	}
	void * LOCALAPI InquireRecvBuf(int &, bool &);

	void SetRecvWindowHead(seq_t pktSeqNo)
	{
		recvWindowNextSN = recvWindowFirstSN = pktSeqNo; 
		recvWindowHeadPos = recvWindowNextPos = 0;
	}
	void SetSendWindowHead(seq_t initialSN)
	{
		welcomedNextSNtoSend = sendBufferNextSN = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextPos = sendWindowNextPos = sendWindowHeadPos = 0;
		sendWindowSize = 1;
	}
	void SetSendWindowWithHeadReserved(seq_t initialSN)
	{
		PFSP_SocketBuf skb = HeadSend();
		skb->InitFlags(); // and locked
		skb->version = THIS_FSP_VERSION;
		welcomedNextSNtoSend = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextSN = initialSN + 1;	// prevent the head packet from being overlaid
		sendWindowNextPos = sendWindowHeadPos = 0;
		sendBufferNextPos = 1;
		sendWindowSize = 1;
	}
	void SetSendWindowSize(int32_t sz1) { sendWindowSize = min(sendBufferBlockN, sz1); }

	// there is a COMMIT packet in the receive queue and there is no gap before the COMMIT packet
	int HasBeenCommitted() const;

	// Slide the send window to skip all of the acknowledged
	void SlideSendWindow();
	// Slide the send window to skip the head slot, supposing that it has been acknowledged
	void SlideSendWindowByOne();

	// return new value of sendWindowNextSN
	seq_t SlideNextToSend()
	{
		if(++sendWindowNextPos - sendBufferBlockN >= 0)
			sendWindowNextPos -= sendBufferBlockN;
		return _InterlockedIncrement((LONG *) & sendWindowNextSN);
	}
	//
	bool LOCALAPI ResizeSendWindow(seq_t, unsigned int);

	// Width of the advertisable receive window (i.e. free receive buffers to advertize), in blocks
	int32_t RecvWindowSize() const
	{
		int32_t d = CountReceived();
		return (d < 0 ? 0 : recvBufferBlockN - d);
	}

	bool HasBacklog() const { return backLog.count > 0; }

	int LOCALAPI	Init(int32_t, int32_t);
	int	LOCALAPI	Init(uint16_t);
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

	void SetCallable() { pControlBlock->notices.SetHead(NullCommand); }	// clear the 'NOT-returned' notice

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

#endif
