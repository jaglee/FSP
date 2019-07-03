#ifndef _FSP_IMPLEMENTATION_H
#define _FSP_IMPLEMENTATION_H

/*
 * Flexible Session Protocol, implementation-dependent definitions
 * shared between the service process and the upper layer application process
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

#include "FSP.h"

#pragma intrinsic(_InterlockedCompareExchange, _InterlockedCompareExchange8)
#pragma intrinsic(_InterlockedExchange, _InterlockedExchange8)
#pragma intrinsic(_InterlockedExchangeAdd, _InterlockedIncrement)
#pragma intrinsic(_InterlockedOr, _InterlockedOr8)

#define LCKREAD(dword) _InterlockedOr((volatile long *)&dword, 0)

#define	MAC_ALIGNMENT	16


/**
 * For testability
 */
#ifdef TRACE
# define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, "ERROR REPORT")
# define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, (s1))
void TraceLastError(char * fileName, int lineNo, char *funcName, char *s1);
#else
# define REPORT_ERROR_ON_TRACE()
# define REPORT_ERRMSG_ON_TRACE(s) (s)
#endif

#define TRACE_ADDRESS	1
#define TRACE_HEARTBEAT	2
#define TRACE_PACKET	4
#define TRACE_SLIDEWIN	8
#define TRACE_ULACALL	16
#define TRACE_OUTBAND	32	// Other than KEEP_ALIVE


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

#ifdef _DEBUG
# define DEINIT_WAIT_TIMEOUT_ms		15000	// 15 seconds
# define BREAK_ON_DEBUG()			DebugBreak()
#else
# define DEINIT_WAIT_TIMEOUT_ms		5000	// 5 seconds
# define BREAK_ON_DEBUG()
#endif


#define MAX_LOCK_WAIT_ms			60000	// one minute
#define TIMER_SLICE_ms				50		// 1/20 second
#define	MAX_IDLE_QUOTA_TICKS		6		// Refuse to add quota if sending is idle more than this threshold
#define SLOW_START_WINDOW_SIZE		4		// in packet

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif


/**
 * Implemented system limit
 */
#ifndef OVER_UDP_IPv4
// IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater. 
# define MAX_BLOCK_SIZE		1024
# define MAX_LLS_BLOCK_SIZE	(MAX_BLOCK_SIZE + sizeof(FSP_NormalPacketHeader))		// 1048
#else
# define MAX_BLOCK_SIZE		512
# define MAX_LLS_BLOCK_SIZE	(MAX_BLOCK_SIZE + sizeof(FSP_NormalPacketHeader) + sizeof(ALFIDPair))	// 544
#endif

#define MIN_QUEUED_INTR		2	// minimum number of queued (soft) interrupt, must be some power value of 2
#define FSP_BACKLOG_SIZE	4	// shall be some power of 2
#define FSP_MAX_NUM_NOTICE	15	// should be a reasonable value, shall be some multiple of 8 minus 1
#define	MIN_RESERVED_BUF	(MAX_BLOCK_SIZE * 2)
#ifndef MAX_BUFFER_BLOCKS
# define	MAX_BUFFER_BLOCKS	0x20000	// maximum buffer size is implementation specific. here about 128MB for FSP over IPv6
#endif

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

// Reflexing string representation of software vector interrupt (notice), for debug purpose
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

// Network byte order of the length of the fixed header, where host byte order is little-endian
#define CONNECT_PARAM_LENGTH_BE16	0x2800
#define	FIXED_HEADER_SIZE_BE16		0x1800
#define SNACK_HEADER_SIZE_BE16		0x1000

// Set the prefix of FSP_ConnectParam content
#define SetConnectParamPrefix(hdr)	{	\
	(hdr)._h.opCode = PEER_SUBNETS;		\
	(hdr)._h.mark = 0;					\
	(hdr)._h.length = CONNECT_PARAM_LENGTH_BE16; \
}

#define SetHeaderSignature(hdr, code) {	\
	(hdr).hs.opCode = (code);			\
	(hdr).hs.major = THIS_FSP_VERSION;	\
	(hdr).hs.offset = FIXED_HEADER_SIZE_BE16;	\
	}


/**
 * Command to lower layer service
 * Try to make a 32-bit process calling the 64-bit FSP lower-level service possible
 * by exploiting POST-FIX(!) ALIGN(8)
 * Feasible in a little-endian CPU, provided that the structure is pre-zeroed
 */
struct CommandToLLS
{
	ALIGN(8)
	DWORD			idProcess;
	ALFID_T			fiberID;
	FSP_ServiceCode	opCode;	// operation code
};



struct CommandNewSession: CommandToLLS
{
	char			szEventName[MAX_NAME_LENGTH];	// name of the callback event
	DWORD			dwMemorySize;	// size of the shared memory, in the mapped view
	uint64_t		hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server

	CommandNewSession() { memset(this, 0, sizeof(CommandNewSession)); }
};



struct CommandRejectRequest : CommandToLLS
{
	uint32_t		reasonCode;	

	CommandRejectRequest(ALFID_T id1, uint32_t rc)	{ fiberID = id1; opCode = FSP_Reject; reasonCode = rc; }
};



struct CommandInstallKey : CommandToLLS
{
	uint32_t	nextSendSN;	// ControlBlock::seq_t
	uint64_t	keyLife;
	octet		ikm[400];	// it is hard-coded to 400 bytes, i.e. 3200 bits
	CommandInstallKey(uint32_t seq1, uint64_t v) { nextSendSN = seq1; keyLife = v; }
};



struct CommandCloneConnect : CommandNewSession
{
	// used to pass 'committing' flag in the command
};



struct FSP_ADDRINFO_EX : FSP_SINKINF
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
};



struct SConnectParam	// MUST be aligned on 64-bit words!
{
	// the first 3 fields, together with initialSN, are to be initialized with random value
	uint64_t	initCheckCode;
	uint64_t	cookie;
	uint32_t	salt;
	int32_t		timeDelta; 
	timestamp_t nboTimeStamp;
	//^ Timestamp in network byte order, together with the first four fields, totally 256 bits could be overlaid
	//
	octet		padding[8];	// allow maximum key length of 384-bit, padding the structure to 64 bytes/512bits
	int32_t		keyBits;	// by default 128
	union
	{
		uint32_t	initialSN;
		int32_t		nextKey$initialSN;
	};

	ALFID_T		idRemote;	// ID of the listener or the new forked, depending on context
	uint32_t	remoteHostID;
	//
	TSubnets	allowedPrefixes;
};	// totally 64 bytes, 512 bits



struct BackLogItem: SConnectParam
{
	FSP_ADDRINFO_EX	acceptAddr;		// including the local fiber ID
	ALFID_T		idParent;
	//^ 0 if it is the 'root' acceptor, otherwise the local fiber ID of the cloned connection
	uint32_t	expectedSN;	// the expected sequence number of the packet to receive by order
	//
	BackLogItem() { } // default constructor
	BackLogItem(const SConnectParam & v): SConnectParam(v) { }
	BackLogItem(ALFID_T id1, uint32_t salt1) { idRemote = id1; salt = salt1; } 
};



class CLightMutex
{
	volatile char		mutex;
public:
	bool WaitSetMutex();
	void SetMutexFree() { _InterlockedExchange8(&mutex, 0); }
};



class LLSNotice: public CLightMutex
{
	friend struct ControlBlock;
	// volatile char	mutex;	// in CLightMutex
protected:
	// 4: The (very short, roll-out) queue of returned notices
	FSP_ServiceCode q[FSP_MAX_NUM_NOTICE];
public:
	void SetHead(FSP_ServiceCode c) { q[0] = c; }
	FSP_ServiceCode GetHead() { return q[0]; }
	// put a new notice at the tail of the queue
	int LOCALAPI	Put(FSP_ServiceCode);
	// pop the notice from the top
	FSP_ServiceCode Pop();
};



class LLSBackLog: public CLightMutex
{
	friend struct ControlBlock;

	ALIGN(8)
	int32_t				capacity;
	volatile int32_t	headQ;
	volatile int32_t	tailQ;
	volatile int32_t	count;
	//
	ALIGN(8)
	BackLogItem			q[MIN_QUEUED_INTR];
	//
	void InitSize() { capacity = MIN_QUEUED_INTR; }	// assume memory has been zeroed
	int	InitSize(int);

public:
	BackLogItem * LOCALAPI FindByRemoteId(ALFID_T, uint32_t);
	bool Has(const BackLogItem *p) { return FindByRemoteId(p->idRemote, p->salt) != NULL; }
	BackLogItem * Peek() { return count <= 0 ? NULL : q  + headQ; }
	int Pop();
	int LOCALAPI Put(const BackLogItem *p);
};



class CSocketItem;	// forward declaration for sake of declaring ControlBlock



/**
 * Session Control Block is meant to be shared by LLS and DLL.
 * Shall be prefixed with 'volatile' if LLS is implemented in hardware
 */

// It heavily depends on Address Space Layout Randomization and user-space memory segment isolation
// or similar measures to protect sensitive information, integrity and privacy, of user process
struct ControlBlock
{
	ALIGN(8)
	FSP_Session_State	state;
	char			milky : 1;		// by default 0: a normal wine-style payload assumed. FIFO
	char			noEncrypt : 1;	// by default 0; 1 if session key installed, encrypt the payload
	//
	ALFID_T			idParent;

	// 1, 2. 
	// The matched list of local and remote addresses is cached in LLS
	// canonical name of the near end and the remote end,
	// the initial address and interface of the near end, and the dynamic addresses of the remote end
	char			nearEndName[256];	// RFC1035, maximum length of a full domain name is 253 octets. Add padding zeroes
	FSP_ADDRINFO_EX	nearEndInfo;
	struct
	{
		char		name[256];
		struct
		{
			TSubnets	allowedPrefixes;
			uint32_t	hostID;
			ALFID_T		fiberID;
		} ipFSP;
	} peerAddr;

	// 3: The negotiated connection parameter
	ALIGN(8)	// 64-bit alignment, make sure that the session key overlays 'initCheckCode' and 'cookie' only
	SConnectParam connectParams;

	// 3+: Performance profiling counts
	CSocketPerformance perfCounts;

	// 4: The queue of returned notices
	LLSNotice	notices;
	// Backlog for listening/connected socket [for client it could be an alternate of Web Socket]
	LLSBackLog	backLog;

	// 5, 6: Send window and receive window descriptor
	typedef uint32_t seq_t;

	//
	// BEGIN REGION: buffer descriptors 
	//
	// (head position, send window first sn), (send window next position, send window next sequence number)
	// and (buffer next position, send buffer next sequence number) are managed independently
	// for maximum parallelism in DLL and LLS
	// the send queue is empty when sendWindowFirstSN == sendWindowNextSN
	seq_t		sendWindowFirstSN;	// left-border of the send window
	int32_t		sendWindowHeadPos;	// the index number of the block with sendWindowFirstSN
	seq_t		sendWindowNextSN;	// the sequence number of the next packet to send
	int32_t		sendWindowNextPos;	// the index number of the block with sendWindowNextSN
	seq_t		sendBufferNextSN;
	int32_t		sendBufferNextPos;	// the index number of the block with sendBufferNextSN
	//
	seq_t		sendWindowLimitSN;	// the right edge of the send window

	// (head position, receive window first sn) (next position, receive buffer maximum sn)
	// are managed independently for maximum parallelism in DLL and LLS
	// the receive queue is empty when recvWindowFirstSN == recvWindowNextSN
	seq_t		recvWindowFirstSN;	// left-border of the receive window (receive queue), may be empty or may be filled but not delivered
	int32_t		recvWindowHeadPos;	// the index number of the block with recvWindowFirstSN
	seq_t		recvWindowNextSN;	// the next to the right-border of the received area
	int32_t		recvWindowNextPos;	// the index number of the block with recvWindowNextSN
	//
	seq_t		recvWindowExpectedSN;
	//
	int32_t		sendBufferBlockN;	// capacity of the send buffer in blocks
	int32_t		recvBufferBlockN;	// capacity of the receive buffer

	int32_t		sendBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		recvBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		sendBuffer;			// relative to start of the control block
	int32_t		recvBuffer;			// relative to start of the control block

	// note that we reuse ACKED (for send), hidden DELIVERED (for receive) 
	enum FSP_SocketBufMark : char
	{
		FSP_BUF_LOCKED = 1,
		FSP_BUF_COMPLETE = 2,
		FSP_BUF_SENT = 4,
		FSP_BUF_ACKED = 8,
		FSP_BUF_RESENT = 16,
	};
	// Total size of FSP_SocketBuf (descriptor): 8 bytes (a 64-bit word)
	typedef struct FSP_SocketBuf
	{
		union
		{
			timestamp_t	timeSent;
			timestamp_t timeRecv;
		};
		int32_t		len;
		char		marks;
		octet		flags;
		uint8_t		version;	// should be the same as in the FSP fixed header
		FSPOperationCode opCode;// should be the same as in the FSP fixed header
		//
		void InitMarkLocked() { _InterlockedExchange8(&marks, FSP_BUF_LOCKED); }
		void ReInitMarkComplete() { _InterlockedExchange8(&marks, FSP_BUF_COMPLETE); }
		void ReInitMarkAcked() { _InterlockedExchange8(&marks, FSP_BUF_ACKED); }
		void ReInitMarkDelivered() { ReInitMarkAcked(); }

		void MarkSent() { _InterlockedOr8(&marks, FSP_BUF_SENT); }
		void MarkAcked() { _InterlockedOr8(&marks, FSP_BUF_ACKED); }
		void MarkResent() { _InterlockedOr8(&marks, FSP_BUF_RESENT); }

		bool InSending() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_SENT) != 0; }
		bool IsComplete() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_COMPLETE) != 0; }
		bool IsAcked() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_ACKED) != 0; }
		bool IsDelivered() { return IsAcked(); }
		bool IsResent() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_RESENT) != 0; }
		//
		void ClearFlags() { _InterlockedExchange8((char *)&flags, 0); }
		template<FSP_FlagPosition pos> void InitFlags() { _InterlockedExchange8((char *)&flags, (char)(1 << pos)); }
		template<FSP_FlagPosition pos> void SetFlag() { _InterlockedExchange8((char *)&flags, flags | (char)(1 << pos)); }
		template<FSP_FlagPosition pos> bool GetFlag() { return (_InterlockedOr8((char *)&flags, 0) & (char)(1 << pos)) != 0; }
		void CopyFlagsTo(FSP_NormalPacketHeader *p) { _InterlockedExchange8((char *)p->flags_ws, flags); }
		void CopyInFlags(const FSP_NormalPacketHeader *p) { _InterlockedExchange8((char *)& flags, p->flags_ws[0]); }
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
		offset = sendBuffer + MAX_BLOCK_SIZE * uint32_t(skb - p0);
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
		offset = recvBuffer + MAX_BLOCK_SIZE * uint32_t(skb - p0);
		return (BYTE *)this + offset;
	}

	// 7, 8 Send buffer and Receive buffer
	// See ControlBlock::Init()

	//
	int32_t CountSendBuffered()
	{
		register int32_t a = LCKREAD(sendBufferNextSN);
		return int32_t(a - LCKREAD(sendWindowFirstSN));
	}
	int32_t CountSentInFlight()
	{
		register int32_t a = LCKREAD(sendWindowNextSN);
		return int32_t(a - LCKREAD(sendWindowFirstSN));
	}
	seq_t GetSendLimitSN()
	{
		register int32_t a = LCKREAD(sendBufferNextSN);
		return int32_t(a - sendWindowLimitSN) > 0 ? sendWindowLimitSN : a;
	}

	int32_t CountDeliverable()
	{
		register int32_t a = LCKREAD(recvWindowExpectedSN);
		return int32_t(a - recvWindowFirstSN);
	}
#if defined(TRACE) && !defined(NDEBUG)
	int DumpSendRecvWindowInfo() const;
	int DumpRecvQueueInfo() const;
#else
	int DumpSendRecvWindowInfo() const { return 0; }
	int DumpRecvQueueInfo() const { return 0; }
#endif

	PFSP_SocketBuf HeadSend() const { return (PFSP_SocketBuf)((BYTE *)this + sendBufDescriptors); }
	PFSP_SocketBuf HeadRecv() const { return (PFSP_SocketBuf)((BYTE *)this + recvBufDescriptors); }

	// Return the head packet even if the send queue is empty
	PFSP_SocketBuf GetSendQueueHead() { return HeadSend() + sendWindowHeadPos; }
	// Return the head packet even if the receive buffer is thoroughly free
	PFSP_SocketBuf GetFirstReceived() { return HeadRecv() + recvWindowHeadPos; }

	// Given that the caller has made sure the queue is not empty, return the last packet of the send queue
	PFSP_SocketBuf GetLastBuffered()
	{
		register int32_t i = LCKREAD(sendBufferNextPos) - 1;
		return (HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i));
	}

	// Take snapshot of the right edge of the receive window, typically on transmit transaction committed
	void SnapshotReceiveWindowRightEdge() { connectParams.nextKey$initialSN = recvWindowNextSN; }

	// Allocate a new send buffer
	PFSP_SocketBuf	GetSendBuf();

	// Assume followed by interlocked/memory-barrier operation 
	void AddRoundRecvBlockN(int32_t & tgt, int32_t a) { tgt += a; if (tgt >= recvBufferBlockN) tgt -= recvBufferBlockN; }
	void AddRoundSendBlockN(int32_t & tgt, int32_t a) { tgt += a; if (tgt >= sendBufferBlockN) tgt -= sendBufferBlockN; }
	// 
	void IncRoundRecvBlockN(int32_t & tgt)
	{
		register int32_t a = InterlockedIncrement((LONG *)&tgt) - recvBufferBlockN;
		if (a >= 0) InterlockedExchange((LONG *)&tgt, a);
	}
	void IncRoundSendBlockN(int32_t & tgt)
	{
		register int32_t a = InterlockedIncrement((LONG *)&tgt) - sendBufferBlockN;
		if (a >= 0) InterlockedExchange((LONG *)&tgt, a);
	}
	// Set the right edge of the send window after the very first packet of the queue is sent
	void SetFirstSendWindowRightEdge()
	{
		register seq_t k = LCKREAD(sendWindowFirstSN);
		if (InterlockedCompareExchange(&sendWindowNextSN, k + 1, k) == k)
			IncRoundSendBlockN(sendWindowNextPos);
	}

	BYTE * LOCALAPI InquireSendBuf(int32_t *);

	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int);
	int LOCALAPI DealWithSNACK(seq_t, FSP_SelectiveNACK::GapDescriptor *, int);

	// Return the locked descriptor of the receive buffer block with the given sequence number
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);

	// Slide the left border of the receive window by one slot
	void SlideRecvWindowByOne()	// shall be atomic!
	{
		IncRoundRecvBlockN(recvWindowHeadPos);
		InterlockedIncrement((LONG *)& recvWindowFirstSN);
	}

	// Given
	//	int32_t & : [_Out_] place holder of the number of bytes [to be] peeked
	//	int32_t & : [_Out_] place holder of the number of blocks peeked
	//	bool &: [_Out_] place holder of the End of Transaction flag
	// Return
	//	Start address of the received message
	// Remark
	//	Would automatically mark the packet peeked as delivered, but would not slide the receive window
	octet* LOCALAPI InquireRecvBuf(int32_t&, int32_t&, bool&);

	// Given
	//	int32_t				the number of blocks peeked and to be free
	// Return
	//	non-negative if succeeded,
	//	negative if error occurred
	int	LOCALAPI MarkReceivedFree(int32_t);

	void SetRecvWindow(seq_t pktSeqNo)
	{
		recvWindowExpectedSN = recvWindowNextSN = recvWindowFirstSN = pktSeqNo;
		recvWindowHeadPos = recvWindowNextPos = 0;
	}
	void SetSendWindow(seq_t initialSN)
	{
		sendBufferNextSN = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextPos = sendWindowNextPos = sendWindowHeadPos = 0;
		sendWindowLimitSN = initialSN + 1;	// for the protocol to work it should allow at least one packet in flight
	}

	// Whether both the End of Transaction flag is received and there is no receiving gap left
	bool HasBeenCommitted();

	// Slide the send window to skip the head slot, supposing that it has been acknowledged
	void SlideSendWindowByOne()
	{
		PFSP_SocketBuf skb = GetSendQueueHead();
		skb->ReInitMarkAcked();
		// but preserve packet flags for possible later reference to EoT, etc.
		IncRoundSendBlockN(sendWindowHeadPos);
		InterlockedIncrement(&sendWindowFirstSN);
	}

	// Return the advertisable size of the receive window
	int32_t GetAdvertisableRecvWin() { return int32_t(LCKREAD(recvWindowFirstSN) + recvBufferBlockN - recvWindowExpectedSN); }

	// Given
	//	ControlBlock::seq_t	The sequence number of the packet that mostly expected by the remote end
	//	unsigned int		The advertised size of the receive window, start from aforementioned most expected packet
	// Do
	//	Adjust the size of the send window size of the near end
	// Remark
	//	Assume the parameters is legitimate, shall call this function only after ICC has been validated
	void ResizeSendWindow(seq_t seq1, uint32_t adRecvWin)
	{
		seq_t seqL = seq1 + adRecvWin;
		if (int32_t(seqL - sendWindowLimitSN) > 0)
			sendWindowLimitSN = seqL;
	}

	bool HasBacklog() const { return backLog.count > 0; }

	int LOCALAPI	Init(int32_t &, int32_t &);
	int	LOCALAPI	Init(uint16_t);
};

#include <poppack.h>



class CSocketItem
{
protected:
	ALFIDPair	fidPair;
	HANDLE	hEvent;
	HANDLE	hMemoryMap;
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	ControlBlock *pControlBlock;

	//virtual ~CSocketItem() { }	// Make this a semi-abstract class
	void Destroy()
	{
		register HANDLE h;
		//
		if ((h = InterlockedExchangePointer((PVOID *)& pControlBlock, NULL)) != NULL)
			::UnmapViewOfFile(h);
		if ((h = InterlockedExchangePointer((PVOID *)& hMemoryMap, NULL)) != NULL)
			::CloseHandle(h);
		if((h = InterlockedExchangePointer((PVOID *) & hEvent, NULL)) != NULL)
			::CloseHandle(h);
	}
};

#endif
