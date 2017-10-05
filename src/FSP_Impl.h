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

#include "Intrins.h"

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
# define SCAVENGE_THRESHOLD_ms		180000	// 3 minutes
# define LAZY_ACK_DELAY_MIN_ms		100		// 100 millisecond, minimum delay for lazy acknowledgement
# define BREAK_ON_DEBUG()			DebugBreak()
#else
# define DEINIT_WAIT_TIMEOUT_ms		5000	// 5 seconds
# define SCAVENGE_THRESHOLD_ms		1800000	// 30 minutes
# define LAZY_ACK_DELAY_MIN_ms		1		// 1 millisecond, minimum delay for lazy acknowledgement
# define BREAK_ON_DEBUG()
#endif


#define MAX_LOCK_WAIT_ms			60000	// one minute
#define TIMER_SLICE_ms				50		// 1/20 second
#define	TIMEOUT_RETRY_MAX_COUNT		5


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



struct CommandInstallKey : CommandToLLS
{
	uint32_t	nextSendSN;	// ControlBlock::seq_t
	uint64_t	keyLife;
	CommandInstallKey(uint32_t seq1, uint64_t v) { nextSendSN = seq1; keyLife = v; }
};



struct CommandCloneConnect : CommandNewSession
{
	ALIGN(4)
	char		isFlushing;
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
	// the first 3 fields, together with initialSN, are to be initiaized with random value
	uint64_t	initCheckCode;
	uint64_t	cookie;
	uint32_t	salt;
	int32_t		timeDelta;	// delay of peer to peer timestamp, delta of clock 
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
	uint64_t	allowedPrefixes[MAX_PHY_INTERFACES];
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
	void InitSize() { capacity = MIN_QUEUED_INTR; }	// assume memory has been zeroized
	int	InitSize(int);

public:
	bool LOCALAPI Has(const BackLogItem *p);
	BackLogItem * Peek() { return count <= 0 ? NULL : q  + headQ; }
	int Pop();
	int LOCALAPI Put(const BackLogItem *p);
};




// Name of the flags for protocol use are in camel-case.
// The flags for internal buffering are in upper case
// 0~7 : reserved for protocol use. See also enum FSP_FlagPosition
enum: uint8_t
{
	EXCLUSIVE_LOCK = 8,
	IS_ACKNOWLEDGED = 9,
	IS_COMPLETED = 10,
	IS_SENT = 11,
	IS_FULFILLED = IS_COMPLETED,// mutual-mirroring flags for send and receive
};



class CSocketItem;	// forward declaration for sake of declaring ControlBlock


/**
 * Session Control Block is meant to be shared by LLS and DLL.
 * Shall be prefixed with 'volatile' if LLS is implemented in hardware
 */

// It heavily depends on Address Space Layout Randomization and user-space memory segment isolation
// or similar measures to pretect sensive information, integrity and privacy, of user process
struct ControlBlock
{
	ALIGN(8)
	FSP_Session_State state;
	char			_reserved1;
	char			_reserved2;
	char			milky :		1;		// by default 0: a normal wine-style payload assumed. FIFO
	char			noEncrypt:	1;		// by default 0: if install session key, encrypt the payload
	//
	ALFID_T			idParent;

	ALIGN(8)	// 64-bit aligment
	FSP_NormalPacketHeader tmpHeader;	// for sending; assume sending is single-threaded for a single session

	// 1, 2.
	// Used to be the matched list of local and remote addresses.
	// for security reason the remote addresses were moved to LLS
	char			nearEndName[INET6_ADDRSTRLEN + 7];	// 72 bytes, in UTF-8
	FSP_ADDRINFO_EX	nearEndInfo;
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
	int32_t		sendWindowLimitSN;	// the right edge of the send window
	int32_t		sendCongestWindow;	// UNRESOLVED! Reserved yet.

	// (head position, receive window first sn) (next position, receive buffer maximum sn)
	// are managed independently for maximum parallism in DLL and LLS
	// the receive queue is empty when recvWindowFirstSN == recvWindowNextSN
	seq_t		recvWindowFirstSN;	// left-border of the receive window (receive queue), may be empty or may be filled but not delivered
	int32_t		recvWindowHeadPos;	// the index number of the block with recvWindowFirstSN
	seq_t		recvWindowNextSN;	// the next to the right-border of the received area
	int32_t		recvWindowNextPos;	// the index number of the block with recvWindowNextSN
	//
	seq_t		welcomedNextSNtoSend;
	seq_t		recvWindowExpectedSN;
	//
	int32_t		sendBufferBlockN;	// capacity of the send buffer in blocks
	int32_t		recvBufferBlockN;	// capacity of the receive buffer

	int32_t		sendBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		recvBufDescriptors;	// relative to start of the control block, may be updated via memory map
	int32_t		sendBuffer;			// relative to start of the control block
	int32_t		recvBuffer;			// relative to start of the control block

	// Total size of FSP_SocketBuf (descriptor): 8 bytes (a 64-bit word)
	typedef struct FSP_SocketBuf
	{
		timestamp_t	timeSent;
		int32_t		len;
		uint16_t	flags;
		uint8_t		version;	// should be the same as in the FSP fixed header
		FSPOperationCode opCode;// should be the same as in the FSP fixed header
		//
#if ARCH_BIG_ENDIAN
		template<uint8_t i>
		bool SetFlag(bool value = true)
		{
			return (value
				? InterlockedBitTestAndSet((LONG *) & flags, i + 16) 
				: InterlockedBitTestAndReset((LONG *) & flags, i + 16)
				) != 0;
		}
		template<uint8_t i>
		bool GetFlag() { return BitTest((LONG *) & flags, i + 16) != 0; }
#else
		template<uint8_t i>
		bool SetFlag(bool value = true)
		{
			return (value
				? InterlockedBitTestAndSet((LONG *) & flags, i) 
				: InterlockedBitTestAndReset((LONG *) & flags, i)
				) != 0;
		}
		//
		template<uint8_t i>
		bool GetFlag() { return BitTest((LONG *) & flags, i) != 0; }
#endif
		bool Lock()	{ return ! SetFlag<EXCLUSIVE_LOCK>(); }
		void Unlock() { SetFlag<EXCLUSIVE_LOCK>(false); }
		//
		void InitFlags() { _InterlockedExchange16((SHORT *) & flags, 1 << EXCLUSIVE_LOCK); }
		void CopyFlagsTo(FSP_NormalPacketHeader *p) { p->flags_ws[0]  = (uint8_t)flags; }
		void CopyInFlags(const FSP_NormalPacketHeader *p) { _InterlockedExchange8((char *) & flags, p->flags_ws[0]); }
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
	int32_t CountSendBuffered()
	{
		register int32_t a, b;
		a = _InterlockedOr((volatile LONG *)&sendBufferNextSN, 0);
		b = _InterlockedOr((volatile LONG *)&sendWindowFirstSN, 0);
		return a - b;
	}
	int32_t CountSentInFlight()
	{
		register int32_t a, b;
		a = _InterlockedOr((volatile LONG *)&sendWindowNextSN, 0);
		b = _InterlockedOr((volatile LONG *)&sendWindowFirstSN, 0);
		return a - b;
	}
#if defined(TRACE) && !defined(NDEBUG)
	int DumpSendRecvWindowInfo() const;
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
	PFSP_SocketBuf LockLastBufferedSend()
	{
		register int i = _InterlockedOr((volatile LONG *)&sendBufferNextPos, 0);
		i--;
		register PFSP_SocketBuf p = HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i);
		if(! p->Lock())
			return NULL;
		// An invalid packet buffer might be locked
		return CountSendBuffered() <= 0 ? NULL : p;
	}

	// Return
	//	0 if used to be no packet at all
	//	1 if there existed a sent packet at the tail which has ready marked EOT 
	//	2 if there existed an unsent packet at the tail and it is marked EOT
	//  -1 if there existed a sent packet at the tail which could not be marked EOT
	int MarkSendQueueEOT();
	// Take snapshot of the right edge of the receive window, typically on transmit transaction committed
	void SnapshotReceiveWindowRightEdge() { connectParams.nextKey$initialSN = recvWindowNextSN; }

	// Allocate a new send buffer
	PFSP_SocketBuf	GetSendBuf();

	void RoundSendBufferNextPos() { int32_t m = sendBufferNextPos - sendBufferBlockN; if(m >= 0) sendBufferNextPos = m; }
	void RoundSendWindowNextPos() { int32_t m = sendWindowNextPos - sendBufferBlockN; if(m >= 0) sendWindowNextPos = m; }

	int32_t CountReceived() const { return int32_t(recvWindowNextSN - recvWindowFirstSN); }	// gaps included, however

	// Given
	//	FSP_NormalPacketHeader*	the place-holder of sequence number and flags
	//	ControlBlock::seq_t		the intent sequence number of the packet
	// Do
	//	Set the default sequence number, expected acknowledgment sequencenumber,
	//	flags and the advertised receive window size field of the FSP header 
	void LOCALAPI SetSequenceFlags(FSP_NormalPacketHeader *pHdr, ControlBlock::seq_t seq1)
	{
		pHdr->expectedSN = htobe32(recvWindowNextSN);
		pHdr->sequenceNo = htobe32(seq1);
		pHdr->ClearFlags();
		pHdr->SetRecvWS(AdRecvWS(recvWindowNextSN));
	}

	void * LOCALAPI InquireSendBuf(int32_t *);

	PFSP_SocketBuf GetFirstReceived()
	{
		register int32_t a = _InterlockedOr((volatile LONG *)& recvWindowHeadPos, 0);
		return HeadRecv() + a;
	}

	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int) const;
	int LOCALAPI DealWithSNACK(seq_t, FSP_SelectiveNACK::GapDescriptor *, int, timestamp_t &);

	// Return the locked descriptor of the receive buffer block with the given sequence number
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);

	// Slide the left border of the receive window by one slot
	void SlideRecvWindowByOne()	// shall be atomic!
	{
		if(++recvWindowHeadPos - recvBufferBlockN >= 0)
			recvWindowHeadPos -= recvBufferBlockN;
		InterlockedIncrement((LONG *) & recvWindowFirstSN);
	}

	// Given
	//	int & : [_Out_] place holder of the number of bytes [to be] peeked.
	//	bool &: [_Out_] place holder of the End of Transaction flag
	// Return
	//	Start address of the received message
	void * LOCALAPI InquireRecvBuf(int32_t &, bool &);
	// Given
	//	int :	the number of bytes peeked to be free
	// Return
	//	Number of blocks that were free
	int	LOCALAPI MarkReceivedFree(int32_t);

	void SetRecvWindow(seq_t pktSeqNo)
	{
		recvWindowExpectedSN = recvWindowNextSN = recvWindowFirstSN = pktSeqNo;
		recvWindowHeadPos = recvWindowNextPos = 0;
	}
	void SetSendWindow(seq_t initialSN)
	{
		welcomedNextSNtoSend = sendBufferNextSN = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextPos = sendWindowNextPos = sendWindowHeadPos = 0;
		sendWindowLimitSN = initialSN + 1;	// for the protocol to work it should allow at least one packet in flight
	}

	// Whether both the End of Transaction flag is received and there is no receiving gap left
	bool HasBeenCommitted() const;

	// Slide the send window to skip all of the acknowledged
	void SlideSendWindow();

	// Slide the send window to skip the head slot, supposing that it has been acknowledged
	void ControlBlock::SlideSendWindowByOne()
	{
		register int32_t a = _InterlockedIncrement((LONG *)& sendWindowHeadPos) - sendBufferBlockN;
		if (a >= 0)
			_InterlockedExchange((LONG *)& sendWindowHeadPos, a);
		//
		_InterlockedIncrement((LONG *)& sendWindowFirstSN);
	}

	// Set the right edge of the send window after the very first packet of the queue is sent
	void SetFirstSendWindowRightEdge()
	{
		seq_t k = sendWindowFirstSN;
		if(_InterlockedCompareExchange((LONG *) & sendWindowNextSN, k + 1, k) == k)
		{
			++sendWindowNextPos;
			RoundSendWindowNextPos();
		}
	}

	//
	bool LOCALAPI ResizeSendWindow(seq_t, unsigned int);

	// Width of the advertisable receive window (i.e. free receive buffers to advertize), in blocks
	int32_t AdRecvWS(seq_t expectedSN)
	{
		seq_t a = _InterlockedOr((LONG *) & recvWindowFirstSN, 0);
		return int32_t(a + recvBufferBlockN - expectedSN);
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
		if((h = InterlockedExchangePointer((PVOID *) & hEvent, NULL)) != NULL)
			::CloseHandle(h);
		//
		if((h = InterlockedExchangePointer((PVOID *) & hMemoryMap, NULL)) != NULL)
		{
			::UnmapViewOfFile(pControlBlock);
			::CloseHandle(h);
			pControlBlock = NULL;
		}
	}
};

#endif
