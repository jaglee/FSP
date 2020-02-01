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

#include "FSP.h"

/**
 * Implementation defined timeout
 */

#if defined(__WINDOWS__)

# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <ws2tcpip.h>
# include <mswsock.h>

# define _CRT_RAND_S
# define REVERSE_EVENT_PREFIX	"Global\\FlexibleSessionProtocolEvent"
# define SERVICE_MAILSLOT_NAME	"\\\\.\\mailslot\\flexible\\session\\protocol"

# ifdef TRACE
   void TraceLastError(const char * fileName, int lineNo, const char *funcName, const char *s1);
#  define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCTION__, "ERROR REPORT")
#  define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCTION__, (s1))
# endif

# ifdef _DEBUG
#  define DEINIT_WAIT_TIMEOUT_ms		15000	// 15 seconds
#  define BREAK_ON_DEBUG()			DebugBreak()
# else
#  define DEINIT_WAIT_TIMEOUT_ms		5000	// 5 seconds
#  define BREAK_ON_DEBUG()
# endif

# define MAX_LOCK_WAIT_ms			60000	// one minute
# define TIMER_SLICE_ms				5

# if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#  define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
# else
#  define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
# endif

typedef DWORD	pid_t;
typedef HANDLE	timer_t;

# ifdef __MINGW32__
# define IN4ADDR_LOOPBACK 0x0100007F	// Works for x86 little-endian
# define max(a,b)	((a) >= (b) ? (a) : (b))
# define min(a,b)	((a) <= (b) ? (a) : (b))

ALIGN(sizeof(uint64_t))
const struct { octet u[8]; } in6addr_linklocalprefix = { { 0xFE, 0x80, 00, 00, 00, 00, 00, 00 } };

// GetTickCount64() is availabe after Windows Vista (inclusively)
static inline uint64_t GetTickCount64()
{
	FILETIME systemTime;
	GetSystemTimeAsFileTime(&systemTime);
	return *(uint64_t *)&systemTime / 10;
}

# else
class CSRWLock
{
protected:
	SRWLOCK rtSRWLock;	// runtime Slim-Read-Write Lock
	void InitMutex() { InitializeSRWLock(&rtSRWLock); }
# if defined(_DEBUG)
	void AcquireMutex()
	{
		uint64_t t0 = GetTickCount64();
		while (!TryAcquireSRWLockExclusive(&rtSRWLock))
		{
			if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			{
				BREAK_ON_DEBUG();	// To trace the call stack
				throw - EDEADLK;
			}
			Sleep(TIMER_SLICE_ms);	// if there is some thread that has exclusive access on the lock, wait patiently
		}
	}
# else
	void AcquireMutex() { AcquireSRWLockExclusive(&rtSRWLock); }
# endif
	void ReleaseMutex() { ReleaseSRWLockExclusive(& rtSRWLock); }
};
# endif

#elif defined(__linux__) || defined(__CYGWIN__)

# include <arpa/inet.h>
# include <errno.h>
# include <fcntl.h>
# include <mqueue.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip6.h>
# include <pthread.h>
# include <signal.h>
# include <sys/mman.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <sys/time.h>
# include <sys/types.h>
# include <time.h>
# include <unistd.h>

# define BREAK_ON_DEBUG()
# define DEINIT_WAIT_TIMEOUT_ms		5000	// 5 seconds

# define MAX_LOCK_WAIT_ms			30000	// half a minute
# define TIMER_SLICE_ms				1		// For HPET

# define INVALID_SOCKET	(-1)
# define SIGNO_FSP		SIGRTMIN

# define max(a,b)	((a) >= (b) ? (a) : (b))
# define min(a,b)	((a) <= (b) ? (a) : (b))

# define printf_s	printf // but printf_s is defined in C11?
# define _strnicmp strncasecmp

# define SHARE_MEMORY_PREFIX	"/FlexibleSessionProtocolSHM"
# define SERVICE_MAILSLOT_NAME	"/FlexibleSessionProtocolMailQueue"

# ifdef TRACE
#  define REPORT_ERROR_ON_TRACE()		perror("ERROR REPORT")
#  define REPORT_ERRMSG_ON_TRACE(s1)	perror(s1)
# endif

typedef int32_t	DWORD;
typedef void*	PVOID;

typedef struct addrinfo*	PADDRINFOA;
typedef struct in6_addr		IN6_ADDR, *PIN6_ADDR;
typedef struct sockaddr_in  SOCKADDR_IN, *PSOCKADDR_IN;
typedef struct sockaddr_in6 SOCKADDR_IN6, *PSOCKADDR_IN6;

typedef union _SOCKADDR_INET {
	struct sockaddr_in	Ipv4;
	struct sockaddr_in6 Ipv6;
	sa_family_t			si_family;
}	SOCKADDR_INET, * PSOCKADDR_INET;


static inline uint64_t GetTickCount64()
{
	timespec v;
	clock_gettime(CLOCK_MONOTONIC, &v);
	return (v.tv_sec * 1000 + v.tv_nsec / 1000);
}

static inline void Sleep(int32_t millis)
{
    struct timespec tv;
    tv.tv_sec = millis / 1000;
    tv.tv_nsec = (millis % 1000) * 1000000;
    nanosleep(&tv, NULL);
}

class CSRWLock
{
protected:
	pthread_rwlock_t  rtSRWLock;
	void InitMutex() { rtSRWLock = PTHREAD_RWLOCK_INITIALIZER; }
	void AcquireMutex() { pthread_rwlock_wrlock(&rtSRWLock); }
	void ReleaseMutex() { pthread_rwlock_unlock(&rtSRWLock); }
};

#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define FSP_ALIGNMENT	8
#define	MAC_ALIGNMENT	16

/**
 * For testability
 */
#ifndef TRACE
# define REPORT_ERROR_ON_TRACE()
# define REPORT_ERRMSG_ON_TRACE(s) (s)
#endif

// Bit 0 is reserved for 'true'
#define TRACE_HEARTBEAT	2
#define TRACE_PACKET	4
#define TRACE_SLIDEWIN	8
#define TRACE_ULACALL	16
#define TRACE_OUTBAND	32	// Other than KEEP_ALIVE
// Bit 6 is reserved
#define TRACE_ADDRESS	128


/**
 * IPC
 */
#define MAX_CTRLBUF_LEN		424	// maximum message passing structure/mailslot size
#define MAX_NAME_LENGTH		64	// considerably less than MAX_PATH

#ifdef _DEBUG
#define	CONNECT_BACKLOG_SIZE	2
#else
#define	CONNECT_BACKLOG_SIZE	512
#endif


#define	MAX_IDLE_QUOTA_TICKS		6		// Refuse to add quota if sending is idle more than this threshold
#define SLOW_START_WINDOW_SIZE		4		// in packet


/**
 * Implemented system limit
 */
#ifndef OVER_UDP_IPv4
// IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater. 
# define MAX_BLOCK_SIZE		1024
#else
# define MAX_BLOCK_SIZE		512
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

// Reflexing string representation of FSP_Session_State, for debug purpose
class CStringizeState
{
	static const char * names[LARGEST_FSP_STATE + 1];
public:
	const char * operator[](int);
};

// Reflexing string representation of FSP_ServiceCode, for debug purpose
class CServiceCode
{
	static const char* names[FSP_Shutdown + 1];
public:
	static const char* sof(int);
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
 * Parameter data-structure and Session Control Block data-structure
 */
#if defined(_MSC_VER)
# define LOCALAPI __fastcall
# include <pshpack1.h>
#else
# define LOCALAPI
# pragma pack(push)
# pragma pack(1)
#endif

// Network byte order of the length of the fixed header, where host byte order is little-endian
#define	FIXED_HEADER_SIZE_BE16		0x1800

// ARM/x86 byte order of the length of the extension header, where host byte order is little-endian
#define CONNECT_PARAM_LENGTH_LE16	0x0028
#define SNACK_HEADER_SIZE_LE16		0x0010


// Set the prefix of FSP_ConnectParam content
#define SetConnectParamPrefix(hdr)	{	\
	(hdr)._h.opCode = PEER_SUBNETS;		\
	(hdr)._h.mark = 0;					\
	(hdr)._h.length = CONNECT_PARAM_LENGTH_LE16; \
}

#define SetHeaderSignature(hdr, code) {	\
	(hdr).hs.opCode = (code);			\
	(hdr).hs.major = THIS_FSP_VERSION;	\
	(hdr).hs.offset = FIXED_HEADER_SIZE_BE16;	\
	}


class CSocketItem;	// forward declaration for sake of declaring CommandToLLS and ControlBlock


/**
 * Command to lower layer service
 * Try to make a 32-bit process calling the 64-bit FSP lower-level service possible
 * by exploiting POST-FIX(!) ALIGN(8)
 * Feasible in a little-endian CPU, provided that the structure is pre-zeroed
 */
struct CommandToLLS
{
	ALIGN(8)
	pid_t			idProcess;
	ALFID_T			fiberID;
	FSP_ServiceCode	opCode;	// operation code
};



struct CommandNewSession: CommandToLLS
{
	uint32_t		dwMemorySize;	// size of the shared memory, in the mapped view
#if defined(__WINDOWS__)
	char			szEventName[MAX_NAME_LENGTH];	// name of the callback event
	uint64_t		hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
#elif defined(__linux__) || defined(__CYGWIN__)
	char			shm_name[MAX_NAME_LENGTH + 8];	// name of the shared memory
	void GetShmNameFrom(CSocketItem *p) { sprintf(shm_name, SHARE_MEMORY_PREFIX "%p", (void *)p); }
#endif

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
	void InitUDPoverIPv4(u32 if1)
	{
		memset(this, 0, sizeof(FSP_SINKINF));		// inaddr_any
		ipi_ifindex = if1;
		cmsg_level = IPPROTO_IP;	/* originating protocol */
	}
	//
	void InitNativeIPv6(u32 if1)
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
	union
	{
	octet		padding[8];	// allow maximum key length of 384-bit, padding the structure to 64 bytes/512bits
		octet	tag[FSP_TAG_SIZE];
		int64_t	tDiff;
	};

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
	char mutex;
public:
	bool WaitSetMutex();
	void SetMutexFree() { _InterlockedExchange8(&mutex, 0); }
};

#ifdef __MINGW32__
class CSRWLock: CLightMutex
{
protected:
	void InitMutex() { /* constructed */ }
	void AcquireMutex() { WaitSetMutex(); }
	void ReleaseMutex() { SetMutexFree(); }
};
#endif

// 4: The soft interrupt vector of returned notices
struct LLSNotice
{
	volatile char 	nmi;
	long			vector;
	void SetHead(FSP_NoticeCode c) { nmi = (char )c; }
	// It is inline in the LLS to set the soft interrupt signal, for sake of performance
	// It is inline in the DLL to fetch the soft interrupt signal, for sake of performance and balance
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
	char			tfrc : 1;		// TCP friendly rate control. By default ECN-friendly
	char			milky : 1;		// by default 0: a normal wine-style payload assumed. FIFO
	char			noEncrypt : 1;	// by default 0; 1 if session key installed, encrypt the payload
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

	enum FSP_SocketBufMark : char
	{
		FSP_BUF_LOCKED = 1,
		FSP_BUF_COMPLETE = 2,
		FSP_BUF_SENT = 4,
		FSP_BUF_ACKED = 8,
		FSP_BUF_RESENT = 16,
		FSP_BUF_DELIVERED = 8,	// FSP_BUF_ACKED reused for single send and receive
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
		void ReInitMarkDelivered() { _InterlockedExchange8(&marks, FSP_BUF_DELIVERED); }

		void MarkSent() { _InterlockedOr8(&marks, FSP_BUF_SENT); }
		void MarkResent() { _InterlockedOr8(&marks, FSP_BUF_RESENT); }

		bool IsComplete() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_COMPLETE) != 0; }
		bool IsDelivered() { return (_InterlockedOr8(&marks, 0) & FSP_BUF_DELIVERED) != 0; }

		bool MayNotSend() { return (_InterlockedOr8(&marks, 0) & (FSP_BUF_COMPLETE | FSP_BUF_SENT)) != FSP_BUF_COMPLETE; }

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
	octet* GetSendPtr(const PFSP_SocketBuf skb)
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((octet*)this + sendBufDescriptors);
		long offset = sendBuffer + MAX_BLOCK_SIZE * long(skb - p0);
		return (octet*)this + offset;
	}
	octet* GetSendPtr(const ControlBlock::PFSP_SocketBuf skb, long& offset)
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((octet*)this + sendBufDescriptors);
		offset = sendBuffer + MAX_BLOCK_SIZE * long(skb - p0);
		return (octet*)this + offset;
	}

	octet* GetRecvPtr(const PFSP_SocketBuf skb) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((octet*)this + recvBufDescriptors);
		long offset = recvBuffer + MAX_BLOCK_SIZE * long(skb - p0);
		return (octet*)this + offset;
	}
	octet* GetRecvPtr(const ControlBlock::PFSP_SocketBuf skb, long& offset) const
	{
		PFSP_SocketBuf p0 = PFSP_SocketBuf((octet*)this + recvBufDescriptors);
		offset = recvBuffer + MAX_BLOCK_SIZE * long(skb - p0);
		return (octet*)this + offset;
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

	PFSP_SocketBuf HeadSend() const { return (PFSP_SocketBuf)((octet*)this + sendBufDescriptors); }
	PFSP_SocketBuf HeadRecv() const { return (PFSP_SocketBuf)((octet*)this + recvBufDescriptors); }

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
		register int32_t a = _InterlockedIncrement((PLONG)&tgt) - recvBufferBlockN;
		if (a >= 0) _InterlockedExchange((PLONG)&tgt, a);
	}
	void IncRoundSendBlockN(int32_t & tgt)
	{
		register int32_t a = _InterlockedIncrement((PLONG)&tgt) - sendBufferBlockN;
		if (a >= 0) _InterlockedExchange((PLONG)&tgt, a);
	}
	// Set the right edge of the send window after the very first packet of the queue is sent
	void SetFirstSendWindowRightEdge()
	{
		register seq_t k = LCKREAD(sendWindowFirstSN);
		if ((seq_t)_InterlockedCompareExchange((PLONG)&sendWindowNextSN, k + 1, k) == k)
			IncRoundSendBlockN(sendWindowNextPos);
	}
	octet* LOCALAPI InquireSendBuf(int32_t *);

	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int);
	int LOCALAPI DealWithSNACK(seq_t, FSP_SelectiveNACK::GapDescriptor *, int);

	// Return the locked descriptor of the receive buffer block with the given sequence number
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);

	// Slide the left border of the receive window by one slot
	void SlideRecvWindowByOne()	// shall be atomic!
	{
		IncRoundRecvBlockN(recvWindowHeadPos);
		_InterlockedIncrement((PLONG)&recvWindowFirstSN);
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
		_InterlockedIncrement((PLONG)&sendWindowFirstSN);
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

#if defined(_MSC_VER)
# include <poppack.h>
#else
# pragma pack(pop)
#endif


class CSocketItem
{
protected:
	ALIGN(FSP_ALIGNMENT)
	ALFIDPair	fidPair;
#if defined(__WINDOWS__)
	HANDLE	hEvent;
	HANDLE	hMemoryMap;
// #elif defined(__linux__) || defined(__CYGWIN__)
#endif
	// size of the shared memory, in the mapped view. This implementation make it less than 2GB:
	int32_t	dwMemorySize;
	ControlBlock *pControlBlock;

#if defined(__WINDOWS__)
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
#elif defined(__linux__) || defined(__CYGWIN__)
	void Destroy()
	{
		register void *buf;
		if ((buf =  _InterlockedExchangePointer((PVOID *)& pControlBlock, NULL)) != NULL)
			munmap(buf, dwMemorySize);
	}
#endif
};

#endif

