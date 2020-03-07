#ifndef _FSP_H_
#define _FSP_H_

/*
 * Flexible Session Protocol, implementation-independent definitions
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
#include "Intrins.h"

#define THIS_FSP_VERSION	0	// current version
#define IPPROTO_FSP			144	// value of protocol field for FSP over IPv6

#ifdef OVERLAY_DNS
# define OVER_UDP_IPv4
#endif

#define ARCH_BIG_ENDIAN		0	// by default it works for little-endian architecture

// Application Layer Fiber ID, the equivalent phrase is Upper Layer Thread ID
typedef uint32_t ALFID_T;
typedef ALFID_T	 ULTID_T;

// To reuse DNS port number 53: 0x35; network byte order 0x3500 === 13568
// ASCII code: 'F': 0x46 'S': 0x53; host byte order 0x4653 === 18003
#if ARCH_BIG_ENDIAN
// in network byte order on a big-endian host
#define PORT2ALFID(port)	((ALFID_T)(unsigned short)(port))
#define PREFIX_FSP_IP6to4	0x2002		// prefix of 6to4 overloaded
# ifndef OVERLAY_DNS
# define DEFAULT_FSP_UDPPORT	(((unsigned short)'F' << 8) + (unsigned short)'S')
# else
# define DEFAULT_FSP_UDPPORT	53
# endif
#else
// __X86__
// in network byte order on a little-endian host
#define PORT2ALFID(port)	((ALFID_T)(port) << 16)
#define PREFIX_FSP_IP6to4	0x0220		// prefix of 6to4 overloaded
# ifndef OVERLAY_DNS
# define DEFAULT_FSP_UDPPORT	((unsigned short)'F' + ((unsigned short)'S' << 8))
# else
# define DEFAULT_FSP_UDPPORT	(53 << 8)
# endif
#endif


// last well known application layer thread ID (upper layer application ID)
// well-known upper layer application ID is compatible with TCP port number
#define LAST_WELL_KNOWN_ALFID 65535

#define FSP_MAX_KEY_SIZE	32	// in bytes
#define FSP_MIN_KEY_SIZE	16	// in bytes
#define FSP_TAG_SIZE		8	// in bytes

#define MAX_PHY_INTERFACES	4	// maximum number of physical interfaces that might be multihomed

//	As recommended in NIST SP800-38d, if maximum combined length of the ciphertext and AAD in a single packet
//	is 2^15 octets, maximum invocations of authenticated decryption function shall be limited to 2^32
//	if a single packet size limit is 2^17, invocations shall be limited to 2^29 for 64 bit tags
//	As an FSP packet may not exceed 2^16 octets, and because out-of-band packet consume invocation space as well
//	we infer that maximum sequence number consumed on either direction shall be limit to 2^29
//	If re-keying occurs more frequently than the length of the send queue
//	earliest packet that shall be retransmitted may always be rejected
//	because this implementation only store one historical key
//	while the earliest packet require earlier key than stored
//	The macro might be defined on command line for purpose of boundary test
#ifndef  FSP_REKEY_THRESHOLD
# define FSP_REKEY_THRESHOLD	0x20000000
#endif


/**
* Protocol defined timeouts
*/
// In debug mode we allow pre-definition via compiler's command-line option
#ifdef _DEBUG
# define TRANSIENT_STATE_TIMEOUT_ms		300000	// 5 minutes
#else
# define TRANSIENT_STATE_TIMEOUT_ms		60000	// 1 minute
#endif

#define RETRANSMIT_MIN_TIMEOUT_us	1000000		// 1 second
#define RETRANSMIT_MAX_TIMEOUT_us	60000000	// 60 seconds

#define COMMITTING_TIMEOUT_ms			90000	// one and a half minutes
//^time-out for committing a transmit transaction starting from last acknowledgement,
// not from start of the transaction. Should be larger than the Maximum Segment Life
#define CLOSING_TIME_WAIT_ms			120000	// 2 minutes
#define SESSION_IDLE_TIMEOUT_us			(4*3600*1000000ULL)	// 4 hours

/**
  error number may appear as REJECT packet 'reason code' where it is unsigned or near-end API return value where it is negative
  standard C	FSP error meaning
	EPERM		Near end only: authorization error
	ENOENT		Listener is out of connection socket space
	ESRCH		-
	EINTR		Interrupted (e.g.RESET/Disposed when waiting for the mutex)
	EIO			Near end only: I/O interface error between the message layer and the packet layer
	ENXIO		-
	E2BIG		Near end only: message is too large to be processed
	ENOEXEC		Resuming or resurrecting is not executed successfully, socket is recycled
	EBADF		Near end only: given socket handle is invalid
	ECHILD		-
	EAGAIN		-
	ENOMEM		Near end only: no memory
	EACCES		Memory access out of border
	EFAULT		General fault
	EBUSY		Near end only: the underlying socket is busy, new service request may not be accepted
	EEXIST		Collision exists when making connection multiplication
	EDOM		Domain error: i.e. parameter value is unacceptable
*/

#include <errno.h>

typedef enum _FSP_Session_State: char
{
	NON_EXISTENT = 0, 
	// the passive listener to folk new connection handle:
	LISTENING,
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	CONNECT_BOOTSTRAP,
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQ, timeout to retry or NON_EXISTENT
	CONNECT_AFFIRMING,
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQ
	// before getting ACK_START or first PERSIST. timeout to NON_EXISTENT:
	CHALLENGING,
	// local context cloned/connection multiplying
	CLONING,
	// after getting a non-EoT PERSIST
	ESTABLISHED,
	// after sending EoT flag, before getting all packet-in-flight acknowledged.
	COMMITTING,	// A.K.A. FLUSHING; used to be PAUSING
	// after getting ACK_FLUSH, i.e. both EoT flag and all packet-in-flight have been acknowledged
	COMMITTED,	// unilaterally adjourned
	// after getting the peer's EoT flag
	PEER_COMMIT,
	// after getting the peer's EoT flag and the near end has sent EoT, before getting ACK_FLUSH
	COMMITTING2,
	// after getting the peer's EoT flag in the COMMITTED state, or ACK_FLUSH in the COMMITTING2 state
	CLOSABLE,
	// passive close of connection
	SHUT_REQUESTED,
	// asymmetrically shutdown
	PRE_CLOSED,
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	CLOSED,
	//
	LARGEST_FSP_STATE = CLOSED
} FSP_Session_State;



// operation code
typedef enum _FSP_Operation_Code : char
{
	INIT_CONNECT = 1,
	ACK_INIT_CONNECT,
	CONNECT_REQUEST,
	ACK_CONNECT_REQ,	// may piggyback payload
	RESET,
	NULCOMMIT,	// Payloadless transmit transaction commitment
	PURE_DATA,	// Without any optional header
	PERSIST,	// Start a new transmit transaction, while EoT flag make it transactional
	ACK_FLUSH,
	RELEASE,
	MULTIPLY,	// To clone connection, may piggyback payload
	KEEP_ALIVE,
	RESERVED_CODE13,
	RESERVED_CODE14,
	RESERVED_CODE15,
	//
	PEER_SUBNETS = 16,
	SELECTIVE_NACK,
	ACK_START = NULCOMMIT,
	//^In-band acknowledgement to CLONE or ACK_CONNECT_REQUEST if no data to send back.
	LARGEST_OP_CODE = SELECTIVE_NACK
} FSPOperationCode;



//  Protocol for ULA to 'hyper-call' FSP LLS
typedef enum : char
{
	NullCommand = 0,
	FSP_Listen = 1,		// register a passive socket
	InitConnection,		// register an initiative socket
	FSP_Accept,			// accept the connection, make SCB of LLS synchronized with DLL 
	FSP_Reject,			// a forward command, explicitly reject some request
	FSP_Start,
	FSP_Urge = FSP_Start,
	FSP_Send,			// Here it is not a command to LLS, but as a context indicator to ULA
	FSP_Receive,		// Here it is not a command to LLS, but as a context indicator to ULA
	FSP_InstallKey,		// install the authenticated encryption key
	FSP_Multiply,		// clone the connection, make SCB of LLS synchronized with DLL
	FSP_Reset,
	FSP_Shutdown		// Here it is passive shutdown responding to LLS and a context indicator to ULA
} FSP_ServiceCode;



//  Protocol for FSP LLS to 'interrupt' ULA
typedef enum
{
	NullNotice = 0,
	// 1~7
	FSP_NotifyListening,		// a reverse command to signal success execution of FSP_Listen
	FSP_NotifyAccepting,		// a reverse command to make context ready
	FSP_NotifyMultiplied,		// a reverse command to inform DLL to accept a multiply request
	FSP_NotifyAccepted,
	FSP_NotifyDataReady,
	FSP_NotifyBufferReady,
	FSP_NotifyToCommit,
	// 8~11
	FSP_NotifyFlushed,
	FSP_NotifyToFinish,
	// built-in rule: notification after FSP_NotifyToFinish implies the LLS socket has been released already
	FSP_NameResolutionFailed,
	// 12~: exceptions, soft NMI
	FSP_MemoryCorruption,
	FSP_NotifyReset,
	FSP_NotifyTimeout,
	SMALLEST_FSP_NMI = FSP_MemoryCorruption,
	LARGEST_FSP_NOTICE = FSP_NotifyTimeout,
} FSP_NoticeCode;



// the number of microsecond elapsed since Midnight January 1, 1970 UTC (Unix epoch)
typedef uint64_t timestamp_t;

typedef uint64_t TSubnets[MAX_PHY_INTERFACES];


#if defined(_MSC_VER)
# include <pshpack1.h>
#else
# pragma pack(push)
# pragma pack(1)
#endif

/**
 * struct FSP_IN6_ADDR * may be converted to struct in6_addr *
 */
// FSP_IN4_ADDR: <'0x2002'><IPv4><FSP UDP Port := 18003><32-bit host-id := 0><32-bit ALFid>
typedef struct FSP_IN4_ADDR_PREFIX
{
	uint16_t	prefix;
	u32	ipv4;	/* IN_ADDR */
	uint16_t	port;
} *PFSP_IN4_ADDR_PREFIX;



typedef struct FSP_IN6_ADDR
{
	union
	{
		FSP_IN4_ADDR_PREFIX _6to4;
		uint64_t	subnet;	
	};
	uint32_t	idHost;
	ALFID_T		idALF;
} *PFSP_IN6_ADDR;



typedef	struct FSP_SINKINF
{
	uint32_t	ipi_addr;
	uint32_t	ipi_ifindex;
	uint32_t	idHost;
	ALFID_T		idALF;
	uint32_t	ipi6_ifindex;
} *PFSP_SINKINF;



// FSP in UDP over IPv4
struct ALFIDPair
{
	ALFID_T source;
	ALFID_T peer;
};



struct FSP$PacketHeader
{
	FSPOperationCode	opCode;
	uint8_t				major;
	uint16_t			offset;
};



struct FSP$OptionalHeader
{
	FSPOperationCode	opCode;
	uint8_t				mark;
	uint16_t			length;
};



// position start from 7, the leftmost one
enum FSP_FlagPosition : uint8_t
{
	TransactionEnded = 7,	// share with the buffer block descriptor
	MinimalDelay = 6,		// MINimal Delay for milk-like payload
	Compressed = 5,			// In this version of FSP, LZ4 is exploited
	CongestionAlarm = 4,	// Explicit Congestion Notification
};



// CONNECT_INIT, the first 32-bit word is the header signature
struct FSP_InitiateRequest
{
	struct FSP$PacketHeader hs;
	uint32_t	salt;
	timestamp_t timeStamp;
	uint64_t	initCheckCode;
};
// Optional payload: domain name of the remote peer, less than 512 - sizeof(FSP_InitiateRequest) = 488 octets



// FSP_ConnectParam specifies the parent connection in an ACK_CONNECT_INIT, CONNECT_REQUEST or MULTIPLY packet
// the opcode used to be CONNECT_PARAM while alias as the mobile parameters
// and it is perfect OK to treat it as the canonical alias of PEER_SUBNETS
struct FSP_ConnectParam
{
	struct FSP$OptionalHeader _h;
	ALFID_T		idListener;
	TSubnets	subnets;
};	// Totally 5 QWORDs, 40 octets



// ACK_CONNECT_INIT, acknowledgement to the connect bootstrap request, works as a challenge against the initiator
struct FSP_Challenge
{
	struct FSP$PacketHeader hs;
	int32_t		timeDelta;
	uint64_t	cookie;
	uint64_t	initCheckCode;
	FSP_ConnectParam params;
};
// Totally 8 QWORDs, 64 octets



// CONNECT_REQUEST, overlay the CONNECT_INIT packet practically
struct FSP_ConnectRequest
{
	struct FSP_InitiateRequest _init;
	struct FSP_ConnectParam params;
	uint32_t	initialSN;		// initial sequence number, I->R, for this session segment
	int32_t		timeDelta;
	uint64_t	cookie;
};	// Totally 11 QWORDs, 88 octets
// Optional payload: canonical name of the near end, less than 512 - sizeof(FSP_ConnectRequest) = 424 octets



// A normal packet since ACK_CONNECT_REQ, the first 32-bit word is the header signature
// Trick that must be kept: the sequence number field MUST be align with the timestamp or cookie field
struct FSP_NormalPacketHeader
{
	struct FSP$PacketHeader hs;
	octet	flags_ws[4];
	uint32_t sequenceNo;
	uint32_t expectedSN;
	union
	{
		uint64_t	code;
		ALFIDPair	id;
	} integrity;
	//
#ifdef __cplusplus
	// A brute-force but safe method of set or retrieve receive window size, with byte order translation
	int32_t GetRecvWS()	const { return ((int32_t)flags_ws[1] << 16) + ((unsigned)flags_ws[2] << 8) + flags_ws[3]; }
#endif
};



// Mandatory additional header for KEEP_ALIVE
// minimum constituent of a SNACK header
struct FSP_SelectiveNACK
{
	struct FSP$OptionalHeader _h;
	uint32_t		ackSeqNo;
	uint32_t		latestSN;
	uint32_t		tLazyAck;	// delay time of the lazy acknowledgement, in microseconds
	struct GapDescriptor
	{
		uint32_t	gapWidth;	// in packets
		uint32_t	dataLength;	// in packets
	};
};



// FSP_RESET, the reset reason should be bit fields.
struct FSP_RejectConnect
{
	struct FSP$PacketHeader hs;
	uint32_t reasons;
	union
	{
		timestamp_t timeStamp;
		struct
		{
			uint32_t initial;
			uint32_t expected;
		} sn;
	};
	//
	union
	{
		uint64_t integrityCode;
		uint64_t cookie;
		uint64_t initCheckCode;
		ALFIDPair fidPair;
	};
};



// To profile the performance of the socket
typedef struct CSocketPerformance
{
#define	RTT_LOG_CAPACITY 256
	int64_t		countPacketReceived;
	int64_t		countPacketAccepted;
	int64_t		countPacketSent;
	int64_t		countPacketResent;
	int64_t		countZWPsent;
	int64_t		countZWPresent;
	int64_t		countKeepAliveLockFail;
	// round-log of RTT jitter
	int64_t		rttJitters[RTT_LOG_CAPACITY];
	uint64_t	jlogCount;
	int32_t		jlogTail;
	// possibility of the real log count exceed 2^64 but jlogCount is less than RTT_LOG_CAPACITY
	// is (RTT_LOG_CAPACITY/2^64), almost computational impossible
#ifdef __cplusplus
	void		PushJitter(int64_t jitter)
	{
		rttJitters[jlogTail++] = jitter;
		if (jlogTail >= RTT_LOG_CAPACITY)
			jlogTail = 0;
		jlogCount++;
	}
#endif
} *PSocketProfile;


#if defined(_MSC_VER)
# include <poppack.h>
#else
# pragma pack(pop)
#endif

#endif
