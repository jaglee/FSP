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
#define DEFAULT_FSP_UDPPORT	(((unsigned short)'F' << 8) + (unsigned short)'S')
#else
// __X86__
// in network byte order on a little-endian host
#define PORT2ALFID(port)	((ALFID_T)(port) << 16)
#define PREFIX_FSP_IP6to4	0x0220		// prefix of 6to4 overloaded
// #define DEFAULT_FSP_UDPPORT 13568
#define DEFAULT_FSP_UDPPORT	((unsigned short)'F' + ((unsigned short)'S' << 8))
#endif


// last well known application layer thread ID (upper layer application ID)
// well-known upper layer application ID is compatible with TCP port number
#define LAST_WELL_KNOWN_ALFID 65535

#define FSP_MAX_KEY_SIZE	32	// in bytes
#define FSP_MIN_KEY_SIZE	16	// in bytes
#define FSP_TAG_SIZE		8	// in bytes

#define MAX_PHY_INTERFACES	4	// maximum number of physical interfaces that might be multihomed

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
	ENOMEM		Near end only: no mememory
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
	// the passiver listener to folk new connection handle:
	LISTENING,
	// context cloned/connection multiplying (ESTABLISHED:CLOSABLE)
	CLONING,
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	CONNECT_BOOTSTRAP,
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQ
	// before getting first PERSIST. timeout to NON_EXISTENT:
	CHALLENGING,
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQ, timeout to retry or NON_EXISTENT
	CONNECT_AFFIRMING,
	// initiator: after getting ACK_CONNECT_REQ 
	// responder: after getting the first PERSIST
	// no default timeout. however, implementation could arbitrarily limit a session life
	ESTABLISHED,
	// after sending EoT flag, before getting all packet-in-flight acknowledged.
	COMMITTING,	// A.K.A. FLUSHING; used to be PAUSING
	// after getting the peer's EoT flag
	PEER_COMMIT,
	// after getting the peer's EoT flag and the near end has sent EoT
	COMMITTING2,
	// after getting ACK_FLUSH, i.e. both EoT flag and all packet-in-flight have been acknowledged
	COMMITTED,	// unilaterally adjourned
	// after getting the peer's EoT flag in the COMMITTED state, or ACK_FLUSH in the COMMITTING2 state
	CLOSABLE,
	// asymmetrically shutdown
	PRE_CLOSED,
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	CLOSED,
	//
	LARGEST_FSP_STATE = CLOSED
} FSP_Session_State;



// operation code
typedef enum _FSP_Operation_Code: char
{
	INIT_CONNECT	= 1,
	ACK_INIT_CONNECT,
	CONNECT_REQUEST,
	ACK_CONNECT_REQ,	// may piggyback payload
	RESET,
	PERSIST,	// Start a new transmit transaction, while EoT flag make it transactional
	PURE_DATA,	// Without any optional header
	_COMMIT,	// Not literally sent anyway, just as a mark in the receive buffer
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
	LARGEST_OP_CODE = SELECTIVE_NACK
} FSPOperationCode;



// Somewhat 'paravirtualization' protocol for DLL to 'hyper-call' LLS and vice-versa
typedef enum: char
{
	NullCommand = 0,
	// 1~15: DLL to LLS
	FSP_Listen = 1,		// register a passive socket
	InitConnection,		// register an initiative socket
	FSP_Accept,			// accept the connection, make SCB of LLS synchronized with DLL 
	FSP_Reject,			// a forward command, explicitly reject some request
	FSP_Recycle,		// a forward command, connection might be aborted
	FSP_Start,			// send a packet starting a new send-transaction
	FSP_Send,			// send a packet/a group of packets
	FSP_Commit,			// force to send a EoT flag,
	//^ The EoT flag is either embedded in the last in-band packet, or piggybacked on the most recent KEEP_ALIVE/ACK_FLUSH
	FSP_Shutdown,		// close the connection
	FSP_InstallKey,		// install the authenticated encryption key
	FSP_Multiply,		// clone the connection, make SCB of LLS synchronized with DLL
	FSP_AdRecvWindow,	// force to advertise the receive window ONCE by send a SNACK/ACK_FLUSH
	// 16~23: LLS to DLL in the backlog
	FSP_NotifyListening = FSP_Listen,		// a reverse command to signal success execution of FSP_Listen
	FSP_NotifyAccepting = FSP_Accept,		// a reverse command to make context ready
	FSP_NotifyRecycled = FSP_Recycle,		// a reverse command to inform DLL to release resource passively
	FSP_NotifyMultiplied = FSP_Multiply,	// a reverse command to inform DLL to accept a multiply request
	FSP_NotifyAccepted = 16,
	FSP_NotifyDataReady,
	FSP_NotifyBufferReady,
	FSP_NotifyToCommit,
	FSP_NotifyFlushed,
	FSP_NotifyToFinish,
	FSP_NotifyReset,	// 22: used to be FSP_Dispose
	// 23: Reserved
	// 24~31: near end error status
	FSP_IPC_CannotReturn = 24,
	FSP_MemoryCorruption,
	FSP_NotifyOverflow,
	FSP_NotifyTimeout,
	FSP_NotifyNameResolutionFailed,
	LARGEST_FSP_NOTICE = FSP_NotifyNameResolutionFailed
} FSP_ServiceCode;



// the number of microsecond elapsed since Midnight January 1, 1970 UTC (unix epoch)
typedef uint64_t timestamp_t;


/**
 * Protocol defined timeouts
 */
// In debug mode we allow pre-definition via compiler's command-line option
#ifdef _DEBUG
# define INIT_RETRANSMIT_TIMEOUT_ms		60000	// 1 minute
# define RECYCLABLE_TIMEOUT_ms			300000	// 5 minutes
# define TRANSIENT_STATE_TIMEOUT_ms		300000	// 5 minutes
#else
# define INIT_RETRANSMIT_TIMEOUT_ms		15000	// 15 seconds
# define RECYCLABLE_TIMEOUT_ms			3600000	// 1 hour
# define TRANSIENT_STATE_TIMEOUT_ms		60000	// 1 minute
#endif

#define KEEP_ALIVE_TIMEOUT_ms			600000	// 10 minutes
#define MAXIMUM_SESSION_LIFE_ms			43200000// 12 hours

#include <pshpack1.h>

/**
 * struct FSP_IN6_ADDR * may be converted to struct in6_addr *
 */
// FSP_IN4_ADDR: <'0x2002'><IPv4><FSP UDP Port := 18003><32-bit host-id := 0><32-bit ALFid>
typedef struct FSP_IN4_ADDR_PREFIX
{
	uint16_t	prefix;
	uint32_t	ipv4;	//IN_ADDR
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



typedef	struct $FSP_HeaderSignature
{
	uint16_t			hsp;	// header stack pointer
	uint8_t				major;
	FSPOperationCode	opCode;
	//
#ifdef __cplusplus
	template<typename THdr, FSPOperationCode opCode1> void Set()
	{
		major = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = htobe16(sizeof(THdr));
	}
	void Set(FSPOperationCode opCode1, int len1)
	{
		major = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = htobe16(len1);
	}
#endif
} *PFSP_HeaderSignature;



// position start from 7, the leftmost one
enum FSP_FlagPosition : uint8_t
{
	TransactionEnded = 7,	// share with the buffer block descriptor
	Compressed = 6,			// In this version of FSP, LZ4 is exploited
	CongestionAlarm = 5,	// Accurate ECN/Scalable Congestion Control
};



// more detail implementation of FSP_NormalPacketHeader is defined later
struct FSP_NormalPacketHeader
{
	uint32_t sequenceNo;
	uint32_t expectedSN;
	union
	{
		uint64_t	code;
		ALFIDPair	id;
	} integrity;
	//
	octet	flags_ws[4];
	$FSP_HeaderSignature hs;

#ifdef __cplusplus
	void Set(FSPOperationCode code, uint16_t hsp, uint32_t seqThis, uint32_t seqExpected, int32_t advRecvWinSize)
	{
		hs.Set(code, hsp);
		expectedSN = htobe32(seqExpected);
		sequenceNo = htobe32(seqThis);
		ClearFlags();
		SetRecvWS(advRecvWinSize);
	}
	// A brute-force but safe method of set or retrieve receive window size, with byte order translation
	int32_t GetRecvWS()	const { return ((int32_t)flags_ws[1] << 16) + ((unsigned)flags_ws[2] << 8) + flags_ws[3]; }
	void SetRecvWS(int32_t v) { flags_ws[1] = (octet)(v >> 16); flags_ws[2] = (octet)(v >> 8); flags_ws[3] = (octet)v; }

	void ClearFlags() { flags_ws[0] = 0; }
	template<FSP_FlagPosition pos> void SetFlag() { flags_ws[0] |= (1 << pos); }
	template<FSP_FlagPosition pos> void ClearFlag() { flags_ws[0] &= ~(1 << pos); }
	template<FSP_FlagPosition pos> int GetFlag() const { return flags_ws[0] & (1 << pos); }

	// Get the first extension header
	PFSP_HeaderSignature PFirstExtHeader() const
	{
		return (PFSP_HeaderSignature)((uint8_t *)this + be16toh(hs.hsp) - sizeof($FSP_HeaderSignature));
	}

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
		if (sp < sizeof(FSP_NormalPacketHeader) || sp >(uint8_t *)p0 - (uint8_t *)this)
			return NULL;
		return (PFSP_HeaderSignature)((uint8_t *)this + sp - sizeof($FSP_HeaderSignature));
	}
#endif
};



struct FSP_InitiateRequest
{
	timestamp_t timeStamp;
	uint64_t	initCheckCode;
	uint32_t	salt;
	$FSP_HeaderSignature hs;
};
// Optional payload: domain name of the remote peer, less than 512 - sizeof(FSP_InitiateRequest) = 488 octets


// acknowledgement to the connect bootstrap request, works as a challenge against the initiator
// to be followed by the certificate optional header
struct FSP_Challenge
{
	uint64_t	cookie;
	uint64_t	initCheckCode;
	int32_t		timeDelta;
	$FSP_HeaderSignature hs;
};
// Optional payload: canonical name of the near end, less than 512 - sizeof(FSP_Challenge) = 488 octets


// FSP_ConnectParam specifies the parent connection in a MULTIPLY or CONNECT_REQUEST packet
// while alias as the mobile parameters
// PEER_SUBNETS used to be CONNECT_PARAM and it is perfect OK to treat the latter as the canonical alias of the former
struct FSP_ConnectParam
{
	uint64_t	subnets[MAX_PHY_INTERFACES];
	ALFID_T		idListener;
	ALFID_T		idHost;
	//
	octet		flags_ws[4];
	$FSP_HeaderSignature hs;
};	// Totally 6 QWORDs, 48 octets



#ifdef __cplusplus
struct FSP_ConnectRequest : FSP_InitiateRequest
{
#else
struct FSP_ConnectRequest
{
	struct FSP_InitiateRequest _h;
#endif
	uint32_t	initialSN;		// initial sequence number, I->R, for this session segment
	int32_t		timeDelta;
	uint64_t	cookie;
	//
	FSP_ConnectParam params;
};	// Totally 11 QWORDs, 88 octets
// Optional payload: canonical name of the near end, less than 512 - sizeof(FSP_ConnectRequest) = 424 octets


#ifdef __cplusplus
struct FSP_AckConnectRequest : FSP_NormalPacketHeader
{
#else
struct FSP_AckConnectRequest
{
	struct FSP_NormalPacketHeader _h;
#endif
	FSP_ConnectParam params;
};



// Mandatory additional header for KEEP_ALIVE
// minimum constituent of a SNACK header
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
	};
	//
	union
	{
		uint64_t integrityCode;
		uint64_t cookie;
		uint64_t initCheckCode;
		ALFIDPair fidPair;
	};
	//
	uint32_t reasons;	// bit field(?)
	$FSP_HeaderSignature hs;
};


#include <poppack.h>

#endif

