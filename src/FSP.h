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

#if ARCH_BIG_ENDIAN
// in network byte order on a big-endian host
#define PORT2ALFID(port)	((ALFID_T)(unsigned short)(port))
#define PREFIX_FSP_IP6to4	0x2002		// prefix of 6to4 overloaded
#define DEFAULT_FSP_UDPPORT (((unsigned short)'F' << 8) + (unsigned short)'S')
#else
// __X86__
// in network byte order on a little-endian host
#define PORT2ALFID(port)	((ALFID_T)(port) << 16)
#define PREFIX_FSP_IP6to4	0x0220		// prefix of 6to4 overloaded
#define DEFAULT_FSP_UDPPORT ((unsigned short)'F' + ((unsigned short)'S' << 8))
#endif


// last well known application layer thread ID (upper layer application ID)
// well-known upper layer application ID is compatible with TCP port number
#define LAST_WELL_KNOWN_ALFID 65535

#define FSP_MAX_KEY_SIZE	32	// in bytes
#define FSP_MIN_KEY_SIZE	16	// in bytes
#define FSP_TAG_SIZE		8	// in bytes

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
		uint64_t		subnet;	
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



typedef	struct FSP_HeaderSignature
{
	uint16_t			hsp;
	uint8_t				major;
	FSPOperationCode	opCode;
} *PFSP_HeaderSignature;



// general place holder for the fixed part of the FSP header
struct FSP_Header
{
	unsigned char headerContent[20];
	FSP_HeaderSignature hs;	// total length: 24 octets; default hsp = 0x18
};


#include <poppack.h>

#endif

