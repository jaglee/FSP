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

#define THIS_FSP_VERSION	0	// current version
#define IPPROTO_FSP			144	// value of protocol field for FSP over IPv6

#define ARCH_BIG_ENDIAN		0	// by default it works for little-endian architecture

// To borrow some stdint definitions
#include "gcm-aes.h"

typedef uint32_t ALFID_T;


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

#define INITIAL_CONGESTION_WINDOW	2 // a protocol default congestion control parameter

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
	// after sending COMMIT/FLUSH, before getting all packet-in-flight acknowledged.
	COMMITTING,	// A.K.A. FLUSHING; used to be PAUSING
	// after getting the peer's COMMIT packet
	PEER_COMMIT,
	// after getting the peer's COMMIT and the near end has sent COMMIT
	COMMITTING2,
	// after getting ACK_FLUSH, i.e. all packet-in-flight acknowledged, including the COMMIT/FLUSH packet.
	COMMITTED,	// unilaterally adjourned
	// after getting the peer's COMMIT/FLUSH in the COMMITTED state, or ACK_FLUSH in the COMMITTING2 state
	CLOSABLE,
	// asymmetrically shutdown
	PRE_CLOSED,
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	CLOSED,
	// context cloned/connection multiplying (ESTABLISHED:CLOSABLE)
	CLONING,
	// after sending RESUME, before RESUME acknowledged
	RESUMING,
	// resurrect from CLOSED:
	QUASI_ACTIVE,
	//
	LARGEST_FSP_STATE = QUASI_ACTIVE
} FSP_Session_State;



// operation code
typedef enum _FSP_Operation_Code: char
{
	INIT_CONNECT	= 1,
	ACK_INIT_CONNECT,
	CONNECT_REQUEST,
	ACK_CONNECT_REQ,	// may piggyback payload
	RESET,
	PERSIST,	// While COMMIT/COMMIT make it transactional
	PURE_DATA,	// Without any optional header
	COMMIT,		// A.K.A. FLUSH, used to be ADJOURN
	ACK_FLUSH,
	RESUME,		// RESUME or RESURRECT connection, may piggyback payload
	RELEASE,
	MULTIPLY,	// To clone connection, may piggyback payload
	KEEP_ALIVE,
	RESERVED_CODE14,
	RESERVED_CODE15,
	RESERVED_CODE16,
	//
	MOBILE_PARAM,
	SELECTIVE_NACK,
	LARGEST_OP_CODE = SELECTIVE_NACK
} FSPOperationCode;





typedef enum: char
{
	NullCommand = 0,
	// 1~15: DLL to LLS
	FSP_Listen = 1,		// register a passive socket
	InitConnection,		// register an initiative socket
	SynConnection,		// make SCB entry of the DLL and the LLS synchronized
	FSP_Reject,			// a forward command, explicitly reject some request
	FSP_Recycle,		// a forward command, connection might be aborted
	FSP_Start,			// send a start packet, MULTIPLY or PERSIST
	FSP_Send,			// send a packet/a group of packets
	FSP_Urge,			// send a packet urgently, mean to urge COMMIT
	FSP_Shutdown,		// close the connection
	FSP_InstallKey,		// install the authenticated encryption key
	// 16~23: LLS to DLL in the backlog
	FSP_NotifyAccepting = SynConnection,	// a reverse command to make context ready
	FSP_NotifyAccepted = 16,
	FSP_NotifyDataReady,
	FSP_NotifyBufferReady,
	FSP_NotifyReset,
	FSP_NotifyFlushed,
	FSP_NotifyFinish,
	FSP_Dispose,		// a reverse command from LLS to DLL meant to synchonize DLL and LLS
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
#define CONNECT_INITIATION_TIMEOUT_ms	30000	// half a minute
#define TRASIENT_STATE_TIMEOUT_ms		300000	// 5 minutes


#include <pshpack1.h>

/**
 * struct FSP_IN6_ADDR * may be converted to struct in6_addr *
 */
// FSP_IN4_ADDR: <'0x2002'><IPv4><FSP UDP Port := 18003><32-bit host-id := 0><32-bit ALT id>
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
		FSP_IN4_ADDR_PREFIX st;
		uint64_t		subnet;	
	} u;
	uint32_t	idHost;
	ALFID_T		idALF;
} *PFSP_IN6_ADDR;



typedef	struct FSP_PKTINFO 
{
	uint32_t	ipi_addr;
	uint32_t	ipi_ifindex;
	uint32_t	idHost;
	ALFID_T		idALF;
	uint32_t	ipi6_ifindex;
} *PFSP_PKTINFO;



// FSP in UDP over IPv4
struct PairALFID
{
	ALFID_T source;
	ALFID_T peer;
};



typedef	struct FSP_HeaderSignature
{
	uint8_t version;
	uint8_t opCode;
	uint16_t hsp;
} *PFSP_HeaderSignature;



// general place holder for the fixed part of the FSP header
struct FSP_Header
{
	unsigned char headerContent[20];
	FSP_HeaderSignature hs;	// total length: 24 octets; default hsp = 0x18
};


#include <poppack.h>

#endif

