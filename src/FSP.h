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

// To borrow some stdint definition from VMAC and VHASH Implementation by Ted Krovetz (tdk@acm.org) and Wei Dai
#include "vmac.h"

typedef uint32_t ALT_ID_T;

#if (VMAC_ARCH_BIG_ENDIAN)
// in network byte order on a big-endian host
#define PORT2ALT_ID(port)	((ALT_ID_T)(unsigned short)(port))
#define IPv6PREFIX_MARK_FSP 0x2002		// prefix of 6to4 overloaded
#define DEFAULT_FSP_UDPPORT (((unsigned short)'F' << 8) + (unsigned short)'S')
#else
// __X86__
// in network byte order on a little-endian host
#define PORT2ALT_ID(port)	((ALT_ID_T)(port) << 16)
#define IPv6PREFIX_MARK_FSP 0x0220		// prefix of 6to4 overloaded
#define DEFAULT_FSP_UDPPORT ((unsigned short)'F' + ((unsigned short)'S' << 8))
#endif


// last well known application layer thread ID (upper layer application ID)
// well-known upper layer application ID is compatible with TCP port number
#define LAST_WELL_KNOWN_ALT_ID 65535


#define FSP_PUBLIC_KEY_LEN	64	// in bytes
#define FSP_SESSION_KEY_LEN	16	// in bytes

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

typedef enum _FSP_Session_State
{
	NON_EXISTENT = 0, 
	// resurrect from CLOSED:
	QUASI_ACTIVE,
	// context cloned by ConnectMU:
	CLONING,
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	CONNECT_BOOTSTRAP,
	// the passiver listener to folk new connection handle:
	LISTENING,
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQUEST
	// before getting first PERSIST. timeout to NON_EXISTENT:
	CHALLENGING,
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQUEST, timeout to retry or NON_EXISTENT
	CONNECT_AFFIRMING,
	// initiator: after getting the ACK_CONNECT_REQUEST 
	// responder: after getting the first PERSIST
	// no default timeout. however, implementation could arbitrarily limit a session life
	ESTABLISHED,
	// after sending FLUSH, before getting all packet-in-flight acknowledged.
	PAUSING,
	// after getting all packet-in-flight acknowledged, including the FLUSH packet.
	CLOSABLE,
	// after sending RESTORE, before RESTORE acknowledged
	RESUMING,
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	CLOSED
} FSP_Session_State;



// operation code
typedef enum _FSP_Operation_Code
{
	INIT_CONNECT	= 1,
	ACK_INIT_CONNECT,
	CONNECT_REQUEST,
	ACK_CONNECT_REQUEST,	// may piggyback payload
	RESET,
	PERSIST,		// Alias: KEEP_ALIVE, DATA_WITH_ACK,
	PURE_DATA,		// Without any optional header
	ADJOURN,
	ACK_FLUSH,
	RESTORE,		// RESUME or RESURRECT connection, may piggyback payload
	FINISH,
	MULTIPLY,		// To clone connection, may piggyback payload
	RESERVED_CODE13,
	RESERVED_CODE14,
	RESERVED_CODE15,
	RESERVED_CODE16,
	//
	CONNECT_PARAM,
	EPHEMERAL_KEY,
	SELECTIVE_NACK,
} FSPOperationCode;





typedef enum
{
	NullCommand = 0,
	// 1~15: DLL to LLS
	FSP_Listen = 1,		// register a passive socket
	InitConnection,		// register an initiative socket
	SynConnection,		// make SCB entry of the DLL and the LLS synchronized
	FSP_Reject,
	FSP_Timeout,		// 5, 'try later', used to be FSP_Preclose
	FSP_Dispose,		// AKA Reset. dispose the socket. connection might be aborted
	FSP_Send,			// send a packet/a group of packets
	FSP_Shutdown,		// close the connection
	// 16~23: LLS to DLL in the backlog
	FSP_NotifyDataReady = 16,
	FSP_NotifyReset,
	FSP_NotifyRecycled,
	FSP_NotifyAdjourn,
	FSP_NotifyFlushed,
	FSP_NotifyBufferReady,
	FSP_NotifyDisposed,
	// 24~31: near end error status
	FSP_NotifyIOError = 24,
	FSP_NotifyOverflow,
	FSP_NotifyNameResolutionFailed,
	FSP_NotifyUnspecifiedFault
} FSP_ServiceCode;


// the number of microsecond elapsed since Midnight January 1, 1970 UTC (unix epoch)
typedef uint64_t timestamp_t;



/**
 * Protocol defined timeouts
 */
#ifdef TRACE
# define CONNECT_INITIATION_TIMEOUT_ms	90000	// 90 seconds
# define KEEP_ALIVE_TIMEOUT_MIN_ms		5000	// 5 seconds
# define TRASIENT_STATE_TIMEOUT_ms		300000	// 5 minutes
#else
# define CONNECT_INITIATION_TIMEOUT_ms	9000	// 9 seconds
# define KEEP_ALIVE_TIMEOUT_MIN_ms		500		// half a second
# define TRASIENT_STATE_TIMEOUT_ms		30000	// half a minute
#endif
/***
 * Protocol defined limit
 */
#define EPHEMERAL_KEY_LIFECYCLE	(1024*1024 - 1)

#include <pshpack1.h>

/**
 * struct FSP_IN6_ADDR * may be converted to struct in6_addr *
 */
typedef struct FSP_IN6_ADDR
{
	// <'0x2002'><IPv4><port><32-bit host-id><32-bit ALT id>
	union
	{
		struct
		{
			uint16_t	prefix;
			uint32_t	ipv4;	//IN_ADDR
			uint16_t	port;
		} st;
		uint64_t		subnet;	
	} u;
	uint32_t	idHost;
	ALT_ID_T	idALT;
} *PFSP_IN6_ADDR;



typedef	struct FSP_PKTINFO 
{
	uint32_t	ipi_addr;
	uint32_t	ipi_ifindex;
	uint32_t	host_id;
	ALT_ID_T	idALT;
	uint32_t	ipi6_ifindex;
} *PFSP_PKTINFO;



// FSP in UDP over IPv4
struct PairSessionID
{
	ALT_ID_T srcSessionID;
	ALT_ID_T dstSessionID;
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

