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

#ifdef _MSC_VER
#include <winsock2.h>
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
#pragma intrinsic(_InterlockedCompareExchange8)
#else
FORCEINLINE UINT8 _InterlockedCompareExchange8(volatile char *dest, char newval, char oldval)
{
    __asm
    {
        mov     al, oldval
        mov     edx,dest
        mov     cl,	newval
        lock cmpxchg byte ptr [edx], cl
    }
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

// Reflexing string representation of FSP_Session_State and FSP_ServiceCode, for debug purpose
extern	char * stateNames[FSP_Session_State::CLOSED + 1];
extern	char * noticeNames[FSP_ServiceCode::FSP_NotifyUnspecifiedFault + 1];


/**
 * Backward compatibility support
 */
#if _WIN32_WINNT < 0x0600
typedef union sockaddr_inet
{
	struct sockaddr_in6 Ipv6;
	struct sockaddr_in Ipv4;
	short si_family;	// ADDRESS_FAMILY as of Windows Vista and later
} SOCKADDR_INET, *PSOCKADDR_INET;
//
#define IN4ADDR_LOOPBACK 0x0100007F	// the loop back address 127.0.0.1 in host byte order
#endif


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
#define	SCAVENGE_THRESHOLD_ms		1800000		// 30 minutes

/**
 * Implemented system limit
 */
#ifdef USE_RAWSOCKET_IPV6
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


/**
 * platform-dependent fundamental utility functions
 */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif
// Return the number of microseconds elapsed since Jan 1, 1970 (unix epoch time)
extern "C" timestamp_t NowUTC();	// it seems that a global property 'Now' is not as clear as this function format

// random generatator is somehow dependent on implementation. hardware prefered.
extern "C" void	rand_w32(uint32_t *p, int n);

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
		hsp = host16tonet(sizeof(THdr));
	}
	template<BYTE opCode1> void Set(int len1)
	{
		version = THIS_FSP_VERSION;
		opCode = opCode1;
		hsp = host16tonet((uint16_t)len1);
	}
};


// position start from 0, the rightmost one
enum FSP_FlagPosition: UINT8
{
	ToBeContinued = 0,
	Compressed = 1,
	ExplicitCongestion = 7
};


struct FSP_NormalPacketHeader
{
	UINT32 sequenceNo;
	UINT32 expectedSN;
	union
	{
		UINT64		code;
		PairSessionID id;
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
	INT32		timeDelta;
	$FSP_HeaderSignature hs;
};

/**
 * TODO: UNRESOLVED! Server's certificate as an optional header, for IPv6 only?
 */
// FSP_ConnectParam assists in renegotiating session key in a PERSIST packet
// while specifies the parent connection in a MULTIPLY or CONNECT_REQUEST packet
// To make life easier we support at most two load-balanced IP interfaces
struct FSP_ConnectParam
{
	uint64_t	subnets[2];
	uint32_t	initialSN;		// initial sequence number, I->R, for this session segment
	ALT_ID_T	listenerID;
	uint32_t	delayLimit;		// In microseconds, 0 for no limit
	$FSP_HeaderSignature hs;
};



// formal connection request, to be followed by half-connection parameter header
// acknowledge of the connection request packet is an 'almost normal' FSP packet
struct FSP_ConnectPublicKey
{
	BYTE	public_n[FSP_PUBLIC_KEY_LEN];
	INT32	timeDelta;
	$FSP_HeaderSignature hsKey;
};



struct FSP_ConnectRequest: FSP_InitiateRequest, FSP_ConnectPublicKey
{
	__declspec(property(get=getCookie, put=setCookie))
	UINT64	cookie;
	UINT64	getCookie() const { return initCheckCode; }
	void	setCookie(UINT64 value) { initCheckCode = value; }
	//
	FSP_ConnectParam params;
};


struct FSP_AckConnectKey
{
	BYTE	encrypted[FSP_PUBLIC_KEY_LEN];		// RSAES-PKCS1-v1_5 O
	INT32	timeDelta;
	$FSP_HeaderSignature hsKey;
};


struct FSP_AckConnectRequest: FSP_NormalPacketHeader, FSP_AckConnectKey
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
		PairSessionID sidPair;
	} u2;
	//
	UINT32 reasons;	// bit field(?)
	$FSP_HeaderSignature hs;
};


// command to lower layer service
struct CommandToLLS
{
	FSP_ServiceCode opCode;	// operation code
	DWORD idProcess;
	ALT_ID_T idSession;
};


// either a passive session, an initiative session
struct CommandNewSession: CommandToLLS
{
	HANDLE	hMemoryMap;		// pass to LLS by ULA, should be duplicated by the server
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	union
	{
		char	szEventName[MAX_NAME_LENGTH];	// name of the callback event
		struct
		{
			BYTE	notUsed[MAX_NAME_LENGTH / 2];
			void	*pSocket;
			int		index;
			HANDLE	hEvent;
		} s;
	} u;

	bool	ResolvEvent();	// implemented in LLS only
};



class ConnectRequestQueue
{
	CommandNewSession q[CONNECT_BACKLOG_SIZE];
	int head;
	int tail;
	char mayFull;
	volatile char mutex;
public:
	// ConnectRequestQueue() { head = tail = 0; mayFull = 0; mutex = SHARED_FREE; }
	int Push(const CommandNewSession *);
	int Remove(int);
};


// packet information on local address and interface number
// for IPv6, local session ID is derived from local address
typedef struct _CMSGHDR
{
#if _WIN32_WINNT >= 0x0600
	CMSGHDR		pktHdr;
#else
	WSACMSGHDR	pktHdr;
#endif
	FSP_PKTINFO	u;
} *PFSP_MSGHDR;


#define IsIPv6MSGHDR(h) (((struct _CMSGHDR *) & (h))->pktHdr.cmsg_level == IPPROTO_IPV6)
#define MSGHDR_ALT_ID(h) (((PFSP_MSGHDR) & (h))->u.idALT)



// packet information on local address and interface number
// for IPv6, local session ID is derived from local address
struct CtrlMsgHdr: _CMSGHDR
{
	void InitUDPoverIPv4(ULONG if1)
	{
		pktHdr.cmsg_len = sizeof(pktHdr) + sizeof(struct in_pktinfo);
		pktHdr.cmsg_level = IPPROTO_IP;	/* originating protocol */
		pktHdr.cmsg_type = IP_PKTINFO;
		memset(& u, 0, sizeof(u));		// inaddr_any
		u.ipi_ifindex = if1;
	}
	void InitNativeIPv6(ULONG if1)
	{
		pktHdr.cmsg_len = sizeof(CtrlMsgHdr);	/* #bytes, including this header */
		pktHdr.cmsg_level = IPPROTO_IPV6;	/* originating protocol */
		pktHdr.cmsg_type = IPV6_PKTINFO;
		memset(& u, 0, sizeof(u));		// in6addr_any;
		u.ipi6_ifindex = if1;
	}
	//
	CtrlMsgHdr() {}
	// implemented in DLL only
	CtrlMsgHdr(const PFSP_IN6_ADDR);
	// implemneted in LLS only
	CtrlMsgHdr(WSABUF &);
	//
	PFSP_IN6_ADDR ExportAddr(struct in6_pktinfo *);
};


struct SConnectParam	// MUST be aligned on 64-bit words!
{
	UINT64		initCheckCode;
	UINT64		cookie;
	UINT32		salt;
	UINT32		initialSN;	// the initial sequence number of the packet to send
	ALT_ID_T	idRemote;	// ID of the listener or the new forked, depending on context
	union
	{
		UINT32	limit;		// in microseconds, for milky payload
		int		p2p;		// peer to peer delay, before challenging
	} delay;
	timestamp_t timeStamp;
	UINT64		allowedPrefixes[MAX_PHY_INTERFACES];
};



struct BackLogItem: SConnectParam
{
	BYTE		bootKey[FSP_PUBLIC_KEY_LEN];
	CtrlMsgHdr	acceptAddr;	// including the interface number AND the local session ID
	ALT_ID_T	idParent;
	//^ 0 if it is the 'root' acceptor, otherwise the local session ID of the cloned connection
	UINT32		expectedSN;	// the expected sequence number of the packet to receive by order
	//
	BackLogItem() {}
	BackLogItem(WSABUF & control): acceptAddr(control) { }
};



// 
template<typename TLogItem> class TSingleProviderMultipleConsumerQ
{
	int	MAX_BACKLOG_SIZE;
	int headQ;
	int tailQ;
	char mutex;
	volatile int count;
	volatile unsigned int nProvider;
	//
	TLogItem q[MIN_QUEUED_INTR];
	//
	void InitSize() { MAX_BACKLOG_SIZE = MIN_QUEUED_INTR; }	// assume memory has been zeroized
	int InitSize(int);

	friend class ControlBlock;
public:
	int LOCALAPI Push(const TLogItem *p);
	int LOCALAPI Pop(TLogItem *p);
};




/**
 * Session Control Block is meant to be shared by LLS and DLL. Shall be prefixed with 'volatile' if LLS is implemented in hardware
 */
typedef int (LOCALAPI * fpDeliverData_t)(void * context, void * buffer, int len);

enum SocketBufFlagBitPosition
{
	BIT_IN_SENDING = 0,
	IS_ACKNOWLEDGED = 1,
	IS_COMPLETED = 2,
	IS_DELIVERED = 3,
	IS_IN_USE = 4,
	// 5, 6: reserved
	TO_BE_CONTINUED = 7
};


class ControlBlock
{
protected:
	friend class CSocketItem;
	volatile LONG returned;
public:
	bool	furtherToSend;	// by default each WriteTo() terminates a message automatically
	bool	eomRecv;		// end of receiving message, notify EndOfMessage in ReadFrom() in out-of-band manner

	FSP_Session_State state;
	bool	IsPassive() const { return state == LISTENING; }

	UINT32			allowedDelay;	// 0 if it is wine-alike payload, non-zero if milky; in microseconds
	ALT_ID_T		idParent;
	char			peerName[INET6_ADDRSTRLEN + 7];	// 72 bytes

	// 1, 2.
	// TODO: UNRESOLVED!? limit multi-home capability to physical interfaces, not logical interfaces?
	CtrlMsgHdr		nearEnd[MAX_PHY_INTERFACES];
	SOCKADDR_INET	sockAddrTo[MAX_PHY_INTERFACES];
	ALT_ID_T GetSessionID() const { return MSGHDR_ALT_ID(nearEnd[0]); }	// a property, actually

	typedef uint32_t seq_t;

	// 5, 6: Send window and receive window descriptor
	volatile seq_t		sendWindowFirstSN;	// left-border of the send window
	volatile seq_t		sendWindowNextSN;	// the sequence number of the next packet to send
	// it means that the send queue is empty when sendWindowFirstSN == sendWindowSN2Recv
	volatile int32_t	sendWindowSize;		// in blocks, width of the send window
	// (next position, send buffer next sn) (head position, send window first sn)
	// are managed independently for maximum parallism in DLL and LLS
	volatile int32_t	sendWindowHeadPos;	// the index number of the block with sendWindowFirstSN
	seq_t		sendBufferNextSN;
	int32_t		sendBufferNextPos;	// the index number of the block with sendBufferNextSN
	seq_t		sendWindowExpectedSN;
	//
	int32_t		sendBufferBlockN;	// capacity of the send buffer
	uint32_t	sendBuffer;			// relative to start of the control block
	uint32_t	sendBufDescriptors;	// relative to start of the control block,

	volatile seq_t		receiveMaxExpected;	// the next to the right-border of the received area
	volatile int32_t	recvWindowNextPos;	// the index number of the block with receiveMaxExpected
	seq_t		recvWindowFirstSN;	// left-border of the receive window (receive queue), may be empty or may be filled but not delivered
	// it means that the receive queue is empty when recvWindowFirstSN == receiveMaxExpected
	// (next position, receive buffer maximum sn) (head position, receive window first sn)
	// are managed independently for maximum parallism in DLL and LLS
	int32_t		recvWindowHeadPos;	// the index number of the block with recvWindowFirstSN
	//
	int32_t		recvBufferBlockN;	// capacity of the receive buffer
	uint32_t	recvBuffer;			// relative to start of the control block
	uint32_t	recvBufDescriptors;	// relative to start of the control block

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
		bool GetFlag() { return (flags & (1 << i)) != 0; }
		//
		bool MarkInSending();
		void MarkUnsent() { flags &= ~(uint16_t)(1 << BIT_IN_SENDING); }
		//
		void ZeroFlags() { flags = 0; MarkUnsent(); }
	} *PFSP_SocketBuf;

	// Convert the relative address in the control block to the address in process space, unchecked
	BYTE * GetSendPtr(const PFSP_SocketBuf skb) const
	{
		return (BYTE *)this + sendBuffer
			+ MAX_BLOCK_SIZE * (skb - (PFSP_SocketBuf)((BYTE *)this + sendBufDescriptors));
	}
	BYTE * GetRecvPtr(const PFSP_SocketBuf skb) const
	{
		return (BYTE *)this + recvBuffer
			+ MAX_BLOCK_SIZE * (skb - (PFSP_SocketBuf)((BYTE *)this + recvBufDescriptors));
	}

	/**
	 * The negotiated connection parameter, deliberately placed just before the send/receive buffer control block
	 * somewhat works as a sentinel: if sessionKey is destroyed, the connection would eventually abort
	 */
	union
	{
		SConnectParam connectParams;
		BYTE sessionKey[FSP_SESSION_KEY_LEN];	// overlay with 'initCheckCode' and 'cookie'
	} u;
	vmac_ctx_t	mac_ctx;

	// 3 The (very short, roll-out) queue of returned notices
	volatile FSP_ServiceCode notices[FSP_MAX_NUM_NOTICE];
	// Backlog for listening/connected socket [for client it could be an alternate of Web Socket]
	TSingleProviderMultipleConsumerQ<BackLogItem>	backLog;

	// 7, 8 Send buffer and Receive buffer
	// See ControlBlock::Init()

	//
	PFSP_SocketBuf LOCALAPI GetVeryFirstSendBuf(seq_t initialSN)
	{
		PFSP_SocketBuf skb = HeadSend();
		skb->version = THIS_FSP_VERSION;
		skb->ZeroFlags();
		sendWindowExpectedSN = sendWindowNextSN = sendWindowFirstSN = initialSN;
		sendBufferNextSN = initialSN + 1;
		sendBufferNextPos = 1;
		sendWindowSize = 1;
		return skb;
	}
	PFSP_SocketBuf GetLastBufferedSend();
	int CountSendBuffered() { return int(sendBufferNextSN - sendWindowFirstSN); }

	PFSP_SocketBuf	GetSendBuf();
	// Return
	//	The send buffer block descriptor of the packet to send
	// Remark
	//	It is assumed that the caller knew there exists at least one packet in the queue
	//	Implement in a way different with that in LLS to maximize parallelism and avoid locking 
	PFSP_SocketBuf	PeekNextToSend()
	{
		register int i = sendBufferNextPos - int(sendBufferNextSN - sendWindowNextSN);
		return HeadSend() + (i < 0 ? i + sendBufferBlockN : i - sendBufferBlockN >= 0 ? i - sendBufferBlockN : i);
	}
	void * LOCALAPI InquireSendBuf(int &);
	int LOCALAPI	MarkSendQueue(void *, int, bool);

	//
	PFSP_SocketBuf LOCALAPI AllocRecvBuf(seq_t);
	int LOCALAPI FetchReceived(void *, fpDeliverData_t);
	int LOCALAPI GetSelectiveNACK(seq_t &, FSP_SelectiveNACK::GapDescriptor *, int) const;
	void * LOCALAPI InquireRecvBuf(int &, bool &);

	bool IsClosable();
	// Slide send window to skip all of the acknowledged. The caller should make sure it is legitimate
	void SlideSendWindow();
	//
	bool LOCALAPI ResizeSendWindow(seq_t, unsigned int);

	INT32 RecvWindowSize() const // in blocks, width of the receive window
	{
		int d = int(receiveMaxExpected - recvWindowFirstSN);
		return (d < 0 ? -1 : recvBufferBlockN - d);
	}

	PFSP_SocketBuf HeadSend() const { return (PFSP_SocketBuf)((BYTE *)this + sendBufDescriptors); }
	PFSP_SocketBuf HeadRecv() const { return (PFSP_SocketBuf)((BYTE *)this + recvBufDescriptors); }
	PFSP_SocketBuf FirstReceived() const { return HeadRecv() + recvWindowHeadPos; }

	bool HasBacklog() const { return backLog.count > 0; }
	bool LOCALAPI	HasBacklog(const BackLogItem *p);
	int LOCALAPI	PushBacklog(const BackLogItem *p);
	int LOCALAPI	PopBacklog(BackLogItem *p);
	int LOCALAPI	PushNotice(FSP_ServiceCode);
	FSP_ServiceCode PopNotice();

	int LOCALAPI	Init(int32_t, int32_t);
	int	LOCALAPI	Init(uint16_t);
};

#include <poppack.h>


class CSocketItem
{
public:
	// Property access of session state shared between DLL and LLS
	void SetReturned(LONG value = 0xA5A5C3C3) { pControlBlock->returned = value; }	// a 'magic' number for testability
	bool IsNotReturned() const { return (pControlBlock->returned == 0); }
	LONG ReturnedValue() const { return pControlBlock->returned; }
	//
protected:
	HANDLE	hMemoryMap;
	DWORD	dwMemorySize;	// size of the shared memory, in the mapped view
	HANDLE	hEvent;
	ALT_ID_T sessionID;
	ControlBlock *pControlBlock;

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
