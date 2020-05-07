#ifndef _FSP_API_H
#define _FSP_API_H

/*
 * Flexible Session Protocol, Application Programming Interface definitions
 * shared between the upper layer application and the dynamic-linked library
 * the header files depended by this included file are included by force
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

// About bool type: assume the compiler support C99, or <stdbool.h> is included

#ifdef _MSC_VER
#define FSPAPI __stdcall
#else
#define FSPAPI
#endif

#ifndef FSPHANDLE
#define FSPHANDLE void *	// the pointer to some entry in the translate look-aside table
#endif

#ifndef DllSpec
#define DllSpec
#endif

#ifdef NDEBUG	// Run-time default for release version
# define MAX_FSP_SHM_SIZE		0x4000000	// 64MB
#elif !defined(MAX_FSP_SHM_SIZE)
# define MAX_FSP_SHM_SIZE		0x100000	// 1MB
#endif

typedef struct FSP_SocketParameter *PFSP_Context;

typedef enum
{
	FSP_GET_EXT_POINTER,		// Placeholder to store the pointer meant to access the extent of the socket
	FSP_SET_EXT_POINTER,		// Value of the pointer meant to access the extent of the socket
	FSP_SET_CALLBACK_ON_ERROR,	// NotifyOrReturn
	FSP_SET_CALLBACK_ON_REQUEST,// CallbackRequested
	FSP_SET_CALLBACK_ON_CONNECT,// CallbackConnected
	FSP_GET_PEER_COMMITTED,
} FSP_ControlCode;


enum FSP_SendOption
{
	TO_END_TRANSACTION = 0x80,
	TO_COMPRESS_STREAM = 0x40,
};


#ifdef __cplusplus
	extern "C" {
#endif

// The call back function through which ULA tells FSP service whether to accept connection request
// Given
//	FSPHANDLE		the handle of the listener's socket
//	PFSP_SINKINF	the context	point to the RFC2292 packet control structure (local IPv4 address NOT converted)
//					exploit CMSG_FIRSTHDR, CMSG_NXTHDR and WSA_CMSG_DATA (CMSG_DATA) to access the header
//	PFSP_IN6_ADDR	the remote address that make the connection (address has been converted if IPv4)
// Return
//	unity (positive integer) is to do a transactional send-receive,
//	zero if to continue,
//	negative if to abort
typedef int (FSPAPI *CallbackRequested)(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);


// The callback function through which the new FSP socket handle and the remote address are passed to ULA
// Given
//	FSPHANDLE		the handle of the new created socket
//	PFSP_InitParams	the context that used to created the socket (may be the listener's context)
// Return
//	1	OK, but only one packet is to be sent (transactional)
//	0	OK, no special processing needed, to keep connection
//	-1	negative, to reset the connection
// Remark
//	ULA may call Dispose if to abort the connection in the call back function
//	There used to be the third parameter with the type 'CMSGHDR *' which requires advanced IPv6 API support
//	Now the caller may get the near-side lower-layer control information via FSPControl
typedef int (FSPAPI *CallbackConnected)(FSPHANDLE, PFSP_Context);


// The callback function through which received message is passed to ULA
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	void *			the pointer to the (partial) message buffer
//	int32_t			the length of the available (partial) message in bytes
//	bool			whether the peer has committed the transmit transaction
// Return
//	true if to continue applying this callback function to accept further data
//	false if to discontinue
// Remark
//	the caller shall make the callback function thread-safe
typedef bool (FSPAPI *CallbackPeeked)(FSPHANDLE, void *, int32_t, bool);


// The pointer of the function call-backed when some inline send buffer is available
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	void *			the start position pointer of the available send buffer
//	int32_t			the capacity of the available send buffer in bytes
// Return
//	0 if no error and further availability of buffer should be reported
//	negative if to be discontinued
// Remark
//	the caller shall make the callback function thread-safe
//	the callback function should consume at least one buffer block to avoid possible dead-loop
typedef int (FSPAPI *CallbackBufferReady)(FSPHANDLE, void *, int32_t);


// The function through which the FSP service informs ULA notification due to some particular
// remote message received, or the return value of previous function call
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	FSP_ServiceCode	the command code of the function call
//	int				the intent returned value
typedef void (FSPAPI *NotifyOrReturn)(FSPHANDLE, FSP_ServiceCode, int);

// A paramenter for argument of NotifyOrReturn type, meant to ignore some LLS notice
DllSpec void FSPAPI FSP_IgnoreNotice(FSPHANDLE, FSP_ServiceCode, int);

#ifdef __cplusplus
	}
#endif


#pragma pack(push)
#pragma pack(1)
struct FSP_SocketParameter
{
	CallbackRequested	onAccepting;	// NULL if synchronous accepting, non-NULL if asynchronous
	CallbackConnected	onAccepted;		// SHOULD be non-NULL for sake of piggybacking payload
	NotifyOrReturn		onError;		// SHOULD be non-NULL

	const void *		welcome;		// default welcome message, may be NULL
	int32_t				len;			// length of the default welcome message

	union
	{
		struct
		{
			unsigned short	milky:		1;	// Minimal-delay service preferred
			unsigned short	noEncrypt:	1;	// do not encrypt the payload in the transport layer
			unsigned short	precompress:1;	// data to send on connect ready were pre-compressed
			unsigned short	tfrc:		1;	// TCP friendly rate control. By default ECN-friendly
			unsigned short	keepAlive : 1;	// The connection should be kept alive. By default timed-out automatically
			unsigned short	RESERVED:	9;
			unsigned short	passive:	1;	// internal use only, shall be ignored by ULA
			unsigned short	isError:	1;	// if set, 'flags' is the error reason
		};
		short flags;	// [_In_: >= 0] the requested features [_Out_: might < 0] the error reason
	};
	short		ifDefault;	// default interface, only for send
	//
	int32_t		recvSize;	// [_In_] default size of the receive window [_Out] size of the allocated receive buffer segment
	int32_t		sendSize;	// [_In_] default size of the send window	 [_Out] size of the allocated send buffer segment
	//
	uint64_t	extentI64ULA;
};
#pragma pack(pop)

// If not specified otherwise, any function that returns integer return
//	-EBADF if the handler given is invalid
//	-EDEADLK if cannot obtain the mutex lock
//	-EINTR if the connection is/has been interrupted by LLS
//	-EINVAL	if parameter domain error

#ifdef __cplusplus
	extern "C" {
#endif

// given
//	the list of IPv6 addresses, ended with IN6ADDR_ANY_INIT
//	the pointer to the socket parameter
// return
//	NULL if it fails immediately, or else
//	the handle of the passive FSP socket, whose properties might be peek and/or set later
// remark
//	The handle returned might be useless, if NotifyOrReturn report error later
DllSpec
FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR, PFSP_Context);


// Given
//	FSPHANDLE	the listening socket
// Return
//	One FSP socket that accepts remote connection request
// Remark
//	This function is blocking, called only
//	when the function pointer onAccepting is NULL in the socket parameter of ListenAt.
DllSpec
FSPHANDLE FSPAPI Accept1(FSPHANDLE);


// given
//	the string name of the remote end, which might be the string representation of an IPv6 addresses or a DNS entry
//	the pointer to the socket parameter
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error later
DllSpec
FSPHANDLE FSPAPI Connect2(const char *, PFSP_Context);


// given
//	the handle of the FSP socket whose connection is to be duplicated,
//	the pointer to the socket parameter
//	the send options (TO_END_TRANSACTION, TO_COMPRESS_STREAM)
//	NotifyOrReturn	the callback function pointer
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error later
DllSpec
FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, unsigned, NotifyOrReturn);


// given
//	the handle of the FSP socket whose connection is to be duplicated,
//	the pointer to the socket parameter
//	the pointer to the callback function
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error later
//	the capacity of immediately available buffer (might be 0) is outputted in the reference
DllSpec
FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE, PFSP_Context, CallbackBufferReady);


// given
//	the handle of the FSP socket to install the master key
//	the buffer of the key
//	the length of the key in bytes
// return
//	0 if no error
//	-EIO	if cannot trigger LLS to do the installation work through I/O
DllSpec
int FSPAPI InstallMasterKey(FSPHANDLE, octet *, int32_t);


// given
//	the handle of the FSP socket to request send buffer for,
//	the pointer to the callback function
// return
//	negative if error, or the capacity of immediately available buffer (might be 0)
//	(-EBUSY if previous asynchronous send has not finished yet)
DllSpec
int32_t FSPAPI GetSendBuffer(FSPHANDLE, CallbackBufferReady);


// given
//	the handle of the FSP socket to request send buffer for,
//	placeholder of the pointer to the capacity available
// return
//	NULL if no immediately available buffer
//	or the pointer to the free send buffer
// remark
//	the capacity might be negative if error occurred, or 0 if no immediately available buffer
DllSpec
void* FSPAPI TryGetSendBuffer(FSPHANDLE, int32_t*);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int32_t		the number of octets to send
//	bool		EoT, whether to terminate the transmit transaction
//	NotifyOrReturn	the pointer to the callback function if EoT
// Return
//	zero or positive, number of payload octets in the send queue
//	negative if it is the error number
//	-EBUSY if previous transmit transaction has not been committed yet
//	-ENOMEM if no enough memory available
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	If it is to commit the transmit transaction the callback function
//	is called if and only if all packets sent are acknowledged
//	If it is not to commit the transmit transaction	the callback function
//	will be ignored and the number of octets to send
//	MUST be multiple of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllSpec
int32_t FSPAPI SendInline(FSPHANDLE, void *, int32_t, bool, NotifyOrReturn);


// Given
//	FSPHANDLE	the socket handle
//	const void *the buffer pointer
//	int32_t		the number of octets to send
//	unsigned	the send options (TO_END_TRANSACTION, TO_COMPRESS_STREAM)
//	NotifyOrReturn	the callback function pointer
// Return
//	non-negative if it is the number of octets put into the queue immediately. might be 0.
//	negative if it failed
//	-EADDRINUSE if previous send is not finished and internal buffer address is in use
//	-EBUSY		if cannot commit the transmit transaction (if requested) on time
//	-ENOMEM		if no enough available for buffering compression state
// Remark
//	Only all data have been buffered may be NotifyOrReturn called.
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until every octet in the given buffer has been passed to LLS.
DllSpec
int32_t FSPAPI WriteTo(FSPHANDLE, const void *, int32_t, unsigned, NotifyOrReturn);


// given
//	the socket handle
//	the pointer to the function called back when peeking finished
// return 0 if no immediate error, or else the error number
//	-EADDRINUSE	if previous receive is not finished and internal buffer address is in use
//	-EDOM		if internal state prevents it from receiving in inline mode
//	-EFAULT		if internal state chaos found
// remark
//	if it failed, when CallbackPeeked is called the first parameter is passed with NULL
//	while the second parameter is passed with the error number
//	currently the implementation limit the maximum message size of each peek to 2GB
//	each calling of the function should accept one and only one transmit transaction from the peer
DllSpec
int FSPAPI RecvInline(FSPHANDLE, CallbackPeeked);


// given
//	the socket handle
//	the placeholder of the length of data received, in octets
//	the placeholder of the boolean variable, EoT flag
// return
//	NULL if error occurred, and the length of the data shall be set to negative number as the error number
//	the pointer to the start position of the received data, while the length of the data is either zero or positive
// remark
//	the EoT flag may be set even if the return value is zero, which is not an error
//	to accept further data following reading function would automatically unlock the buffer returned by this function
DllSpec
void* FSPAPI TryRecvInline(FSPHANDLE, int32_t*, bool*);


// Given
//	FSPHANDLE		the FSP socket handle
//	void *			the start pointer of the receive buffer
//	int				the capacity in byte of the receive buffer
//	NotifyOrReturn	the function called back when either EoT reached,
//					connection terminated or receive buffer fulfilled
// Return
//	positive if it is the number of octets received immediately
//	0 if no immediate error while NotifyOrReturn is not NULL
//	-EADDRINUSE	if previous receive is not finished and internal buffer address is in use
//	-EBUSY		if previous asynchronous read has not finished yet
//	-EFAULT		if the packet buffer was broken
//	-ENOMEM		if it is to decompress, but there is no enough memory for internal buffer
// Remark
//	NotifyOrReturn is called when receive buffer is full OR end of transaction encountered
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until either the buffer is fulfilled or the peer's transmit transaction has been committed
//	In the blocking mode DLL MAY report that the transmit transaction has been committed
//	before all data has been fetched
//	ULA should check whether the transmit transaction is committed by calling FSPControl. See also WriteTo
DllSpec
int FSPAPI ReadFrom(FSPHANDLE, void *, int, NotifyOrReturn);


// Return whether previous ReadFrom has encountered an end-of-transaction mark. DOES NOT work with ReadInline!
// A shortcut for FSPControl(FSPHANDLE, FSP_GET_PEER_COMMITTED, ...);
DllSpec
bool FSPAPI HasReadEoT(FSPHANDLE);


// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	0 if no error
//	-EAGAIN if commit more than once, which may render dead-lock
//	-EBUSY if can not reach target state in the limited time
//	-EDOM if internal state chaos found
//	-EFAULT	if internal resource error encountered
// Remark
//	Would block until the connection is CLOSABLE, closed or reset if the function pointer is NULL
DllSpec
int FSPAPI Commit(FSPHANDLE, NotifyOrReturn);


// Given
//	FSPHANDLE		the FSP socket
// Return
//	0 if no error
//	negative if some common error
// Remark
//	Unlike Commit, the last packet is not necessarily marked EoT
//	For compatibility with TCP byte-stream transmission
DllSpec
int FSPAPI Flush(FSPHANDLE);



// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Do
//	Set the function to be called back on passively shutdown by the remote end
// Return
//	0 if no error
//	EAGAIN if the socket has already been shut down
// Remark
//	The pointer of the callback function CANNOT be null
DllSpec
int FSPAPI SetOnRelease(FSPHANDLE, NotifyOrReturn);



// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	EAGAIN warning if the connection is already in the progress of shutdown
//	ETIMEOUT warning if the connection is already CLOSABLE but fails to migrate to CLOSED state timely
//	0 if no error
//	-EBUSY if it is still committing while the function is called in blocking mode
//	-EDOM if the peer has not committed the transmit transaction at first
// Remark
//	If the pointer of the callback function is null,
//	it would block the caller until the connection is closed or reset
DllSpec
int FSPAPI Shutdown(FSPHANDLE, NotifyOrReturn);


// Given
//	FSPHANDLE		the FSP socket
// Return
//	0 if no error
//	negative if error
// Remark
//	It is blocking in the sense that it waits locked operation to exit
DllSpec
int FSPAPI Dispose(FSPHANDLE hFSPSocket);


// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	ULTID_T			the upper layer thread ID/application layer fiber ID, in network byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
DllSpec
uint32_t * FSPAPI TranslateFSPoverIPv4(PFSP_IN6_ADDR, uint32_t, ULTID_T);


DllSpec
int FSPAPI FSPControl(FSPHANDLE, FSP_ControlCode, ULONG_PTR);


// Return the extent pointer set by ULA, either stored directly in FSP_SocketParameter.extentI64ULA
// or set by calling FSPControl(FSPHANDLE, FSP_SET_EXT_POINTER, ...);
// A shortcut for FSPControl(FSPHANDLE, FSP_GET_EXT_POINTER, ...);
DllSpec
void * FSPAPI GetExtPointer(FSPHANDLE);


DllSpec
PFSP_Context FSPAPI GetFSPContext(FSPHANDLE);


DllSpec
int FSPAPI GetProfilingCounts(FSPHANDLE, PSocketProfile);


// Exported by the DLL
DllSpec
timestamp_t NowUTC();

// For sake of unit test:
DllSpec
FSPHANDLE FSPAPI CreateFSPHandle();

DllSpec
void FSPAPI FreeFSPHandle(FSPHANDLE);

#ifdef __cplusplus
	}
#endif

#endif
