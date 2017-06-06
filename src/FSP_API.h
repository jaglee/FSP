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

#ifdef _MSC_VER
#define FSPAPI __stdcall
#else
#define FSPAPI
#endif

#ifndef FSPHANDLE
#define FSPHANDLE void *	// the pointer to some entry in the translate look-aside table
#endif

#define INVALID_FSPHANDLE_VALUE NULL

#ifndef DllSpec
#define DllSpec
#endif

#define MAX_FSP_SHM_SIZE		0x400000	// 4MB

#if defined(_M_X64) || defined(_M_IA64)
    typedef unsigned __int64 ulong_ptr;
#else
    typedef unsigned long ulong_ptr;
#endif

typedef unsigned char octet;

typedef struct FSP_SocketParameter *PFSP_Context;

typedef enum
{
	FSP_GET_SIGNATURE,			// pointer to the placeholder of the 64-bit signature
	FSP_SET_SIGNATURE,			// pointer to the placeholder of the 64-bit signature
	FSP_SET_CALLBACK_ON_ERROR,	// NotifyOrReturn
	FSP_SET_CALLBACK_ON_REQUEST,// CallbackRequested
	FSP_SET_CALLBACK_ON_CONNECT,// CallbackConnected
	FSP_GET_PEER_COMMITTED,
} FSP_ControlCode;



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
//	unity (positive integer) is to do a transactional send-receive),
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
//	BOOL			whether the peer has committed the tansmit transaction
// Return
//	true(positive non-zero) if processing is successful and the buffer should be release
//	false(zero) if processing has not finished and the receive buffer should be held
// Remark
//	the caller shall make the callback function thread-safe
typedef int (FSPAPI *CallbackPeeked)(FSPHANDLE, void *, int32_t, BOOL);


// The pointer of the function callbacked when some inline send buffer is available
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	void *			the start position pointer of the available send buffer
//	int32_t			the capacity of the available send buffer in bytes
// Return
//	0 if no error and further availabililty of buffer should be reported
//	negative if to be discontinued
// Remark
//	the caller shall make the callback function thread-safe
typedef int (FSPAPI *CallbackBufferReady)(FSPHANDLE, void *, int32_t);


// The function through which the FSP service informs ULA notification due to some particular
// remote message received, or the return value of previous function call
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	FSP_ServiceCode	the command code of the function call or notice code of the FSP service notification
//	int				the intent returned value
typedef void (FSPAPI *NotifyOrReturn)(FSPHANDLE, FSP_ServiceCode, int);

#ifdef __cplusplus
	};
#endif


struct FSP_SocketParameter
{
	CallbackRequested	onAccepting;	// may be NULL, cannot be NULL for cloning offspring
	CallbackConnected	onAccepted;		// cannot be NULL
	NotifyOrReturn		onError;		// should be non-NULL
	//
	const void *	welcome;		// default welcome message, may be NULL
	unsigned short	len;			// length of the default welcome message
	union
	{
		struct
		{
			unsigned short	milky:		1;
			unsigned short	RESERVED:	13;
			unsigned short	passive:	1;	// internal use only, shall be ignored by ULA
			unsigned short	isError:	1;	// if set, 'flags' is the error reason
		};
		short flags;	// [_In_: >= 0] the requested features [_Out_: might < 0] the error reason
	};
	int32_t		ifDefault;	// default interface, only for send
	//
	int32_t		recvSize;	// [_In_] default size of the receive window [_Out] size of the allocated receive buffer segment
	int32_t		sendSize;	// [_In_] default size of the send window	 [_Out] size of the allocated send buffer segment
	//
	uint64_t	signatureULA;
};



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
//	The handle returned might be useless, if NotifyOrReturn report error laterly
DllSpec
FSPHANDLE FSPAPI ListenAt(const PFSP_IN6_ADDR, PFSP_Context);


// given
//	the string name of the remote end, which might be the string representation of an IPv6 addresses or a DNS entry
//	the pointer to the socket parameter
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error laterly
DllSpec
FSPHANDLE FSPAPI Connect2(const char *, PFSP_Context);


// given
//	the handle of the FSP socket whose connection is to be duplicated,
//	the pointer to the socket parameter
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
//	NotifyOrReturn	the callback function pointer
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error laterly
DllSpec
FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, int8_t, NotifyOrReturn);



// given
//	the handle of the FSP socket whose connection is to be duplicated,
//	the pointer to the socket parameter
//	[inout] pointer to the placeholder of an integer specifying the the minimum requested size of the buffer
//	the pointer to the callback function
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error laterly
//	the capacity of immediately available buffer (might be 0) is outputted in the reference
DllSpec
FSPHANDLE FSPAPI MultiplyAndGetSendBuffer(FSPHANDLE, PFSP_Context, int *, CallbackBufferReady);


// given
//	the handle of the FSP socket to install the session key
//	the buffer of the key
//	the length of the key in bytes
//	the life of the key in terms of number of packets allowed to send or resend
// return
//	0 if no error
//	-EDOM	if parameter domain error
//	-EFAULT if unexpected exception
//	-EINTR	if cannot obtain the right lock
//	-EIO	if cannot trigger LLS to do the installation work through I/O
DllSpec
int FSPAPI InstallAuthenticKey(FSPHANDLE, uint8_t *, int, int32_t);



// given
//	the handle of the FSP socket to request send buffer for,
//	the minimum requested size of the buffer,
//	the pointer to the callback function
// return
//	negative if error, or the capacity of immediately available buffer (might be 0)
DllSpec
int FSPAPI GetSendBuffer(FSPHANDLE, int, CallbackBufferReady);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllSpec
int FSPAPI SendInline(FSPHANDLE, void *, int, int8_t);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	int8_t	
//		0:		do not terminate the transmit transaction
//		EOF:	terminate the transaction
//	NotifyOrReturn	the callback function pointer
// Return
//	non-negative if it is the number of octets put into the queue immediately. might be 0 of course.
//	negative if it failed
// Remark
//	Only all data have been buffered may be NotifyOrReturn called.
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until every octet in the given buffer has been passed to LLS. See also ReadFrom
DllSpec
int FSPAPI WriteTo(FSPHANDLE, void *, int, int8_t, NotifyOrReturn);


// given
//	the socket handle
//	the pointer to the function called back when peeking finished
// return 0 if no immediate error, or else the error number
// remark
//	if it failed, when CallbackPeeked is called the first parameter is passed with NULL
//	while the second parameter is passed with the error number
//	currently the implementation limit the maximum message size of each peek to 2GB
DllSpec
int FSPAPI RecvInline(FSPHANDLE, CallbackPeeked);


// Given
//	FSPHANDLE		the FSP socket handle
//	void *			the start pointer of the receive buffer
//	int				the capacity in byte of the receive buffer
//	NotifyOrReturn	the function called back when either EoT reached,
//					connection terminated or receive buffer fulfilled
// Return
//	positive if it is the number of octets received immediately
//	0 if no immediate error while NotifyOrReturn is not NULL
//	negative if error
// Remark
//	NotifyOrReturn is called when receive buffer is full OR end of transaction encountered
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	If NotifyOrReturn is NULL the function is blocking, i.e.
//	waiting until either the buffer is fulfilled or the peer's transmit transactin has been committed
//	ULA should check whether the transmit transaction is committed by calling FSPControl. See also WriteTo
DllSpec
int FSPAPI ReadFrom(FSPHANDLE, void *, int, NotifyOrReturn);



// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	EBUSY warning if it is COMMITTING
//	0 if no error
//	-EDEADLK if no mutual-exclusive lock available
//	-EBADF if the socket is in abnormal state
//	-EAGAIN if commit more than once, which may render dead-lock
//	-EFAULT if internal resource error encountered, typical time-out clock unavailable
//	-EIO if the packet piggyback EoT flag cannot be sent
DllSpec
int FSPAPI Commit(FSPHANDLE, NotifyOrReturn);



// Given
//	FSPHANDLE		the FSP socket
//	NotifyOrReturn	the function pointer for call back
// Return
//	EDOM warning if the connection is to shutdown prematurely, i.e. it is a RESET actually
//	EBUSY warning if it is COMMITTING
//	EAGAIN warning if the connection is already in the progress of shutdown
//	0 if no error
//	-EDEADLK if no mutual-exclusive lock available
//	-EBADF if the socket is in abnormal state
//	-EFAULT if internal resource error encountered, typical time-out clock unavailable
//	-EIO if the shutdown packet cannot be sent
// Remark
//	It is assumed that when Shutdown was called ULA did not expect further data from the remote end
//	The caller should make sure Shutdown is not carelessly called more than once
//	in a multi-thread continual communication context or else connection reuse(resurrection) may be broken
// If the pointer of the callback function is null, 
// blocks until it reaches the state that the transmit transaction has been comitted
DllSpec
int FSPAPI Shutdown(FSPHANDLE, NotifyOrReturn);


// return 0 if no zero, negative if error, positive if warning
DllSpec
int FSPAPI Dispose(FSPHANDLE hFSPSocket);


// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	ALFID_T			the application layer fiber ID, in neutral byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
DllSpec
uint32_t * FSPAPI TranslateFSPoverIPv4(PFSP_IN6_ADDR, uint32_t, ALFID_T);


DllSpec
int FSPAPI FSPControl(FSPHANDLE, FSP_ControlCode, ulong_ptr);


// Exported by the DLL
DllSpec
timestamp_t NowUTC();

#ifdef __cplusplus
	}
#endif

#endif
