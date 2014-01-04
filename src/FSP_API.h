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
#define FSPAPI __fastcall
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

typedef union
{
	unsigned long value;
	unsigned long *p;
}	ulong_ptr;



typedef struct FSP_SocketParameter *PFSP_Context;


#ifdef __cplusplus
	extern "C" {
#endif

// The call back function through which ULA tells FSP service whether to accept connection request
// Given
//	FSPHANDLE		the handle of the listener's socket
//	void *			the context	point to the RFC2292 packet control structure (local IPv4 address NOT converted)
//					exploit CMSG_FIRSTHDR, CMSG_NXTHDR and WSA_CMSG_DATA (CMSG_DATA) to access the header
//	PFSP_IN6_ADDR	the remote address that make the connection (address has been converted if IPv4)
// Return
//	zero (or positive integer) if to continue, negative if to abort
typedef int (FSPAPI *CallbackRequested)(FSPHANDLE, void *, PFSP_IN6_ADDR);


// The callback function through which the new FSP socket handle and the remote address are passed to ULA
// Given
//	FSPHANDLE		the handle of the new created socket
//	PFSP_InitParams	the context that used to created the socket (may be the listener's context)
//	PFSP_IN6_ADDR	the remote address that make the connection (address has been converted if IPv4)
// Remark
//	ULA may call Dispose if to abort the connection in the call back function
typedef void (FSPAPI *CallbackConnected)(FSPHANDLE, PFSP_Context, PFSP_IN6_ADDR);


// The callback function through which received message is passed to ULA
// Given
//	FSPHANDLE		the handle of the FSP socket (the context)
//	void *			the pointer to the (partial) message buffer
//	size_t			the length of the available (partial) message in bytes
//	bool			whether the message is unfinal/partial (to be continued)
// Return
//	true(positive non-zero) if processing is successful and the buffer should be release
//	false(zero) if processing has not finished and the receive buffer should be held
// Remark
//	the caller shall make the callback function thread-safe
typedef int (FSPAPI *CallbackPeeked)(FSPHANDLE, void *, size_t, bool);


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
	CallbackRequested	beforeAccept;	// may be NULL
	CallbackConnected	afterAccept;	// cannot be NULL
	NotifyOrReturn	onError;		// the pointer of the function called back on error, generally shall be set
	const void *	welcome;		// default welcome message, may be NULL
	unsigned short	len;			// length of the default welcome message
	union USocketFlags
	{
		struct
		{
			unsigned short	milky:		1;
			unsigned short	encrypting:	1;
			unsigned short	compressing:1;
			unsigned short	RESERVED:	12;
			unsigned short	passive:	1;	// internal use only, shall be ignored by ULA
		} st;
		unsigned short flags; //[_In_] the requested features [_Out] the error reason
	} u;
	int	ifDefault;	// default interface, only for send
	int recvSize;	// default size of the receive window
	int sendSize;	// default size of the send window
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
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error laterly
DllSpec
FSPHANDLE FSPAPI ConnectMU(FSPHANDLE, PFSP_Context);


// the API is designed in such a way that the callback function may utilize the buffer pointer immediately
DllSpec
int FSPAPI GetSendBuffer(FSPHANDLE, void **, int, NotifyOrReturn);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	bool		whether it is to be continued
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllSpec
int FSPAPI SendInline(FSPHANDLE, void *, int, bool);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	NotifyOrReturn	the callback function pointer
// Return
//	0 if no immediate error, negative if it failed, or positive it was warned (I/O pending)
// Remark
//	Only all data have been buffered may be NotifyOrReturn called. Return value passed in NotifyOrReturn is
//	the number of octets really scheduled to send which may be less or greater
//	than requested because of compression and/or encryption
//	NotifyOrReturn might report error even if WriteTo itself return no error
//	ULA should tell DLL whether the message is completed by call FSPControl. See also ReadFrom()
DllSpec
int FSPAPI WriteTo(FSPHANDLE, void *, int, NotifyOrReturn);


// given
//	the socket handle
//	the pointer to the function called back when peeking finished
// return 0 if no immediate error, or else the error number
// remark
//	if it failed, error number is reported through size_t parameter of 
//  the PeekCallback while the void * parameter passed will be NULL
DllSpec
int FSPAPI RecvInline(FSPHANDLE, CallbackPeeked);


// Given
//	FSPHANDLE		the FSP socket handle
//	void *			the start pointer of the receive buffer
//	int				the capacity in byte of the receive buffer
//	NotifyOrReturn	the function called back when either end of message reached,
//					connection terminated or receive buffer fulfilled
// Return
//	0 if no immediate error, negative if error
// Remark
//	ULA MUST call ReadFrom to accept data if the socket is compressing and/or encrypting
//	NotifyOrReturn is called when receive buffer is full OR end of message encountered
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	ULA should check whether the message is completed by calling DLL FSPControl. See also WriteTo()
DllSpec
int FSPAPI ReadFrom(FSPHANDLE, void *, int, NotifyOrReturn);



// Adjourn/pause the session by managing to flush all data-in-flight to the remote peer
// return 0 if no immediate error, or else the error number
// remark
//	NotifyOrReturn might return rejection of the adjournment
//	To resume just SendInline or WriteTo
DllSpec
int FSPAPI Adjourn(FSPHANDLE, NotifyOrReturn);



// Try to terminate the session gracefully
// return 0 if no immediate error, or else the error number
// remark
//	Unlike Adjourn, it is the onError function whose pointer was passed in the socket context parameter that
//	handle the final result of shutdown (0 if no error/shutdown gracefully, negative if timeout and so on)
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket);


// return 0 if no zero, negative if error, positive if warning
DllSpec
int FSPAPI Dispose(FSPHANDLE hFSPSocket);


// Given
//	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
//	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
//	ALT_ID_T		the session ID, in host byte order
// Return
//	the pointer to the place holder of host-id which might be set/updated later
// Remark
//	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
DllSpec
uint32_t * TranslateFSPoverIPv4(PFSP_IN6_ADDR, uint32_t, ALT_ID_T);


// When use FSPControl to enumerate interfaces,
// 'value' is the pointer to the first element of an array of IN6_PKTINFO structure
// and the 'ipi6_ifindex' field of the first element should store the size of the array
// return number of availabe interfaces with configured IPv4/IPv6 address
// which might be zero. negative if error.

// TODO: enumerate control code and its parameter type
DllSpec
int FSPControl(FSPHANDLE hFSPSocket, unsigned controlCode, ulong_ptr value);


DllSpec
bool EOMReceived(FSPHANDLE);


#ifdef __cplusplus
	}
#endif

#endif
