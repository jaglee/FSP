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
#define CRYPTO_NACL_KEYBYTES	32

#if defined(_M_X64) || defined(_M_IA64)
    typedef unsigned __int64 ulong_ptr;
#else
    typedef unsigned long ulong_ptr;
#endif


typedef struct FSP_SocketParameter *PFSP_Context;

typedef enum
{
	FSP_GET_SIGNATURE,			// pointer to the placeholder of the 64-bit signature
	FSP_SET_COMPRESSION,		// 0: disable, 1: lz4, others: reserved
	FSP_SET_CALLBACK_ON_ERROR,	// NotifyOrReturn
	FSP_SET_CALLBACK_ON_FINISH,	// NotifyOrReturn
	FSP_SET_CALLBACK_ON_CONNECT	// CallbackConnected
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
//	bool			whether the message is unfinal/partial (to be continued)
// Return
//	true(positive non-zero) if processing is successful and the buffer should be release
//	false(zero) if processing has not finished and the receive buffer should be held
// Remark
//	the caller shall make the callback function thread-safe
typedef int (FSPAPI *CallbackPeeked)(FSPHANDLE, void *, int32_t, bool);


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
	CallbackRequested	beforeAccept;	// may be NULL
	CallbackConnected	afterAccept;	// cannot be NULL
	NotifyOrReturn		onError;		// should be non-NULL
	NotifyOrReturn		onFinish;		// on getting remote peer's RELEASE packet, may be NULL
	//
	const void *	welcome;		// default welcome message, may be NULL
	unsigned short	len;			// length of the default welcome message
	union USocketFlags
	{
		struct
		{
			unsigned short	milky:		1;
			unsigned short	RESERVED_AE:1;	// reserved for further authenticated encryption
			unsigned short	compressing:1;
			unsigned short	RESERVED:	11;
			unsigned short	eom:		1;	// end of message, a run-time flag
			unsigned short	passive:	1;	// internal use only, shall be ignored by ULA
		} st;
		unsigned short flags; //[_In_] the requested features [_Out] the error reason
	} u;
	int32_t		ifDefault;	// default interface, only for send
	//
	int32_t		recvSize;	// default size of the receive window
	int32_t		sendSize;	// default size of the send window
	//
	uint64_t	signatureULA;
};



//	Choice of the flag:
//		0: not finshed more data to follow
//		1: it is the trail of the containing message
//		2: it is the last message of the transaction on the particular transmit direction
enum FlagEndOfMessage
{
	NOT_END_ANYWAY = 0,
	END_OF_MESSAGE = 1,
	END_OF_TRANSACTION = 2
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
//	FlagEndOfMessage
//	NotifyOrReturn	the callback function pointer
// return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// remark
//	The handle returned might be useless, if CallbackConnected report error laterly
DllSpec
FSPHANDLE FSPAPI MultiplyAndWrite(FSPHANDLE, PFSP_Context, FlagEndOfMessage, NotifyOrReturn);



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
//	FlagEndOfMessage, NOT_END_ANYWAY if it is the final initiator, END_OF_TRANSACTION the final responder
// return
//	0 if no error
//	-EDOM if parameter domain error
//	-EFAULT if unexpected exception
//	-EIO if I/O interface error between the message layer and the packet layer
DllSpec
int FSPAPI InstallAuthenticKey(FSPHANDLE, uint8_t *, int, int32_t, FlagEndOfMessage);



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
//	FlagEndOfMessage
// Return
//	number of octets really scheduled to send
// Remark
//	The buffer MUST begin from what GetSendBuffer has returned and
//	may not exceed the capacity that GetSendBuffer has returned
//	if the buffer is to be continued, its size MUST be multiplier of MAX_BLOCK_SIZE
//	SendInline could be chained in tandem with GetSendBuffer
DllSpec
int FSPAPI SendInline(FSPHANDLE, void *, int, enum FlagEndOfMessage);


// Given
//	FSPHANDLE	the socket handle
//	void *		the buffer pointer
//	int			the number of octets to send
//	FlagEndOfMessage
//	NotifyOrReturn	the callback function pointer
// Return
//	0 if no immediate error, negative if it failed, or positive it was warned (I/O pending)
// Remark
//	Return value passed in NotifyOrReturn is the number of octets really scheduled to send
//	which may be less or greater than requested because of compression and/or encryption
//	Only all data have been buffered may be NotifyOrReturn called.
DllSpec
int FSPAPI WriteTo(FSPHANDLE, void *, int, enum FlagEndOfMessage, NotifyOrReturn);


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
//	NotifyOrReturn	the function called back when either end of message reached,
//					connection terminated or receive buffer fulfilled
// Return
//	0 if no immediate error, negative if error
// Remark
//	NotifyOrReturn is called when receive buffer is full OR end of message encountered
//	NotifyOrReturn might report error later even if ReadFrom itself return no error
//	Return value passed in NotifyOrReturn is number of octets really received
//	ULA should check whether the message is completed by calling DLL FSPControl. See also WriteTo()
DllSpec
int FSPAPI ReadFrom(FSPHANDLE, void *, int, NotifyOrReturn);


// Try to terminate the session gracefully, automatically commit if not yet 
// Return 0 if no immediate error, or else the error number
// The callback function might return code of delayed error
DllSpec
int FSPAPI Shutdown(FSPHANDLE hFSPSocket, NotifyOrReturn);


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


// Given
//	pointer to the buffer of exported public key
//	pointer to the buffer of exported private key
// Do
//	Generate the public-private key pair
// Return
//	0 (always succeed in presumed constant time)
DllSpec
int FSPAPI CryptoNaClKeyPair(unsigned char *bufPublicKey, unsigned char *bufPrivateKey);


// Given
//	pointer to the buffer of the shared secret, crypto_core_hsalsa20_tweet_KEYBYTES = 32 bytes
//	the byte string of the peer's public key
//	the byte string of the near end's private key
// Do
//	Derive the shared secret
// Return
//	0 (always succeed in presumed constant time)
DllSpec
int FSPAPI CryptoNaClGetSharedSecret(unsigned char *bufSharedSecret, const unsigned char *peersPublicKey, const unsigned char *nearPrivateKey);


// Given
//	pointer to the buffer of the output hash, 64 bytes
//	the input byte string to calculate the hash
//	the length of the byte string
// Do
//	get the SHA512 result
// Return
//	0 (always succeed in presumed constant time)
DllSpec
int FSPAPI CryptoNaClHash(unsigned char *buf, const unsigned char *input, unsigned long long len);

#ifdef __cplusplus
	}
#endif

#endif
