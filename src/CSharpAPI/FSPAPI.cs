using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace CSharpAPI
{
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public partial struct FSP_SocketParameter { };

    public enum FSP_ControlCode
    {
	    FSP_GET_SIGNATURE,			// pointer to the placeholder of the 64-bit signature
	    FSP_SET_COMPRESSION,		// 0: disable, 1: lz4, others: reserved
	    FSP_SET_CALLBACK_ON_ERROR,	// NotifyOrReturn
	    FSP_SET_CALLBACK_ON_FINISH,	// NotifyOrReturn
	    FSP_SET_CALLBACK_ON_CONNECT	// CallbackConnected
    };

    public enum FSP_ServiceCode: byte
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
	    FSP_NotifyRecycled = FSP_Recycle,		// a reverse command to inform DLL to release resource passively
	    FSP_NotifyAccepted = 16,
	    FSP_NotifyDataReady,
	    FSP_NotifyBufferReady,
	    FSP_NotifyReset,
	    FSP_NotifyFlushed,
	    FSP_NotifyToFinish,
	    FSP_NotifyFlushing, // 22: used to be FSP_Dispose
	    // 23: Reserved
	    // 24~: near end error status
	    FSP_MemoryCorruption = 24,
	    FSP_NotifyOverflow,
	    FSP_NotifyTimeout,
	    FSP_NotifyNameResolutionFailed,
	    LARGEST_FSP_NOTICE = FSP_NotifyNameResolutionFailed
    };

    public enum FlagEndOfMessage
    {
        NOT_END_ANYWAY = 0,
        END_OF_MESSAGE = 1,
        END_OF_TRANSACTION = 2
    };

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
    public delegate int CallbackRequested(IntPtr handle, IntPtr pSinkInf, IntPtr pIn6Addr);

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
    public delegate int CallbackConnected(IntPtr handle, ref FSP_SocketParameter pContext);

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
    public delegate int CallbackPeeked(IntPtr handle
        , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] Byte[] buffer, int size, bool toBeContinued);

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
    public delegate int CallbackBufferReady(IntPtr handle
        , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] Byte[] buffer, int size);

    // The function through which the FSP service informs ULA notification due to some particular
    // remote message received, or the return value of previous function call
    // Given
    //	FSPHANDLE		the handle of the FSP socket (the context)
    //	FSP_ServiceCode	the command code of the function call or notice code of the FSP service notification
    //	int				the intent returned value
    public delegate int NotifyOrReturn(IntPtr handle, FSP_ServiceCode code, int result);

    public partial struct FSP_SocketParameter
    {
	    public CallbackRequested	beforeAccept;	// may be NULL
        public CallbackConnected    afterAccept;	// cannot be NULL
        public NotifyOrReturn       onError;		// should be non-NULL
        public NotifyOrReturn       onFinish;		// on getting remote peer's RELEASE packet, may be NULL
        //
        public IntPtr welcome;		// default welcome message, may be NULL
        public UInt16 len;			// length of the default welcome message
        public UInt16 flags;       // bit 0: milky, bit 2: compressing; others are runtime or reserved
        public Int32 ifDefault;	// default interface, only for send
        //
        public Int32 recvSize;	// default size of the receive window
        public Int32 sendSize;	// default size of the send window
	    //
        public UInt64 signatureULA;
    };


    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct FSP_IN6_ADDR
    {
        public UInt64   subnet;
        public UInt32   idHost;
        public UInt32   idALF;
    };


    class FSPAPI
    {
        public const int CRYPTO_NACL_KEYBYTES = 32;

        // given
        //	the list of IPv6 addresses, ended with IN6ADDR_ANY_INIT
        //	the pointer to the socket parameter
        // return
        //	NULL if it fails immediately, or else
        //	the handle of the passive FSP socket, whose properties might be peek and/or set later
        // remark
        //	The handle returned might be useless, if NotifyOrReturn report error laterly
        [DllImport("FSP_DLL")]
        public static extern IntPtr ListenAt(ref FSP_IN6_ADDR bindPoint, ref FSP_SocketParameter context);

        // given
        //	the string name of the remote end, which might be the string representation of an IPv6 addresses or a DNS entry
        //	the pointer to the socket parameter
        // return
        //	the handle of the new created socket
        //	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
        // remark
        //	The handle returned might be useless, if CallbackConnected report error laterly
        [DllImport("FSP_DLL")]
        public static extern IntPtr Connect2(string peerURI, ref FSP_SocketParameter context);

        // given
        //	the handle of the FSP socket whose connection is to be duplicated,
        //	the pointer to the socket parameter
        // return
        //	the handle of the new created socket
        //	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
        // remark
        //	The handle returned might be useless, if CallbackConnected report error laterly
        [DllImport("FSP_DLL")]
        public static extern IntPtr ConnectMU(IntPtr handle, ref FSP_SocketParameter context);

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
        [DllImport("FSP_DLL")]
        public static extern int InstallAuthenticKey(IntPtr handle
            , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=2)]Byte[] sharedKey, int keyLenth
            , Int32 keyLife, FlagEndOfMessage eomFlag);

        // given
        //	the handle of the FSP socket to request send buffer for,
        //	the minimum requested size of the buffer,
        //	the pointer to the callback function
        // return
        //	negative if error, or the capacity of immediately available buffer (might be 0)
        [DllImport("FSP_DLL")]
        public static extern int GetSendBuffer(IntPtr handle, int sizeRequested, CallbackBufferReady callback);

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
        [DllImport("FSP_DLL")]
        public static extern int SendInline(IntPtr handle, IntPtr buffer, int size, FlagEndOfMessage eomFlag);

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
        [DllImport("FSP_DLL")]
        public static extern int WriteTo(IntPtr handle
            , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]Byte[] message, int len
            , FlagEndOfMessage eomFlag, NotifyOrReturn callback);

        // given
        //	the socket handle
        //	the pointer to the function called back when peeking finished
        // return 0 if no immediate error, or else the error number
        // remark
        //	if it failed, when CallbackPeeked is called the first parameter is passed with NULL
        //	while the second parameter is passed with the error number
        //	currently the implementation limit the maximum message size of each peek to 2GB
        [DllImport("FSP_DLL")]
        public static extern int RecvInline(IntPtr handle, CallbackPeeked callback);

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
        [DllImport("FSP_DLL")]
        public static extern int ReadFrom(IntPtr handle
            , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]Byte[] buffer, int capacity
            , NotifyOrReturn callback);

        // Try to terminate the session gracefully, automatically commit if not yet 
        // Return 0 if no immediate error, or else the error number
        // The callback function might return code of delayed error
        [DllImport("FSP_DLL")]
        public static extern int Shutdown(IntPtr handle, NotifyOrReturn callback);

        // return 0 if no zero, negative if error, positive if warning
        [DllImport("FSP_DLL")]
        public static extern int Dispose(IntPtr handle);

        // Given
        //	PFSP_IN6_ADDR	the place holder of the output FSP/IPv6 address
        //	uint32_t		the 32-bit integer representation of the IPv4 address to be translated
        //	ALFID_T			the application layer fiber ID, in neutral byte order
        // Return
        //	the pointer to the place holder of host-id which might be set/updated later
        // Remark
        //	make the rule-adhered IPv6 address, the result is placed in the given pointed place holder
        [DllImport("FSP_DLL")]
        public static extern UIntPtr TranslateFSPoverIPv4(ref FSP_IN6_ADDR outIn, UInt32 ipv4, UInt32 idALF);

        // yet to be documented
        [DllImport("FSP_DLL")]
        public static extern int FSPControl(IntPtr handle, FSP_ControlCode code, IntPtr value);
    }
}
