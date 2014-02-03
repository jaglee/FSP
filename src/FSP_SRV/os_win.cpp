#define _CRT_RAND_S
#include <stdlib.h>
#include "fsp_srv.h"

#include <Iphlpapi.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSTcpIP.h>

#include <process.h>
#include <io.h>
#include <fcntl.h>


#define REPORT_WSAERROR_TRACE(s) (\
	printf("\n/**\n * %s, line# %d\n * %s\n */\n", __FILE__, __LINE__, __FUNCDNAME__), \
	ReportWSAError(s)\
	)

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")

CLowerInterface	* CLowerInterface::pSingleInstance;
HANDLE	TimerWheel::timerQueue;

static LPFN_WSARECVMSG	WSARecvMsg;

static int LOCALAPI ReportWSAError(char * msg);

// eventually IPv6 version
inline int BindInterface(SOCKET sd, PSOCKADDR_IN6 pAddrListen);

// abstract out for sake of testability
inline int GetPointerOfWSARecvMsg(SOCKET sd)
{
	GUID funcID = WSAID_WSARECVMSG;
	DWORD bytesReturned;
	return WSAIoctl(sd, SIO_GET_EXTENSION_FUNCTION_POINTER, & funcID, sizeof(funcID)
		, (char *) & WSARecvMsg, sizeof(WSARecvMsg), & bytesReturned
		, NULL, NULL);
}




//
// TODO: local interface sharing...
//
CLowerInterface::CLowerInterface()
{
	WSADATA wsaData;
	int r;

	// initializw windows socket support
	if((r = WSAStartup(0x202, & wsaData)) < 0)
		throw (HRESULT)r;

	memset(& nearInfo, 0, sizeof(nearInfo));

#ifdef USE_RAWSOCKET_IPV6
	sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
	if (sdSend == INVALID_SOCKET)
		throw E_HANDLE;
	//
	nearInfo.pktHdr.cmsg_type = IPV6_PKTINFO;
	nearInfo.pktHdr.cmsg_level = IPPROTO_IPV6;
	nearInfo.pktHdr.cmsg_len = sizeof(nearInfo);	/* #bytes, including this header */
#else
	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
		throw E_HANDLE;
	//
	nearInfo.pktHdr.cmsg_type = IP_PKTINFO;
	nearInfo.pktHdr.cmsg_level = IPPROTO_IP;
	nearInfo.pktHdr.cmsg_len = sizeof(nearInfo.pktHdr) + sizeof(struct in_pktinfo);
#endif

	LearnAddresses();
	PoolingALT_IDs();

	if((r = GetPointerOfWSARecvMsg(sdSend)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot get function pointer WSARecvMsg");
		throw (HRESULT)r;
	}

	sinkInfo.name =  (struct sockaddr *) & addrFrom;
	sinkInfo.namelen = sizeof(addrFrom);
	sinkInfo.Control.buf = (char *) & nearInfo;
	sinkInfo.Control.len = sizeof(nearInfo);

	bufHead = bufTail = 0;
	memset(bufferMemory, 0, sizeof(bufferMemory));

	mutex = SHARED_FREE;
	pSingleInstance = this;

	// only after the required fields initialized may the listener thread started
	// fetch message from remote endpoint and deliver them to upper layer application
	DWORD idReceiver;	// the thread id of the receiver
	thReceiver = CreateThread(NULL // LPSECURITY_ATTRIBUTES, get a default security descriptor inherited
		, 0			// dwStackSize, uses the default size for the executables
		, ProcessRemotePacket	// LPTHREAD_START_ROUTINE
		, this		// LPVOID lpParameter
		, 0			// DWORD dwCreationFlags: run on creation
		, & idReceiver);	// LPDWORD lpThreadId
#ifdef TRACE
	printf("Thead ID of the receiver of the packet from the remote end point = %d\r\n", idReceiver);
#endif
	if(thReceiver == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		throw E_ABORT;
	}
}



CLowerInterface::~CLowerInterface()
{
	// kill the listening thread at first
	TerminateThread(thReceiver, 0);

	// close all of the listening socket
	for(register DWORD i = 0; i < sdSet.fd_count; i++)
	{
		closesocket(sdSet.fd_array[i]);
	}

	// close the unbound socket for sending
	closesocket(sdSend);

	WSACleanup();
}



// TODO: fill in the allowed prefixes with properly multihome support (utilize concept of 'zone')
// multihome/mobility/resilence support (see also CInterface::EnumEffectiveAddresses):
// MAX_PHY_INTERFACES is hard-coded to 4
// sockAddrTo[0] is the most preferred address (care of address)
// sockAddrTo[3] is the home-address
// while sockAddr[1], sockAddr[2] are backup-up/load-balance address (might be zero)
int LOCALAPI CLowerInterface::EnumEffectiveAddresses(UINT64 *prefixes)
{
	// UNRESOLVED! could we make sure u is 64-bit aligned?
	if (nearInfo.IsIPv6())
	{
		prefixes[0] = *(UINT64 *) & nearInfo.u;
		prefixes[1] = 0;	// IN6_ADDR_ANY; no compatible multicast prefix
	}
	else
	{
		((PFSP_IN4_ADDR_PREFIX) & prefixes[0])->prefix = PREFIX_FSP_IP6to4;
		((PFSP_IN4_ADDR_PREFIX) & prefixes[0])->ipv4 = (nearInfo.u.ipi_addr == 0)
			? INADDR_LOOPBACK	// in ws2def.h
			: nearInfo.u.ipi_addr;
		((PFSP_IN4_ADDR_PREFIX) & prefixes[0])->port = DEFAULT_FSP_UDPPORT;
		//
		((PFSP_IN4_ADDR_PREFIX) & prefixes[1])->prefix = PREFIX_FSP_IP6to4;
		((PFSP_IN4_ADDR_PREFIX)& prefixes[1])->ipv4 = INADDR_BROADCAST;
		((PFSP_IN4_ADDR_PREFIX) & prefixes[1])->port = DEFAULT_FSP_UDPPORT;
	}
	// we assume that at the very beginning the home address equals the care-of address
	prefixes[3] = prefixes[0];
	prefixes[2] = prefixes[1];
	return 4;
}


//
inline bool CLowerInterface::LearnOneIPv6Address(PSOCKADDR_IN6 p, int k)
{
	// only for unspecified/global scope:
	if(p->sin6_scope_id != 0)
		return false;

	DWORD m = 0;
	DWORD r = GetBestInterfaceEx((PSOCKADDR)p, & m);
	if(r != 0)
	{
		m = 0;
#ifdef TRACE
		printf("GetBestInterfaceEx (IPv6) error number: %d\n", r);
#endif
	}

	for(register int j = 0; j < k; j++)
	{
		if(interfaces[j] == m
			&& * (long long *)(addresses[j].sin6_addr.u.Byte)
			== * (long long *)(p->sin6_addr.u.Byte))
		{
			return false;	// this interface has been enumerated
		}
	}
	//
	if(k >= nAddress)
		throw E_OUTOFMEMORY;
	interfaces[k] = m;
	addresses[k] = * p;
	return true;
}



#if USE_RAWSOCKET_IPV6
// learn all configured IPv6 addresses
// figure out the associated interface number of each address block(individual prefix)
// and do house-keeping
// (IPv6 addresses whose lower 32-bits are between 0 and 65535 are reserved, otherwise removed)
inline void CLowerInterface::LearnAddresses()
{
	struct {
	    INT iAddressCount;
		SOCKET_ADDRESS Address[MAX_CONNECTION_NUM * MAX_PHY_INTERFACES];
		SOCKADDR_IN6 in6Address[MAX_CONNECTION_NUM * MAX_PHY_INTERFACES];
	} listAddress;
	PSOCKADDR p;

	DWORD n = 0;
	int r = 0;
	listAddress.iAddressCount = MAX_CONNECTION_NUM * MAX_PHY_INTERFACES;
	if((r = WSAIoctl(sdSend, SIO_ADDRESS_LIST_QUERY, NULL, 0, & listAddress, sizeof(listAddress), & n, NULL, NULL)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot query list of addresses");
		throw (HRESULT)r;
	}

	nAddress = FD_SETSIZE;
	FD_ZERO(& sdSet);
	int k = 0;
	for(register int i = 0; i < listAddress.iAddressCount; i++)
	{
		register int j;
		p = listAddress.Address[i].lpSockaddr;
		if(p->sa_family == AF_INET6 && LearnOneIPv6Address((PSOCKADDR_IN6)p, k))
		{
			for(j = 0; j < k; j++)
			{
				if(interfaces[k] == interfaces[j])
					break;
			}
			if(j < i)
				continue;
			// we bind on unique physical interface only
			if(BindInterface(sdSend, (PSOCKADDR_IN6)p) != 0)
			{
				REPORT_WSAERROR_TRACE("Bind failure");
				throw E_ABORT;
			}
			FD_SET(sdSend, & sdSet);
			sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
			if(sdSend == INVALID_SOCKET)
				throw E_HANDLE;
		}
		//
		k++;
	}
	// it would leave one socket unbound for sending packet
	//
	nAddress = k;
}
#else
// Given
//	SOCKET		The UDP socket to be bound
//	PSOCKADDR_IN
//	int			the position that the address is provisioned
// Return
//	0 if no error
//	negative, as the error number
int CLowerInterface::BindInterface(SOCKET sd, PSOCKADDR_IN pAddrListen, int k)
{
	DWORD isHeaderIncluded = TRUE;	// boolean

#ifdef TRACE
	printf_s("Bind to listen at UDP socket address: %d.%d.%d.%d:%d\n"
		, pAddrListen->sin_addr.S_un.S_un_b.s_b1
		, pAddrListen->sin_addr.S_un.S_un_b.s_b2
		, pAddrListen->sin_addr.S_un.S_un_b.s_b3
		, pAddrListen->sin_addr.S_un.S_un_b.s_b4
		, ntohs(pAddrListen->sin_port));
#endif
	memcpy(& addresses[k], pAddrListen, sizeof(SOCKADDR_IN));
	interfaces[k] = 0;

	if (bind(sd, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot bind to the selected address");
		return -1;
	}
	// header is needed as it is the way to differentiate IPv4 or IPv6
	if (setsockopt(sd, IPPROTO_IP, IP_PKTINFO, (char *)& isHeaderIncluded, sizeof(isHeaderIncluded)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IP address");
		return -1;
	}

	FD_SET(sd, & sdSet);
	return 0;
}

// learn all configured IPv4 address (for FSP over UDP)
// throws
//	HRESULT of WSAIOCtrl if cannot query the address
//	E_FAIL if no valid address configured
//	E_OUTOFMEMORY if no enough address buffer
//	E_ABORT if bind failure in the middle way
//	E_HANDLE if cannot allocate enough socket handle
inline void CLowerInterface::LearnAddresses()
{
	struct {
	    INT iAddressCount;
		SOCKET_ADDRESS Address[MAX_CONNECTION_NUM * MAX_PHY_INTERFACES];
		ALIGN(16) SOCKADDR placeholder[MAX_CONNECTION_NUM * MAX_PHY_INTERFACES];
	} listAddress;

	DWORD n = 0;
	int r = 0;
	listAddress.iAddressCount = MAX_CONNECTION_NUM * MAX_PHY_INTERFACES;
	if((r = WSAIoctl(sdSend, SIO_ADDRESS_LIST_QUERY, NULL, 0, & listAddress, sizeof(listAddress), & n, NULL, NULL)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot query list of addresses");
		throw (HRESULT)r;
	}

	if (listAddress.iAddressCount < 0)
		throw E_FAIL;

	register PSOCKADDR_IN p;
	int k = 0;
	nAddress = FD_SETSIZE;
	FD_ZERO(& sdSet);
	for (register int i = 0; i < listAddress.iAddressCount; i++)
	{
		p = (PSOCKADDR_IN)listAddress.Address[i].lpSockaddr;
#ifdef TRACE
		printf_s("#%d socket interface address family: %d, length: %d\n"
			, i
			, p->sin_family
			, listAddress.Address[i].iSockaddrLength);
#endif
		if (p->sin_family != AF_INET)
			throw E_UNEXPECTED;	// memory corruption!
		//
		if(k >= nAddress)
			throw E_OUTOFMEMORY;
		//
		p->sin_port = DEFAULT_FSP_UDPPORT;
		if(BindInterface(sdSend, p, k) != 0)
		{
			REPORT_WSAERROR_TRACE("Bind failure");
			throw E_ABORT;
		}
		sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(sdSend == INVALID_SOCKET)
			throw E_HANDLE;
		k++;
	}
	if (k >= nAddress)
		throw E_OUTOFMEMORY;

	// Set the loopback address as the last resort of receiving
	SOCKADDR_IN loopback;
	p = &loopback;
	p->sin_family = AF_INET;
	p->sin_port = DEFAULT_FSP_UDPPORT;
	p->sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	*(long long *)p->sin_zero = 0;
	if (BindInterface(sdSend, p, k) != 0)
	{
		REPORT_WSAERROR_TRACE("Fail to bind on loopback interface");
		throw E_ABORT;
	}

	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
		throw E_HANDLE;
	// Set the INADDR_ANY for transmission; reuse storage of loopback address
	p->sin_addr.S_un.S_addr = INADDR_ANY;
	r = bind(sdSend, (const sockaddr *)p, sizeof(SOCKADDR_IN));

	nAddress = k + 1;
}
#endif


// UNRESOLVED! TODO: as for IPv6, ALT_ID pool is preconfigured
inline void CLowerInterface::PoolingALT_IDs()
{
	register int k;
	ALT_ID_T id;
	//
	// refuse to continue if the random number generator doesn't work
	for(register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		//
		do
		{
			rand_w32(& id, 1);
			k = id & (MAX_CONNECTION_NUM-1);
		} while(id <= LAST_WELL_KNOWN_ALT_ID || poolSessionID[k]->pairSessionID.source != 0);
		//
		poolSessionID[k]->pairSessionID.source = id;
	}
}


/**
 * A simple memory allocation mechanism based on contiguous segment
 */
inline BYTE * CLowerInterface::BeginGetBuffer()
{
	register int i = bufTail;
	if(i > MAX_BUFFER_MEMORY - sizeof(PktSignature) - MAX_LLS_BLOCK_SIZE)
		i = 0;
	PktSignature *pSignature = (PktSignature *)(bufferMemory + i);
	if((pSignature->size & 1) == 1)
		return NULL;	// the segment is already in use
	return (BYTE *)(pSignature + 1);
}



inline void LOCALAPI CLowerInterface::CommitGetBuffer(BYTE *p, size_t size)
{
	PktSignature *pSignature = (PktSignature *)(p - sizeof(PktSignature));
	// hard-coded: assume MAX_LLS_BLOCK_SIZE never exceed 1MiB and sizeof(size_t) never exceed 8
	size = (size + 7) & 0xFFFF8;
	pSignature->size =  size | 1;
	bufTail = (int)(p + size - bufferMemory);
}



inline void LOCALAPI CLowerInterface::FreeBuffer(BYTE *p)
{
	PktSignature *pSignature = (PktSignature *)(p - sizeof(PktSignature));
	bool secondRound = false;	// just guard against dead-loop
	pSignature->size &= 0xFFFF8;	// hard coded: at most 1MB
	if(pSignature == (PktSignature *)(bufferMemory + bufHead))
	{
		do
		{
			bufHead += (int)(sizeof(PktSignature) + pSignature->size);
			if(bufHead == bufTail)
				break;	// See also CommitGetBuffer()
			if(secondRound && bufHead > bufTail)
			{
				REPORT_ERRMSG_ON_TRACE("possibly falled into dead-loop");
				break;
			}
			if(bufHead > MAX_BUFFER_MEMORY - sizeof(PktSignature) - MAX_LLS_BLOCK_SIZE)
			{
				bufHead = 0;
				secondRound = true;
			}
			if(bufHead == bufTail)
				break;	// See also BeginGetBuffer()
		} while(! (((PktSignature *)(bufferMemory + bufHead))->size & 1));
	}
}


// retrieve message from remote end point
// it's a thread entry
DWORD WINAPI CLowerInterface::ProcessRemotePacket(LPVOID lpParameter)
{
	TRACE_HERE("to process remote packet");
	try
	{
		((CLowerInterface *)lpParameter)->ProcessRemotePacket();
	}
	catch(HRESULT x)
	{
		printf("PANIC! To restart after diagnose internal exception 0x%X", x);
		return -1;
	}
	return 0;
}



inline void CLowerInterface::ProcessRemotePacket()
{
	fd_set readFDs;
	register int i;
	int r;
	if(sdSet.fd_count <= 0)
	{
		TRACE_HERE("Empty socket set, nowhere listen");
		throw E_INVALIDARG;
	}
	do
	{
		// make it as compatible as possible...
		FD_ZERO(& readFDs);
		for(i = 0; i < (int)sdSet.fd_count; i++)		
		{
			FD_SET(sdSet.fd_array[i], & readFDs);
		}
		// select returns total number of sockets that are ready
		if(select(sdSet.fd_count, & readFDs, NULL, NULL, NULL) <= 0)
		{
			REPORT_WSAERROR_TRACE("select failure");
			break;	// TODO: crash recovery from select
		}
		for(i = 0; i < (int) readFDs.fd_count; i++)
		{
			while(_InterlockedCompareExchange8(& this->mutex
				, SHARED_BUSY
				, SHARED_FREE) 
				!= SHARED_FREE)
			{
				Sleep(0);	// just yield out the CPU time slice
			}
			// Unfortunately, it was proven that no matter whether there is MSG_PEEK
			// MSG_PARTIAL is not supported by the underlying raw socket service
			sinkInfo.dwFlags = 0;
			sdRecv = readFDs.fd_array[i];
			r = AcceptAndProcess();
			mutex = SHARED_FREE;
			//
			if(r == E_ABORT)
				return;
		}
	} while(1, 1);
}



int CLowerInterface::AcceptAndProcess()
{
	if((pktBuf = BeginGetBuffer()) == NULL)
		return ENOMEM;	

	// Unfortunately, it was proven that no matter whether there is MSG_PEEK
	// MSG_PARTIAL is not supported by the underlying raw socket service
	// so scattered I/O is actually unutilized.
	WSABUF	scatteredBuf[1];
	scatteredBuf[0].buf = (CHAR *)pktBuf;
	scatteredBuf[0].len = MAX_LLS_BLOCK_SIZE;
	sinkInfo.lpBuffers = scatteredBuf;
	sinkInfo.dwBufferCount = 1;

	int	r = WSARecvMsg(sdRecv, & sinkInfo, & countRecv, NULL, NULL);
	if(r != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot receive packet information");
		mutex = SHARED_FREE;
		return E_ABORT; // TO DO: crash recovery
	}

	CommitGetBuffer(pktBuf, countRecv);

	FSPOperationCode opCode = (FSPOperationCode)
		(nearInfo.IsIPv6() ? HeaderFSP().hs.opCode : HeaderFSPoverUDP().hs.opCode);
#ifdef TRACE
	printf_s("Packet of opCode %d[%s] received\n", (int)opCode, opCodeStrings[opCode]);
	printf_s("Remote address:\n");
	DumpNetworkUInt16((UINT16 *)&addrFrom, sizeof(addrFrom) / 2);
	printf_s("Near sink:\n");
	DumpNetworkUInt16((UINT16 *)&nearInfo.u, sizeof(nearInfo.u) / 2);
#endif
	int lenPrefix = nearInfo.IsIPv6() ? 0 : sizeof(PairSessionID);
	CSocketItemEx *pSocket = NULL;
	PktSignature *pSignature;
	switch(opCode)
	{
	case INIT_CONNECT:
		OnGetInitConnect();
		break;
	case ACK_INIT_CONNECT:
		OnInitConnectAck();
		break;
	case CONNECT_REQUEST:
		OnGetConnectRequest();
		break;
	case ACK_CONNECT_REQUEST:	// connect request acknowledged
		pSocket = MapSocket();
		if(pSocket == NULL)
			break;
		//
		if(! pSocket->IsInUse())
		{
			pSocket = NULL;	// FreeBuffer(pktBuf);
			break;
		}
		pSocket->OnConnectRequestAck( *FSP_OperationHeader<FSP_AckConnectRequest>()
			, countRecv - lenPrefix  - sizeof(FSP_AckConnectRequest) );
		pSocket->SetReady();
		pSocket = NULL;	// FreeBuffer(pktBuf);
		break;
	case RESET:
		OnGetResetSignal();
		break;
	// TODO: get hint of explicit congest notification
	// TODO: automatically register remote address as the favorable contact address (?)
	case PERSIST:
	case PURE_DATA:
	case ADJOURN:
	case ACK_FLUSH:
	case RESTORE:
	case FINISH:
	case MULTIPLY:
	case KEEP_ALIVE:
		pSocket = MapSocket();
		if(pSocket == NULL)
			break;
		//
		pSignature = (PktSignature *)pktBuf - 1;	// assume aligned_malloc
		pSignature->pkt = FSP_OperationHeader<FSP_NormalPacketHeader>();
		pSignature->pktSeqNo = ntohl(pSignature->pkt->sequenceNo);
		pSignature->lenData = countRecv - lenPrefix - ntohs(pSignature->pkt->hs.hsp);
#ifdef TRACE
		printf_s("packet #%u, payload length %d, to put onto the queue\n", pSignature->pktSeqNo, pSignature->lenData);
#endif
		if(pSignature->lenData < 0 || pSignature->lenData > MAX_BLOCK_SIZE)
		{
			pSocket->HandleMemoryCorruption();
			pSocket = NULL;	// FreeBuffer(pktBuf);
			break;
		}
		// UNRESOLVED! TODO: take use of allowedPrefixes to select preferred addrFrom in asymmentric network context
		pSocket->sockAddrTo[0] = addrFrom;
#ifdef TRACE
		printf_s("Socket : 0x%08X , buffer : 0x%08X queued\n", (LONG)pSocket, (LONG)pSignature->pkt);
#endif
		if(pSocket->PushPacketBuffer(pSignature) == NULL)
			QueueUserWorkItem(HandleFullICC, pSocket, WT_EXECUTEDEFAULT);
		break;
	default:
		r = 0;	// UNRECOGNIZED packets are simply discarded
	}

	if(pSocket == NULL)
		FreeBuffer(pktBuf);
	// Or else it is in the working thread that the memory block free

	return r;
}



// Given
//	char *	pointer the data buffer to send back.
//	int		length of the data to send back, in bytes. must be positive
// Do
//	Send back to the remote address where the most recent received packet was sent
// Return
//	Number of bytes actually sent (0 means error)
// Remark
//	It is safely assume that remote and near address are of the same address family
int LOCALAPI CLowerInterface::SendBack(char * buf, int len)
{
	// the final WSAMSG structure
	PairSessionID sidPair;
	WSABUF wsaData[2];
	WSABUF *pToSend;
	int nToSend;

	wsaData[1].buf = buf;
	wsaData[1].len = len;
	if (nearInfo.IsIPv6())
	{
		pToSend = &wsaData[1];
		nToSend = 1;
	}
	else
	{
		// Store the local(near end) session ID as the source, the remote end session ID as
		// the destination session ID in the given session ID association
		sidPair.peer = HeaderFSPoverUDP().source;
		sidPair.source = HeaderFSPoverUDP().peer;
		wsaData[0].buf = (char *)& sidPair;
		wsaData[0].len = sizeof(PairSessionID);
		//
		pToSend = wsaData;
		nToSend = 2;
	}
	//
#ifdef TRACE
	printf_s("Send back to (namelen = %d):\n", sinkInfo.namelen);
	DumpNetworkUInt16((UINT16 *)& addrFrom, sinkInfo.namelen / 2);
#endif
	DWORD n = 0;
	int r = WSASendTo(sdSend
		, pToSend, nToSend, &n
		, 0
		, (const sockaddr *)& addrFrom, sinkInfo.namelen
		, NULL, NULL);
	if (r != 0)
	{
		ReportWSAError("CLowerInterface::SendBack");
		return 0;
	}
#ifdef TRACE
	printf("%s, line %d, %d bytes sent back.\n", __FILE__, __LINE__, n);
	printf("Peer name length = %d, socket address:\n", sinkInfo.namelen);
	DumpNetworkUInt16((UINT16 *)& addrFrom, sizeof(SOCKADDR_IN6) / 2);
#endif
	return n;
}



// inline: only in the CLowerInterface constructor may it be called
inline int BindInterface(SOCKET sd, PSOCKADDR_IN6 pAddrListen)
{
	DWORD optRcvAll = RCVALL_ON; // RCVALL_SOCKETLEVELONLY;
	DWORD opt_size;
	DWORD isHeaderIncluded = TRUE;	// boolean
	
	if(bind(sd, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN6)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot bind to the selected address");
		return -1;
	}

	// put it into promiscuous mode
	opt_size = sizeof(optRcvAll);
	// The socket handle passed to the WSAIoctl function must be of AF_INET address family, SOCK_RAW socket type, and IPPROTO_IP protocol
	if(WSAIoctl(sd, SIO_RCVALL, & optRcvAll, sizeof(optRcvAll), NULL, 0, & opt_size, NULL, NULL) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set it in promiscuous mode");
		return -1;
	}

	if(setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, (char *) & isHeaderIncluded, sizeof(isHeaderIncluded)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IPv6 address");
		return -1;
	}

	return 0;
}

/*
TODO: after configure the ALT_IDs, listen to address change event
TODO: on reconfiguration, refresh IPv6 end point of each FSP socket

Issue SIO_ADDRESS_LIST_CHANGE IOCTL 
Issue SIO_ADDRESS_LIST_QUERY IOCTL 

Whenever SIO_ADDRESS_LIST_CHANGE IOCTL notifies the application of address list change 
(either through overlapped I/O or by signaling FD_ADDRESS_LIST_CHANGE event),
he whole sequence of actions should be repeated. 

scan all configured FSP socket, modify the near end addresses accordingly
*/


// return the WSA error number, which is greater than zero. may be zero if no error at all.
static int LOCALAPI ReportWSAError(char * msg)
{
	int	err = WSAGetLastError();
	LPVOID lpMsgBuf;

	printf("%s, error code = %d\n", msg, err);
	if (FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL )) 
	{
		printf("\tError: %s\n", lpMsgBuf);
		LocalFree( lpMsgBuf );
	}

	return err;
}





// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(char * fileName, int lineNo, char *funcName, char *s1)
{
	char buffer[ERROR_SIZE];
	DWORD err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buffer, ERROR_SIZE, NULL);
	printf("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", fileName, lineNo, funcName, s1);
	if(buffer[0] != 0)
		printf((char *)buffer);
}



/**
 *	POSIX gettimeofday(); get current UTC time
 */

// Return the number of microseconds elapsed since Jan 1, 1970 UTC (unix epoch)
extern "C" timestamp_t NowUTC()
{
	// return the number of 100-nanosecond intervals since January 1, 1601 (UTC), in host byte order
	FILETIME systemTime;
	GetSystemTimeAsFileTime(& systemTime);

	timestamp_t & t = *(timestamp_t *) & systemTime;
	t /= 10;
	return (t - DELTA_EPOCH_IN_MICROSECS);
}
    



// Given
//	DWORD	the process ID
// Return
//	Whether the identified process is still alive
// Remark
//	It is assumed that process ID is 'almost never' reused
bool IsProcessAlive(DWORD idProcess)
{
	// PROCESS_QUERY_LIMITED_INFORMATION
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, idProcess);
	DWORD exitCode;
	if(hProcess == NULL)
		return false;	// no such process at all. maybe information may not be queried, but it is rare
	//
	BOOL r = GetExitCodeProcess(hProcess, & exitCode);
	CloseHandle(hProcess);

	return (r && exitCode == STILL_ACTIVE);
}


// Given
//	_Uint32t	[_Out_] placeholder of the random 32-bit words to be generated
//	int			number of the random 32-bit words to be gererated
// Do
//	Exploit rand_s() to get a string of specified number near-real random 32-bit words 
// Remark
//	Hard-coded: at most generate 256 bits
void rand_w32(uint32_t *p, int n)
{
	for(register int i = 0; i < min(n, 32); i++)
	{
		rand_s(p + i);
	}
}






//in linux, use high-resolution timers, jiffies 
//				
//#include <linux/kernel.h>
//#include <linux/module.h>
//#include <linux/hrtimer.h>
//#include <linux/ktime.h>
//
//
//#define MS_TO_NS(x)	(x * 1E6L)
//
//static struct hrtimer hr_timer;
//enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
//{
//  printk( "my_hrtimer_callback called (%ld).\n", jiffies );
//  return HRTIMER_NORESTART;
//}
//
//int init_module( void )
//{
//  ktime_t ktime;
//  unsigned long delay_in_ms = 200L;
//  printk("HR Timer module installing\n");
//  ktime = ktime_set( 0, MS_TO_NS(delay_in_ms) );
//  hrtimer_init( &hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
//  hr_timer.function = &my_hrtimer_callback;
//  printk( "Starting timer to fire in %ldms (%ld)\n", delay_in_ms, jiffies );
//  hrtimer_start( &hr_timer, ktime, HRTIMER_MODE_REL );
//  return 0;
//}
//
//void cleanup_module( void )
//{
//  int ret;
//  ret = hrtimer_cancel( &hr_timer );
//  if (ret) printk("The timer was still in use...\n");
//  printk("HR Timer module uninstalling\n");
//  return;
//}
TimerWheel::TimerWheel()
{
	if(timerQueue == NULL)
		timerQueue = CreateTimerQueue();
}


TimerWheel::~TimerWheel()
{
	if(timerQueue != NULL)
	{
		DeleteTimerQueueEx(timerQueue, NULL);
		timerQueue = NULL;
	}
}



bool CSocketItemEx::AddTimer()
{
	if(::CreateTimerQueueTimer(& timer, TimerWheel::Singleton()
			, TimeOut	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, tKeepAlive_ms
			, tKeepAlive_ms
			, WT_EXECUTEINTIMERTHREAD
			) )
	{
		clockCheckPoint.tMigrate = NowUTC();
		return true;
	}
	else
	{
		return false;
	}
}



void CSocketItemEx::ChangeKeepAliveClock()
{
	timestamp_t t1 = NowUTC();
	if(clockCheckPoint.tKeepAlive - t1 < tRoundTrip_us)
		return;
	//
	clockCheckPoint.tKeepAlive = t1 + tRoundTrip_us;
	::ChangeTimerQueueTimer(TimerWheel::Singleton(), timer, tRoundTrip_us / 1000, tKeepAlive_ms);
}




bool CSocketItemEx::RemoveTimer()
{
	if(::DeleteTimerQueueTimer(TimerWheel::Singleton(), timer, NULL))
	{
		timer = NULL;
		return true;
	}
	else
	{
		return false;
	}
}



bool LOCALAPI CSocketItemEx::ReplaceTimer(uint32_t period)
{
	clockCheckPoint.tKeepAlive = NowUTC() + period * 1000;
	tKeepAlive_ms = period;
	return ( timer == NULL 
		&&	::CreateTimerQueueTimer(& timer, TimerWheel::Singleton()
			, TimeOut	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, period
			, period
			, WT_EXECUTEINTIMERTHREAD)
		|| timer != NULL
		&& ::ChangeTimerQueueTimer(TimerWheel::Singleton(), timer, period, period)
		);
}



void CSocketItemEx::ScheduleEmitQ()
{
	QueueUserWorkItem(HandleSendQ, this, WT_EXECUTELONGFUNCTION);
}



void CSocketItemEx::ScheduleConnect(CommandNewSession *pCmd)
{
	// TODO: RDSC management
	// Send RESTORE when RDSC hit
	pCmd->u.s.pSocket = this;
	QueueUserWorkItem(HandleConnect, pCmd, WT_EXECUTELONGFUNCTION);
}



inline
PktSignature * CSocketItemEx::PushPacketBuffer(PktSignature *pNext)
{
	while(_InterlockedCompareExchange8(& mutex
		, SHARED_BUSY
		, SHARED_FREE)
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	PktSignature *p = tailPacket;
	pNext->next = NULL;
	if(p == NULL)
	{
		headPacket = tailPacket = pNext;
	}
	else
	{
		tailPacket->next = pNext;
		tailPacket = pNext;
	}

	mutex = SHARED_FREE;
	return p;
}



inline
void CSocketItemEx::PopPacketBuffer()
{
	while(_InterlockedCompareExchange8(& mutex
		, SHARED_BUSY
		, SHARED_FREE)
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	PktSignature *p = headPacket->next;	// MUST put before FreeBuffer or else it may be overwritten
	CLowerInterface::Singleton()->FreeBuffer((BYTE *)headPacket + sizeof(PktSignature));
	if((headPacket = p) == NULL)
		tailPacket = NULL;

	mutex = SHARED_FREE;
}



DWORD WINAPI HandleSendQ(LPVOID p)
{
	try
	{
		CSocketItemEx *p0 = (CSocketItemEx *)p;
#ifdef TRACE
		printf_s("0x%08X : before HandleSendQ TestAndWaitReady\n", (LONG)p0);
#endif
		if(! p0->TestAndWaitReady())
		{
			//// UNRESOLVED! How to forceful reset the session if it is locked...
			//if(p0->IsInUse())
			//	CLowerInterface::Singleton()->FreeItem(p0);
			return 0;
		}
#ifdef TRACE
		printf_s("0x%08X : after HandleSendQ TestAndWaitReady\n", (LONG)p0);
#endif
		p0->EmitQ();
		p0->SetReady();

		return 1;
	}
	catch(...)
	{
		return 0;
	}
}



DWORD WINAPI HandleFullICC(LPVOID p)
{
	try
	{
		CSocketItemEx *p0 = (CSocketItemEx *)p;
		while(p0->headPacket)
		{
#ifdef TRACE
			printf_s("0x%08X : before HandleFullICC TestAndWaitReady\n", (LONG)p0);
#endif
			if(! p0->TestAndWaitReady())
			{
				//// UNRESOLVED! How to forceful reset the session if it is locked...
				//if(p0->IsInUse())
				//	CLowerInterface::Singleton()->FreeItem(p0);
				return 0;
			}
#ifdef TRACE
			printf_s("0x%08X : after HandleFullICC TestAndWaitReady\n", (LONG)p0);
#endif
			// synchronize the state in the 'cache' and the real state
			p0->lowState = p0->pControlBlock->state;
			switch(p0->headPacket->pkt->hs.opCode)
			{
			case PERSIST:
				p0->OnGetPersist();
				break;
			case PURE_DATA:
				p0->OnGetPureData();
				break;
			case ADJOURN:
				p0->OnGetAdjourn();
				break;
			case ACK_FLUSH:
				p0->OnAdjournAck();
				break;
			case RESTORE:
				p0->OnGetRestore();
				break;
			case FINISH:
				p0->OnGetFinish();
				break;
			case MULTIPLY:
				p0->OnGetMultiply();
				break;
			case KEEP_ALIVE:
				p0->OnGetKeepAlive();
			}
			//
			p0->SetReady();
			p0->PopPacketBuffer();
		}
		return 1;
	}
	catch(...)
	{
		return 0;
	}
}



DWORD WINAPI HandleConnect(LPVOID p)
{
	try
	{
		CSocketItemEx *p1 = (CSocketItemEx *)((CommandNewSession *)p)->u.s.pSocket;
		p1->Connect((CommandNewSession *)p);
		return 1;
	}
	catch(...)
	{
		return 0;
	}
}


// It is assumed that inUse and isReady are stored compactly (octet by octet)
bool CSocketItemEx::TestAndWaitReady()
{
	time_t t0 = time(NULL);
	while(! TestAndLockReady())
	{
		Sleep(1);
		if(time(NULL) - t0 > TRASIENT_STATE_TIMEOUT_ms)
			return false;
	}
	//
	return true;
}



// UNRESOLVED! TODO: enforce rate-limit (and rate-limit based congestion avoidance/control)
// TODO: UNRESOLVED! is it multi-home awared?
// Given
//	ULONG	number of WSABUF descriptor to gathered in sending
// Return
//	number of bytes sent, or 0 if error
int LOCALAPI CSocketItemEx::SendPacket(ULONG n1)
{
	LPWSABUF lpBuffers;
	if (pControlBlock->nearEnd->IsIPv6())
	{
		lpBuffers = wsaBuf + 1;
	}
	else
	{
		// assume sidPair is maintained properly
		lpBuffers = wsaBuf;
		n1++;
	}
//#ifdef TRACE
//	printf_s("\nPeer name length = %d, socket address:\n", namelen);
//	DumpNetworkUInt16((UINT16 *)sockAddrTo, sizeof(SOCKADDR_IN6) / 2);
//	printf_s("Data to sent:\n----\n");
//	for (register ULONG i = 0; i < n1; i++)
//	{
//		DumpNetworkUInt16((UINT16 *)lpBuffers[i].buf, lpBuffers[i].len / 2);
//		printf("----\n");
//	}
//#endif
	DWORD n = 0;
	///It is a headache to specify valid local interface in the parameter block to utilize WSASendMsg
	// Minimum OS version that support WSASendMsg is Windows Vista/Server 2008
	// Let the underlying network service select the best outgoing interface
	//int r = WSASendTo(CLowerInterface::Singleton()->sdSend
	//	, lpBuffers, n1, &n
	//	, 0
	//	, (const struct sockaddr *)sockAddrTo
	//	, namelen
	//	, NULL, NULL);
	///but i don't know why I/O gathering failed sometimes...
	///it doesn't worth the trouble to figure out it on Microsoft Windows platform!?
	//RecvSocket = WSASocket(AF_INET, 
	//   SOCK_DGRAM, 
	//   IPPROTO_UDP, 
	//   NULL, 
	//   0, 
	//   0);
	{
		char buf[MAX_BLOCK_SIZE + sizeof(pairSessionID)];
		int d = 0;
		for(register ULONG j = 0; j < n1; j++)
		{
			memcpy(buf + d, lpBuffers[j].buf, lpBuffers[j].len);
			d += lpBuffers[j].len;
		}
		n = sendto(CLowerInterface::Singleton()->sdSend, buf, d, 0, (const struct sockaddr *)sockAddrTo, namelen);
	}
	int r = (n == SOCKET_ERROR ? -1 : 0);
	//
	if (r != 0)
	{
		ReportWSAError("CSocketItemEx::SendPacket");
		return 0;
	}
//#ifdef TRACE
//	printf_s("\n%s, line %d, %d bytes sent.\n", __FILE__, __LINE__, n);
//#endif
	return n;
}



int ConnectRequestQueue::Push(const CommandNewSession *p)
{
	while(_InterlockedCompareExchange8(& mutex, SHARED_BUSY, SHARED_FREE) != SHARED_FREE)
	{
		Sleep(0);
	}
	//
	if(mayFull != 0 && tail == head)
	{
		mutex = SHARED_FREE;
		return -1;
	}

	register int i = tail;
	if(++tail >= CONNECT_BACKLOG_SIZE)
		tail = 0;
	q[i] = *p;
	mayFull = 1;
	//
	mutex = SHARED_FREE;
	return i;
}



// Given
//	int		the index of the item to be removed
// Return
//	0	if no error
//	-1	if no item could be removed
int ConnectRequestQueue::Remove(int i)
{
	while(_InterlockedCompareExchange8(& mutex, SHARED_BUSY, SHARED_FREE) != SHARED_FREE)
	{
		Sleep(0);
	}
	// 
	if(tail < 0 || tail >= CONNECT_BACKLOG_SIZE)
		REPORT_ERRMSG_ON_TRACE("check tail in case of falling into dead loop");
	//
	if(mayFull == 0 && head == tail)
	{
		mutex = SHARED_FREE;
		return -1;
	}
	//
	q[i].opCode = NullCommand;
	if(i == head)
		do
		{
			if(++head >= CONNECT_BACKLOG_SIZE)
				head = 0;
		} while(head != tail && q[head].opCode == NullCommand);
	mayFull = 0;
	//
	mutex = SHARED_FREE;
	return 0;
}	
