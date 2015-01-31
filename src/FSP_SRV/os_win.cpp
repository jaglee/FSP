#define _CRT_RAND_S
#include <stdlib.h>
#include "fsp_srv.h"

#include <MSTcpIP.h>
#include <Iphlpapi.h>

#include <netfw.h>
#include <Psapi.h>
#include <tchar.h>


#define REPORT_WSAERROR_TRACE(s) (\
	printf("\n/**\n * %s, line# %d\n * %s\n */\n", __FILE__, __LINE__, __FUNCDNAME__), \
	ReportWSAError(s)\
	)

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")

/*

RFC 2460                   IPv6 Specification              December 1998

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#pragma pack(1)
struct IPv6_HEADER
{
	union
	{
		struct
		{
			unsigned int version : 4;
			unsigned int traffic_class : 8;
			unsigned int flowLabel : 20;
		};
		unsigned long version_traffic_flow;
	};
	unsigned short payloadLenth;
	unsigned char nextHeader;	// should be IPPROTO_FSP
	unsigned char hopLimit;		// should be 255, the maximum
	IN6_ADDR srcAddr;
	IN6_ADDR dstAddr;

	void Set(int m, PIN6_ADDR a0, PIN6_ADDR a1)
	{
		version_traffic_flow = 6 << 4;	// in network byte order, it would be correct
		payloadLenth = htons(m);
		nextHeader = IPPROTO_FSP;
		hopLimit = 255;		// hard-coded here
		srcAddr = *a0;
		dstAddr = *a1;
	}
};

#pragma pack()

CLowerInterface	* CLowerInterface::pSingleInstance;
HANDLE	TimerWheel::timerQueue;

static LPFN_WSARECVMSG	WSARecvMsg;

static int LOCALAPI ReportWSAError(char * msg);

static int CreateFWRules();

// abstract out for sake of testability
inline int GetPointerOfWSARecvMsg(SOCKET sd)
{
	GUID funcID = WSAID_WSARECVMSG;
	DWORD bytesReturned;
	return WSAIoctl(sd, SIO_GET_EXTENSION_FUNCTION_POINTER, & funcID, sizeof(funcID)
		, (char *) & WSARecvMsg, sizeof(WSARecvMsg), & bytesReturned
		, NULL, NULL);
}


VOID NETIOAPI_API_ OnUnicastIpChanged(PVOID, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE);


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

	CreateFWRules();

	memset(& nearInfo, 0, sizeof(nearInfo));

#ifndef OVER_UDP_IPv4
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
	PoolingALFIDs();

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
	CancelMibChangeNotify2(hMobililty);
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




#ifndef OVER_UDP_IPv4	// by default exploit IPv6
/**
 the interface to bind might be configured but not started. in that case binding would fail. do
 netsh wlan start hostednetwork
 */
// inline: only in the CLowerInterface constructor may it be called
inline int BindInterface(SOCKET sd, PSOCKADDR_IN6 pAddrListen)
{
	DWORD isHeaderIncluded = TRUE;	// boolean

	if (bind(sd, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN6)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot bind to the selected address");
		return -1;
	}

	// It is useless to put it into promiscuous mode WSAIoctl(sd, SIO_RCVALL, ...)

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_HDRINCL, (char *)& isHeaderIncluded, sizeof(isHeaderIncluded)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to send the IPv6 header");
		return -1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, (char *)& isHeaderIncluded, sizeof(isHeaderIncluded)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IPv6 address");
		return -1;
	}

	return 0;
}



// learn all configured IPv6 addresses
// figure out the associated interface number of each address block(individual prefix)
// and do house-keeping
// (IPv6 addresses whose lower 32-bits are between 0 and 65535 are reserved, otherwise removed)
inline void CLowerInterface::LearnAddresses()
{
	PMIB_UNICASTIPADDRESS_TABLE table;
	PIN6_ADDR p;
	int k = 0;
	CHAR strIPv6Addr[INET6_ADDRSTRLEN];

	nAddress = FD_SETSIZE;
	FD_ZERO(&sdSet);
	memset(addresses, 0, sizeof(addresses));

	GetUnicastIpAddressTable(AF_INET6, &table);
	for (register long i = table->NumEntries - 1; i >= 0; i--)
	{
		p = &table->Table[i].Address.Ipv6.sin6_addr;

#ifdef TRACE
		inet_ntop(AF_INET6, p, strIPv6Addr, sizeof(strIPv6Addr));
		printf_s("\n%s\nInterfaceIndex = %d, DaD state = %d, ScopeId = %d, SkipAsSource = %d\n"
			, strIPv6Addr
			, table->Table[i].InterfaceIndex
			, table->Table[i].DadState
			, table->Table[i].ScopeId.Value
			, table->Table[i].SkipAsSource
			);
		//table->Table[i].PrefixOrigin;
		//table->Table[i].OnLinkPrefixLength;
#endif

		// UNRESOLVED!!	// only for unspecified/global scope:?
		if (table->Table[i].ScopeId.Value != 0)
			continue;
		if (table->Table[i].DadState != IpDadStateTentative && table->Table[i].DadState != IpDadStatePreferred)
			continue;

		// Here it is compatible with single physical interfaced host in multi-homed site
		bool found = false;
		for (register int j = 0; j < k; j++)
		{
			if (interfaces[j] == table->Table[i].InterfaceIndex
			&& *(uint64_t *)(addresses[j].sin6_addr.u.Byte) == *(uint64_t *)(p->u.Byte))
			{
				found = true;
				break;
			}
		}
		if (found)	// this interface has been enumerated
			continue;

		//
		if (k >= nAddress)
			throw E_OUTOFMEMORY;

		interfaces[k] = table->Table[i].InterfaceIndex;
		addresses[k].sin6_family = AF_INET6;
		addresses[k].sin6_addr = *p;
		// port number and flowinfo are all zeroed already
		addresses[k].sin6_scope_id = table->Table[i].ScopeId.Value;

		if (::BindInterface(sdSend, &addresses[k]) != 0)
		{
			REPORT_WSAERROR_TRACE("Bind failure");
			throw E_ABORT;
		}
		FD_SET(sdSend, &sdSet);
		k++;

		sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
		if (sdSend == INVALID_SOCKET)
			throw E_HANDLE;
	}
	nAddress = k;
	FreeMibTable(table);

	NotifyUnicastIpAddressChange(AF_INET6, OnUnicastIpChanged, NULL, TRUE, &hMobililty);
}



// UNRESOLVED!? To be tested: for user-mode IPv6, configure contemporary IPv6 address for EVERY unicast interface
inline void CLowerInterface::SetLocalApplicationLayerFiberID(ALFID_T id)
{
	MIB_UNICASTIPADDRESS_ROW	row;
	int r;
	CHAR strIPv6Addr[INET6_ADDRSTRLEN];

	for (register int i = 0; i < nAddress; i++)
	{
		InitializeUnicastIpAddressEntry(&row);

		// ALFIDs are processed 'as is'
		*(ALFID_T *)&(addresses[i].sin6_addr.u.Byte[12]) = id;
		row.InterfaceIndex = interfaces[i];
		row.Address.Ipv6 = addresses[i];

		// UNRESOLVED! if creation failed?
		r = CreateUnicastIpAddressEntry(&row);
		inet_ntop(AF_INET6, &row.Address.Ipv6, strIPv6Addr, sizeof(strIPv6Addr));
		printf_s("It returned %d to set IPv6 address to %s@%d\n", r, strIPv6Addr, interfaces[i]);
	}
}



inline void CLowerInterface::PoolingALFIDs()
{
	register int k;
	ALFID_T id;
	//
	// refuse to continue if the random number generator doesn't work
	for (register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		//
		do
		{
			rand_w32(&id, 1);
			k = id & (MAX_CONNECTION_NUM - 1);
		} while (id <= LAST_WELL_KNOWN_ALFID || poolFiberID[k]->fidPair.source != 0);
		// for every valid interface, pre-configure the id
		SetLocalApplicationLayerFiberID(id);
		//
		poolFiberID[k]->fidPair.source = id;
	}
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

inline void CLowerInterface::PoolingALFIDs()
{
	register int k;
	ALFID_T id;
	//
	// refuse to continue if the random number generator doesn't work
	for (register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		//
		do
		{
			rand_w32(&id, 1);
			k = id & (MAX_CONNECTION_NUM - 1);
		} while (id <= LAST_WELL_KNOWN_ALFID || poolFiberID[k]->fidPair.source != 0);
		//
		poolFiberID[k]->fidPair.source = id;
	}
}
#endif




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
#ifdef TRACE_PACKET
	printf_s("Packet of opCode %d[%s] received\n", (int)opCode, opCodeStrings[opCode]);
	printf_s("Remote address:\n");
	DumpNetworkUInt16((UINT16 *)&addrFrom, sizeof(addrFrom) / 2);
	printf_s("Near sink:\n");
	DumpNetworkUInt16((UINT16 *)&nearInfo.u, sizeof(nearInfo.u) / 2);
#endif
	int lenPrefix = nearInfo.IsIPv6() ? 0 : sizeof(PairALFID );
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
	case ACK_CONNECT_REQ:	// connect request acknowledged
		pSocket = MapSocket();
		if(pSocket == NULL)
			break;
		//
		if(! pSocket->TestAndLockReady())
		{
			TRACE_HERE("lost ACK_CONNECT_REQ due to lack of locks");
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
	case PERSIST:
	case PURE_DATA:
	case COMMIT:
	case ACK_FLUSH:
	case RESUME:
	case RELEASE:
	case MULTIPLY:
	case KEEP_ALIVE:
		pSocket = MapSocket();
		if(pSocket == NULL)
		{
#ifdef TRACE
			printf_s("Cannot map socket for local fiber#%u\n", GetLocalFiberID());
#endif
			break;
		}
		//
		pSignature = (PktSignature *)pktBuf - 1;	// assume aligned_malloc
		pSignature->pkt = FSP_OperationHeader<FSP_NormalPacketHeader>();
		pSignature->pktSeqNo = ntohl(pSignature->pkt->sequenceNo);
		pSignature->lenData = countRecv - lenPrefix - ntohs(pSignature->pkt->hs.hsp);
#ifdef TRACE_PACKET
		printf_s("packet #%u, payload length %d, to put onto the queue\n", pSignature->pktSeqNo, pSignature->lenData);
#endif
		if(pSignature->lenData < 0 || pSignature->lenData > MAX_BLOCK_SIZE)
		{
			pSocket->HandleMemoryCorruption();
			pSocket = NULL;	// FreeBuffer(pktBuf);
			break;
		}
		// save the source address temporarily as it is not necessariy legitimate
		pSocket->sockAddrTo[MAX_PHY_INTERFACES] = addrFrom;
#ifdef TRACE_PACKET
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
	PairALFID fidPair;
	WSABUF wsaData[2];
	IPv6_HEADER hdrIN6;

	wsaData[1].buf = buf;
	wsaData[1].len = len;
	if (nearInfo.IsIPv6())
	{
		hdrIN6.Set(len, (PIN6_ADDR)& nearInfo.u, (PIN6_ADDR)& addrFrom.Ipv6.sin6_addr);
		wsaData[0].buf = (char *)& hdrIN6;
		wsaData[0].len = sizeof(hdrIN6);
	}
	else
	{
		// Store the local(near end) fiber ID as the source, the remote end fiber ID as
		// the destination fiber ID in the given fiber ID association
		fidPair.peer = HeaderFSPoverUDP().source;
		fidPair.source = HeaderFSPoverUDP().peer;
		wsaData[0].buf = (char *)& fidPair;
		wsaData[0].len = sizeof(fidPair);
	}
	//
#ifdef TRACE
	printf_s("Send back to (namelen = %d):\n", sinkInfo.namelen);
	DumpNetworkUInt16((UINT16 *)& addrFrom, sinkInfo.namelen / 2);
#endif
	DWORD n = 0;
	int r = WSASendTo(sdSend
		, wsaData, 2, &n
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
timestamp_t NowUTC()
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
	for (register int i = 0; i < min(n, 32); i++)
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
	return (
		::CreateTimerQueueTimer(& timer, TimerWheel::Singleton()
			, TimeOut	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, tKeepAlive_ms
			, tKeepAlive_ms
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE
		);
}



// Remark
//	Timestamp arithmetic is rendered in the Galois feild
//	clockCheckPoint and tLastRecv must be well defined
void CSocketItemEx::EarlierKeepAlive()
{
//#ifdef TRACE
//	TRACE_HERE("keep alive earlier");
//	DumpTimerInfo(tLastRecv);
//#endif
	if (clockCheckPoint.tKeepAlive - tLastRecv < tRoundTrip_us)
		return;
	//
	clockCheckPoint.tKeepAlive = tLastRecv + tRoundTrip_us;
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



// Given
//	uint32_t		number of millisecond delayed to trigger the timer
// Return
//	true if the timer was set, false if it failed.
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



void CSocketItemEx::ScheduleConnect(CommandNewSessionSrv *pCmd)
{
	// TODO: RDSC management
	// Send RESUME when RDSC hit
	pCmd->pSocket = this;
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



// only if there is some packet in the queue would it be locked
inline
FSP_NormalPacketHeader * CSocketItemEx::PeekLockPacketBuffer()
{
	while(_InterlockedCompareExchange8(& mutex
		, SHARED_BUSY
		, SHARED_FREE)
		!= SHARED_FREE)
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	if(headPacket == NULL)
	{
		// assert(tailPacket == NULL);
		mutex = SHARED_FREE;
		return NULL;
	}

	return headPacket->pkt;
}



// assume mutex is busy
inline
void CSocketItemEx::PopUnlockPacketBuffer()
{
	if(headPacket == NULL)
	{
		// assert(tailPacket == NULL);
		mutex = SHARED_FREE;
		return;
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
		if(! p0->TestAndWaitReady())
		{
			//// UNRESOLVED! How to forceful reset the session if it is locked...
			//if(p0->IsInUse())
			//	CLowerInterface::Singleton()->FreeItem(p0);
			return 0;
		}
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
		FSP_NormalPacketHeader *hdr;
		while(hdr = p0->PeekLockPacketBuffer())
		{
			if(! p0->TestAndWaitReady())
			{
				//// UNRESOLVED! How to forceful reset the session if it is locked...
				//if(p0->IsInUse())
				//	CLowerInterface::Singleton()->FreeItem(p0);
				p0->UnlockPacketBuffer();
				return 0;
			}
			// synchronize the state in the 'cache' and the real state
			p0->lowState = p0->pControlBlock->state;
			switch(hdr->hs.opCode)
			{
			case PERSIST:
				p0->OnGetPersist();
				break;
			case PURE_DATA:
				p0->OnGetPureData();
				break;
			case COMMIT:
				p0->OnGetCommit();
				break;
			case ACK_FLUSH:
				p0->OnAckFlush();
				break;
			case RESUME:
				p0->OnGetResume();
				break;
			case RELEASE:
				p0->OnGetRelease();
				break;
			case MULTIPLY:
				p0->OnGetMultiply();
				break;
			case KEEP_ALIVE:
				p0->OnGetKeepAlive();
			}
			//
			p0->SetReady();
			p0->PopUnlockPacketBuffer();
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
		((CommandNewSessionSrv *)p)->DoConnect();
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
		{
			TRACE_HERE("TestAndWaitReady timeout");
			return false;
		}
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
int CSocketItemEx::SendPacket(register ULONG n1, ScatteredSendBuffers s)
{
	register LPWSABUF lpBuffers = s.scattered;
	IPv6_HEADER hdrIN6;
	n1++;

	// 'Prefer productivity over cleverness - if there is some cleverness'
	if (pControlBlock->nearEnd->IsIPv6())
	{
		int	d = 0;
		for (register ULONG j = 1; j < n1; j++)
		{
			d += lpBuffers[j].len;
		}
		hdrIN6.Set(d, (PIN6_ADDR)& pControlBlock->nearEnd[0], &sockAddrTo->Ipv6.sin6_addr);
		s.scattered[0].buf = (CHAR *)& hdrIN6;
		s.scattered[0].len = sizeof(hdrIN6);
	}
	else
	{
		s.scattered[0].buf = (CHAR *)& fidPair;
		s.scattered[0].len = sizeof(fidPair);
	}

	tRecentSend = NowUTC();
//#ifdef TRACE_PACKET
//	printf_s("\nPeer socket address:\n");
//	DumpNetworkUInt16((UINT16 *)sockAddrTo, sizeof(SOCKADDR_IN6) / 2);
//	printf_s("Data to sent:\n----\n");
//	for (register ULONG i = 0; i < n1; i++)
//	{
//		DumpNetworkUInt16((UINT16 *)lpBuffers[i].buf, lpBuffers[i].len / 2);
//		printf("----\n");
//	}
//#endif
	DWORD n = 0;
	// UNRESOLVED! Mixed IPv4/IPv6 network interface, i.e.dual hosted networks
	int r = WSASendTo(CLowerInterface::Singleton()->sdSend
		, lpBuffers, n1
		, &n
		, 0
		, (const struct sockaddr *)sockAddrTo
		, sockAddrTo->si_family == AF_INET6 ? sizeof(sockAddrTo->Ipv6) : sizeof(sockAddrTo->Ipv4)
		, NULL
		, NULL);
	if (r != 0)
	{
		ReportWSAError("CSocketItemEx::SendPacket");
		return 0;
	}
#ifdef TRACE_PACKET
	printf_s("\n%s, line %d, %d bytes sent.\n", __FILE__, __LINE__, n);
#endif
	return n;
}



int ConnectRequestQueue::Push(const CommandNewSessionSrv *p)
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


/*
mobility support...
TODO: after configure the ALFIDs, listen to address change event
TODO: on reconfiguration, refresh IPv6 end point of each FSP socket

scan all configured FSP socket, modify the near end addresses accordingly
*/
//[Avoid dead loop here!]
VOID NETIOAPI_API_ OnUnicastIpChanged(PVOID, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE notificationType)
{
	printf_s("MIB_NOTIFICATION_TYPE: %d\n", notificationType);
	switch (notificationType)
	{
	case MibParameterNotification:
		printf("//// ParameterChange.//\n");
		break;
	case MibAddInstance:
		printf("//// Addition.//\n");
		break;
	case MibDeleteInstance:
		printf("//// Deletion.//\n");
		break;
	case MibInitialNotification:
		printf("//// Initial notification.//\n");
		return;
	default:
		return;
	}
	if (row == NULL)
	{
		printf("Internal panic! Cannot guess which IP interface was changed\n");
		return;
	}

	CHAR strIPv6Addr[INET6_ADDRSTRLEN];
	// change from:
	if (inet_ntop(AF_INET6, &(row->Address.Ipv6.sin6_addr), strIPv6Addr, sizeof(strIPv6Addr)) != NULL)
		printf("\tIt is about %s\n", strIPv6Addr);
	else
		ReportWSAError("Cannot figuout out the string representation of the address?");

	MIB_UNICASTIPADDRESS_ROW infoRow;	//SOCKADDR_IN6 addr = row->Address.Ipv6;
	// InitializeUnicastIpAddressEntry(&infoRow);
	infoRow.InterfaceLuid = row->InterfaceLuid;
	infoRow.Address = row->Address;
	GetUnicastIpAddressEntry(&infoRow);

	// change to:
	if (inet_ntop(AF_INET6, &(row->Address.Ipv6.sin6_addr), strIPv6Addr, sizeof(strIPv6Addr)) != NULL)
		printf("\tIt is about %s\n", strIPv6Addr);
	else
		ReportWSAError("Cannot figuout out the string representation of the address?");
}



// return 0 if no error
// positive if warning
static int CreateFWRules()
{
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	INetFwPolicy2 *pNetFwPolicy2 = NULL;
	INetFwRules *pFwRuleSet = NULL;
	INetFwRule *pFwRule = NULL;

	BSTR bstrRuleName = SysAllocString(L"Flexible Session Protocol");
	BSTR bstrRuleDescription = SysAllocString(L"Allow network traffic from/to FSP over IPv6");
	BSTR bstrRuleGroup = SysAllocString(L"FSP/IPv6");	//  and optionally FSP over UDP/IPv4
	BSTR bstrRulePorts = SysAllocString(L"18003");	// 0x4653, i.e. ASCII Code of 'F' 'S'
	BSTR bstrRuleService = SysAllocString(L"*");
	BSTR bstrRuleApplication = NULL;
	WCHAR	strBuf[MAX_PATH];	// shall not be too deep
	// Here we assume OLE2ANSI is not defined so that OLECHAR is WCHAR
#ifdef UNICODE	// when TCHAR is WCHAR, so that it is compatible with OLECHAR
	//if(GetFullPathName(appPath, MAX_PATH + 1, strBuf, NULL) <= 0)	//
	GetModuleFileName(NULL, (LPTSTR)strBuf, MAX_PATH);
	// Windows XP:The string is truncated to nSize characters and is not null-terminated; but here we do not support XP
#else
	TCHAR	strBuf0[MAX_PATH + 1];
	size_t	lenBstr;
	//QueryFullProcessImageName(GetCurrentProcess(), 0, strBuf0, &(DWORD &)lenBstr);
	//GetLastError();	// invalid parameter?
	//GetProcessImageFileName(GetCurrentProcess(), strBuf0, MAX_PATH);	// \Device\Harddisk0\Partition1\...
	GetModuleFileName(NULL, strBuf0, MAX_PATH);
	if (mbstowcs_s<MAX_PATH>(&lenBstr, strBuf, strBuf0, MAX_PATH - 1) != 0)
		goto l_bailout;
#endif
	bstrRuleApplication = SysAllocString((const OLECHAR *)strBuf);
	// BSTR bstrRuleApplication = SysAllocString(L"%programfiles%\\Flexible Session Protocol\\raw_server.exe");

	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
		);

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
			goto l_bailout;
		}
	}

	// Retrieve INetFwPolicy2
	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)& pNetFwPolicy2);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto l_bailout;
	}

	// Retrieve INetFwRules
	hr = pNetFwPolicy2->get_Rules(&pFwRuleSet);
	if (FAILED(hr))
	{
		printf("get_Rules failed: 0x%08lx\n", hr);
		goto l_bailout;
	}

	// Check whether the rule exists: should return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
	// Remove all of the old rules...
	while (SUCCEEDED(hr = pFwRuleSet->Item(bstrRuleName, &pFwRule)))
	{
		pFwRule->Release();
		if (!SUCCEEDED(pFwRuleSet->Remove(bstrRuleName)))
			break;	// or else it would fall into deadlock
	}


	// Create a new Firewall Rule object.
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto l_bailout;
	}
	// Outbound rule for FSP: do not specify application nor profile domain
	// Populate the Firewall Rule object
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	//pFwRule->put_ApplicationName(bstrRuleApplication);	// do not limit the application for outbound
	pFwRule->put_Protocol(IPPROTO_FSP);	//  NET_FW_IP_PROTOCOL_TCP == IPPROTO_TCP		
	// there is no 'port' concept in FSP
	pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	pFwRule->put_Enabled(VARIANT_TRUE);
	// LocalAddresses, LocalPorts, RemoteAddresses, RemotePorts, Interfaces and InterfaceTypes are all ignored
	// Add the Firewall Rule
	hr = pFwRuleSet->Add(pFwRule);
	if (FAILED(hr))	// 80070005 // E_ACCESSDENIED
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto l_bailout;
	}


	// The second rule is inbound/service rule for FSP: bind appliction
	pFwRule->Release();
	// must release the old one or else the rule handle is the same as the one exists
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto l_bailout;
	}
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_ApplicationName(bstrRuleApplication);
	// pFwRule->put_ServiceName(bstrRuleService);
	pFwRule->put_Protocol(IPPROTO_FSP);	// NET_FW_IP_PROTOCOL_TCP
	pFwRule->put_Direction(NET_FW_RULE_DIR_IN);		// By default the direcion is in
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	pFwRule->put_Enabled(VARIANT_TRUE);
	// LocalAddresses, LocalPorts, RemoteAddresses, RemotePorts, Interfaces and InterfaceTypes are all ignored
	// Add the Firewall Rule
	hr = pFwRuleSet->Add(pFwRule);
	if (FAILED(hr))	// 8000FFFF // E_UNEXPECTED	// the method failed because the object is already in the collection
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto l_bailout;
	}


	// The third rule is for outbound FSP over UDP/IPv4
	pFwRule->Release();
	// must release the old one or else the rule handle is the same as the one exists
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto l_bailout;
	}
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);	// NET_FW_IP_VERSION_V4
	pFwRule->put_LocalPorts(bstrRulePorts);
	pFwRule->put_RemotePorts(bstrRulePorts);
	pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	pFwRule->put_Enabled(VARIANT_TRUE);
	// LocalAddresses, RemoteAddresses, Interfaces and InterfaceTypes are all ignored
	// Add the Firewall Rule
	hr = pFwRuleSet->Add(pFwRule);
	if (FAILED(hr))	// 80070005 // E_ACCESSDENIED
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto l_bailout;
	}


	// The fourth rule is for inbound/service rule for FSP over UDP/IPv4
	pFwRule->Release();
	// must release the old one or else the rule handle is the same as the one exists
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto l_bailout;
	}
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_ApplicationName(bstrRuleApplication);
	// pFwRule->put_ServiceName(bstrRuleService);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);	// NET_FW_IP_VERSION_V4
	pFwRule->put_LocalPorts(bstrRulePorts);
	pFwRule->put_RemotePorts(bstrRulePorts);
	pFwRule->put_Direction(NET_FW_RULE_DIR_IN);		// By default the direcion is in
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	pFwRule->put_Enabled(VARIANT_TRUE);
	// LocalAddresses, RemoteAddresses, Interfaces and InterfaceTypes are all ignored
	// Add the Firewall Rule
	hr = pFwRuleSet->Add(pFwRule);
	if (FAILED(hr))	// 8000FFFF // E_UNEXPECTED	// the method failed because the object is already in the collection
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto l_bailout;
	}


l_bailout:
	// Free BSTR's
	SysFreeString(bstrRuleName);
	SysFreeString(bstrRuleDescription);
	SysFreeString(bstrRuleGroup);
	SysFreeString(bstrRulePorts);
	SysFreeString(bstrRuleService);
	if (bstrRuleApplication != NULL)
		SysFreeString(bstrRuleApplication);

	// Release the INetFwRule object
	if (pFwRule != NULL)
	{
		pFwRule->Release();
	}

	// Release the INetFwRules object
	if (pFwRuleSet != NULL)
	{
		pFwRuleSet->Release();
	}

	// Release the INetFwPolicy2 object
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}

	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	return 0;
}
