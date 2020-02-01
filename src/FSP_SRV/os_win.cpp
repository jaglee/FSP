/*
 * FSP lower-layer service program, collection of the platform-dependent
 * / IPC-mechanism-dependent functions
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
#include "fsp_srv.h"

#include <MSTcpIP.h>
#include <Iphlpapi.h>

#include <Psapi.h>
#include <tchar.h>

#if _MSC_VER
# include <netfw.h>
# pragma comment(lib, "Iphlpapi.lib")
# pragma comment(lib, "Ws2_32.lib")
# pragma comment(lib, "User32.lib")
#endif

#define REPORT_WSAERROR_TRACE(s) (\
	printf("\n/**\n * %s, line# %d\n * %s\n */\n", __FILE__, __LINE__, __FUNCTION__), \
	ReportWSAError(s)\
	)

// The handle of the global timer wheel timer queue
static HANDLE	globalTimerQueue;

// The preconfigured ALFID, for FSP emulator with user-mode Windows socket only
static ALFID_T preallocatedIDs[MAX_CONNECTION_NUM];

// The function called by the macro REPORT_WSAERROR_TRACE
static int LOCALAPI ReportWSAError(const char *msg);

// The function called directly or by ReportWSAError
static void LOCALAPI ReportErrorAsMessage(int);

// Forward declaration of the firewall manipulation function
static int CreateFWRules();

/**
 *	The function pointer of WSARecvMsg obtained from the run-time library
 *	'GetPointerOfWSARecvMsg' was abstracted out for sake of testability
 */
static LPFN_WSARECVMSG	WSARecvMsg;
inline int GetPointerOfWSARecvMsg(SOCKET sd)
{
	GUID funcID = WSAID_WSARECVMSG;
	DWORD bytesReturned;
	return WSAIoctl(sd, SIO_GET_EXTENSION_FUNCTION_POINTER, & funcID, sizeof(funcID)
		, (char *) & WSARecvMsg, sizeof(WSARecvMsg), & bytesReturned
		, NULL, NULL);
}


#if (_WIN32_WINNT < 0x0600) && !defined(OVER_UDP_IPv4)
static LPFN_WSASENDMSG	WSASendMsg;
inline int GetPointerOfWSASendMsg(SOCKET sock)
{
    GUID	guidWSASendMsg = WSAID_WSASENDMSG;
    DWORD	dwBytes = 0;

    return WSAIoctl(sock, 
                SIO_GET_EXTENSION_FUNCTION_POINTER, 
                &guidWSASendMsg, 
                sizeof(guidWSASendMsg), 
                &WSASendMsg, 
                sizeof(WSASendMsg), 
                &dwBytes, 
                NULL, 
                NULL
                );
}
#endif


#ifndef OVER_UDP_IPv4
// Forward declaration of the callback function for handling the event that some IPv6 interface was changed
VOID NETIOAPI_API_ OnUnicastIpChanged(PVOID, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE);
#endif

/*
 * The OS-dependent CommandNewSessionSrv constructor
 */
CommandNewSessionSrv::CommandNewSessionSrv(const CommandToLLS *p1)
{
	CommandNewSession *pCmd = (CommandNewSession *)p1;
	memcpy(this, pCmd, sizeof(CommandToLLS));
	hMemoryMap = (HANDLE)pCmd->hMemoryMap;
	dwMemorySize = pCmd->dwMemorySize;
	hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, (LPCSTR)pCmd->szEventName);
}



// To initialize:
//	- Startup the socket service
//	- Create rule entries in the firewall setting to enable FSP traffic
//	- Bind the listening sockets besides the default sending socket
//	- Preallocate Application Layer Fiber ID pool
//	- Enable accepting and processing of the remote FSP packets
//	- Enable mobility detection
bool CLowerInterface::Initialize()
{
	WSADATA wsaData;
	int r;

	// initialize windows socket support
	if ((r = WSAStartup(0x202, &wsaData)) < 0)
	{
		BREAK_ON_DEBUG();
		return false;
	}

	CreateFWRules();

	memset(& nearInfo, 0, sizeof(nearInfo));
	mesgInfo.name = (struct sockaddr*) & addrFrom;
	mesgInfo.namelen = sizeof(addrFrom);
	mesgInfo.Control.buf = (char*)&nearInfo;
	mesgInfo.Control.len = sizeof(nearInfo);
	// See also ProcessRemotePacket and SendBack
#ifndef OVER_UDP_IPv4
	mesgInfo.lpBuffers = &iovec[1];
	mesgInfo.dwBufferCount = 1;
	//
	sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
	if (sdSend == INVALID_SOCKET)
	{
		BREAK_ON_DEBUG();
		return false;
	}
	//
	nearInfo.pktHdr.cmsg_type = IPV6_PKTINFO;
	nearInfo.pktHdr.cmsg_level = IPPROTO_IPV6;
	nearInfo.pktHdr.cmsg_len = sizeof(nearInfo);	/* #bytes, including this header */
#else
	iovec[0].buf = (char*)&pktBuf->fidPair;
	iovec[0].len = sizeof(ALFIDPair);
	mesgInfo.lpBuffers = iovec;
	mesgInfo.dwBufferCount = 2;
	//
	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
	{
		BREAK_ON_DEBUG();
		return false;
	}
	//
	nearInfo.pktHdr.cmsg_type = IP_PKTINFO;
	nearInfo.pktHdr.cmsg_level = IPPROTO_IP;
	nearInfo.pktHdr.cmsg_len = sizeof(nearInfo.pktHdr) + sizeof(struct in_pktinfo);
#endif

	if(! LearnAddresses())
		return false;
	MakeALFIDsPool();
	// This is a workaround (because of limitation under user-mode socket programming)
#ifndef OVER_UDP_IPv4
	for (register u_int i = 0; i < sdSet.fd_count; i++)
	{
		SetLocalApplicationLayerFiberIDs(i);
	}
#endif

	if((r = GetPointerOfWSARecvMsg(sdSend)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot get function pointer WSARecvMsg");
		return false;
	}
#if (_WIN32_WINNT < 0x0600) && !defined(OVER_UDP_IPv4)
	if((r = GetPointerOfWSASendMsg(sdSend)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot get function pointer WSASendMsg");
		return false;
	}
#endif

	// only after the required fields initialized may the listener thread started
	// fetch message from remote endpoint and deliver them to upper layer application
	DWORD idReceiver;	// the thread id of the receiver
	thReceiver = CreateThread(NULL // LPSECURITY_ATTRIBUTES, get a default security descriptor inherited
		, 0			// dwStackSize, uses the default size for the executables
		, ProcessRemotePacket	// LPTHREAD_START_ROUTINE
		, this		// LPVOID lpParameter
		, 0			// DWORD dwCreationFlags: run on creation
		, & idReceiver);	// LPDWORD lpThreadId
	printf_s("Thread ID of the receiver of the packet from the remote end point = %d\r\n", idReceiver);
	if(thReceiver == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		throw E_ABORT;
	}

#ifndef OVER_UDP_IPv4
	disableFlags = 0;
	NotifyUnicastIpAddressChange(AF_INET6, OnUnicastIpChanged, NULL, FALSE, &hMobililty);
#endif

	globalTimerQueue = ::CreateTimerQueue();
	if(globalTimerQueue == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return false;
	}
	return true;
}



// The body of the class destructor
void CLowerInterface::Destroy()
{
	DeleteTimerQueueEx(globalTimerQueue, INVALID_HANDLE_VALUE);
#ifndef OVER_UDP_IPv4
	CancelMibChangeNotify2(hMobililty);
#endif
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



// Preallocate a pool of re-usable random ALFIDs. Preallocation would later make the lower network interface to provision the corresponding IP addresses
// This is a workaround as we cannot receive a unicast packet whose destination IPv6 address does not match any known unicast IP address on an NIC
// even if it has been put to promiscuous mode
inline void CLowerInterface::MakeALFIDsPool()
{
	register int k;
	ALFID_T id;
	//
	// refuse to continue if the random number generator doesn't work
	for (register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		// Here 'id', as a random number, is generated as a 32-bit integer in network byte order
		// while 'k' is a simple hash number derived in host byte order
		// See also LearnAddresses, operator::[], AllocItem, FreeItem
		do
		{
			do
			{
				rand_w32(&id, 1);
				k = be32toh(id);
			} while (k <= LAST_WELL_KNOWN_ALFID);
			//
			k &= MAX_CONNECTION_NUM - 1;
		} while (tlbSockets[k]->fidPair.source != 0);
		//
		tlbSockets[k]->fidPair.source = preallocatedIDs[i] = id;
	}
}



// sockAddrTo[0] is the most preferred address (care of address)
// sockAddrTo[3] is the home-address
// while sockAddr[1], sockAddr[2] are backup-up/load-balance address (might be zero)
// we assume that at the very beginning the home address equals the care-of address
int LOCALAPI CLowerInterface::EnumEffectiveAddresses(uint64_t *prefixes)
{
	memset(prefixes, 0, sizeof(TSubnets));
	if (! nearInfo.IsIPv6())
		return 0;

	// The address that has accepted the acknowledgement is the current care-of-address
	// no matter whether it is global routable:
	prefixes[0] = *(uint64_t *)& nearInfo.u;

	int n = sdSet.fd_count;
	int k = 1;
	uint64_t prefix;
	for (register int i = 0; i < n; i++)
	{
		// binary prefix 000 MUST have its interface ID set to EUID, which is NOT compatible with FSP
		// neither the "IPv4-Compatible	IPv6 address" nor the "IPv4 - mapped IPv6 address"
		// is compatible with FSP
		if ((addresses[i].sin6_addr.u.Byte[0] & 0xE0) == 0)
			continue;
		// RFC4291 link-local address is NOT compatible with FSP resilience support
		if (*(uint64_t *)& addresses[i].sin6_addr == *(uint64_t *)& in6addr_linklocalprefix)
			continue;
		// RFC4193 unique local address is preferred if and only if the peer takes use of it as well
		if (((prefixes[0] & 0xFE) != 0xFC && (addresses[i].sin6_addr.u.Byte[0] & 0xFE) == 0xFC)
		 || ((prefixes[0] & 0xFE) == 0xFC && (addresses[i].sin6_addr.u.Byte[0] & 0xFE) != 0xFC))
		{
			continue;
		}
		// other global routable address are supposed to be not-NATed, compatible with FSP
		prefix = *(uint64_t *)& addresses[i].sin6_addr;
		if (prefix == prefixes[0])
			continue;
		prefixes[k] = prefix;
		if (++k >= MAX_PHY_INTERFACES)
			break;
	}
	//
	return k;
}



#ifndef OVER_UDP_IPv4	// by default exploit IPv6
// put it into promiscuous mode, here user-mode
static SOCKET	sdPromiscuous;
static LONG		enableFlags;	// Somewhat a mirror of CLowerInterface disableFlags

// An IPv6 socket that was created with the address family set to AF_INET6, the socket type set to SOCK_RAW,
// and the protocol set to IPPROTO_IPV6 (but IPPROTO_FSP works!).
// Any direct change from applying this option on one interface and then to another interface
// with a single call using this IOCTL is not supported.
// An application must first use this IOCTL to turn off the behavior on the first interface,
// and then use this IOCTL to enable the behavior on a new interface.
int	DisablePromiscuous()
{
	DWORD optRcvAll = RCVALL_OFF;
	DWORD opt_size;
	int r = 0;
	if(WSAIoctl(sdPromiscuous, SIO_RCVALL, &optRcvAll, sizeof(optRcvAll), NULL, 0, &opt_size, NULL, NULL) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot disable the promiscuous mode");
		r = -1;
	}
	//
	sdPromiscuous = NULL;
	return r;
}



// There's the document glitch when this code snippet was written: the output buffer MUST be specified
// Given
//	SOCKET		the socket that bind the interface to be set into promiscuous mode
// Do
//	Set the given socket as the default promiscuous interface
// Return
//	positive if a warning saying that there is already a default promiscuous interface
//	0 if no error
//	negative if error
int	EnablePromiscuous(SOCKET sd)
{
	if (sdPromiscuous != NULL)
		return 1;

	// This error can also be returned if the network interface associated with the socket cannot be found.
	// This could occur if the network interface associated with the socket is deleted or removed (a remove PCMCIA or USB network device, for example). 
	DWORD optRcvAll = RCVALL_IPLEVEL;	//  RCVALL_SOCKETLEVELONLY not implemented; // RCVALL_ON let NIC enabled
	DWORD opt_size;
	if (WSAIoctl(sd, SIO_RCVALL, &optRcvAll, sizeof(optRcvAll), NULL, 0, &opt_size, NULL, NULL) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set the default interface in promiscuous mode");
		return -1;
	}
	sdPromiscuous = sd;
	//
	return 0;
}



// Given
//	SOCKET			the handle of the socket to bind the designated listening address
// Return
//	0 if no error and the new socket is bound to the promiscuous interface
//	negative if it failed
//	positive if it succeeded
// Do
//	Set valuable options
// Remark
//	inline: only in the CLowerInterface constructor may it be called
//	MUST bind the socket at first or else EnablePromiscuous would return WSAEINVAL
inline int CLowerInterface::SetInterfaceOptions(SOCKET sd)
{
	DWORD wantPktInfo = TRUE;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, (char *)& wantPktInfo, sizeof(wantPktInfo)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IPv6 address");
		return -1;
	}
	// Here we didn't set IPV6_V6ONLY, for we suppose that dual-stack support is not harmful, though neither benefical

	// We do want to test larger gap, and be in favor of FIFD
	WSAIoctl(sd, SIO_ENABLE_CIRCULAR_QUEUEING, NULL, 0, NULL, 0, NULL, NULL, NULL);

	return EnablePromiscuous(sd);
}



// learn all configured IPv6 addresses
// figure out the associated interface number of each address block(individual prefix)
// and do house-keeping
// (IPv6 addresses whose lower 32-bits are between 0 and 65535 are reserved, otherwise removed)
// throws
//	E_OUTOFMEMORY if no enough address buffer
//	E_ABORT if bind failure in the middle way
//	E_HANDLE if cannot allocate enough socket handle
inline bool CLowerInterface::LearnAddresses()
{
	PMIB_UNICASTIPADDRESS_TABLE table;
	PIN6_ADDR p;
	u_int & k = sdSet.fd_count;
	CHAR strIPv6Addr[INET6_ADDRSTRLEN];

	FD_ZERO(&sdSet);
	memset(addresses, 0, sizeof(addresses));

	if(GetUnicastIpAddressTable(AF_INET6, &table) != NO_ERROR)
		return false;

	k = 0;
	for (register long i = table->NumEntries - 1; i >= 0; i--)
	{
		p = &table->Table[i].Address.Ipv6.sin6_addr;
		// show which interfaces were bound
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

		//Extensible link-local interface, where the value of ScopeId typically equals the interface number under Windows, should be acceptable?
		if (table->Table[i].ScopeId.Value != 0)
			continue;

		if (table->Table[i].DadState == IpDadStateDuplicate)
			printf_s("Warning: this is a duplicate address on the subnet.\n");
		else if (table->Table[i].DadState != IpDadStatePreferred)
			continue;

		// Loopback, IPv4-compatible or IPv4-mapped IPv6 addresses are NOT compatible with FSP
		if (*(int64_t *)& p->u == 0)
			continue;

		// See also MakeALFIDsPool, operator::[], AllocItem, FreeItem
		if (be32toh(*(ALFID_T *)& p->u.Byte[12]) > LAST_WELL_KNOWN_ALFID)
		{
			DeleteUnicastIpAddressEntry(&table->Table[i]);
			continue;
		}

		// Here it is compatible with single physical interfaced host in multi-homed site
		if (IsPrefixDuplicated(table->Table[i].InterfaceIndex, p))
			continue;

		if (k >= SD_SETSIZE)
		{
			printf_s("Has more than %d IPv6 addresses?\n", k);
			return false;
		}

		interfaces[k] = table->Table[i].InterfaceIndex;
		addresses[k].sin6_family = AF_INET6;
		addresses[k].sin6_addr = *p;
		// port number and flowinfo are all zeroed already
		addresses[k].sin6_scope_id = table->Table[i].ScopeId.Value;

		if (::bind(sdSend, (const struct sockaddr *)& addresses[k], sizeof(SOCKADDR_IN6)) != 0)
		{
			REPORT_WSAERROR_TRACE("Bind failure");
			return false;
		}
		//
		if(SetInterfaceOptions(sdSend) == 0)
			iRecvAddr = i;
		// UNRESOLVED!? But if SetInterfaceOptions failed thoroughly?
		FD_SET(sdSend, &sdSet);
		// k++;	// When FD_SET, the alias target is already increased

		sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
		if (sdSend == INVALID_SOCKET)
		{
			REPORT_WSAERROR_TRACE("Cannot create new socket");
			return false;
		}
	}
	if (k == 0)
	{
		printf_s("IPv6 not enabled?\n");
		return false;
	}

	// note that k is alias of fd_count of the socket set for this instance
	FreeMibTable(table);
	return true;
}



// For FSP over IPv6 raw-socket, provision an IPv6 interface with ALFID pool
// Given
//	int		The index of the address entry
// Do
//	Register the IPv6 addresses for EVERY ALFID at the specified IPv6 interface
inline void CLowerInterface::SetLocalApplicationLayerFiberIDs(int iEntry)
{
	MIB_UNICASTIPADDRESS_ROW	row;
	int r;
	DWORD ifNo = interfaces[iEntry];	// the interface number/index
	SOCKADDR_IN6 addr = addresses[iEntry];

	for (register u_int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		InitializeUnicastIpAddressEntry(&row);

		row.InterfaceIndex = ifNo;
		row.Address.Ipv6 = addr;
		*(ALFID_T *) & (row.Address.Ipv6.sin6_addr.u.Byte[12]) = preallocatedIDs[i];

		r = CreateUnicastIpAddressEntry(&row);
		if (r != NO_ERROR)
		{
			ReportErrorAsMessage(r);
			continue;
		}
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		CHAR strIPv6Addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &row.Address.Ipv6.sin6_addr, strIPv6Addr, sizeof(strIPv6Addr));
		printf_s("It returned %d to set IPv6 address to %s@%d\n", r, strIPv6Addr, interfaces[iEntry]);
#endif
	}
}



// Given
//	int		The index of the interface to remove preallocated ALFID address. The index was originally reported by the network layer
// Do
//	Remove EVERY IPv6 address with some preallocated ALFID configured for the designated interface
inline void CLowerInterface::RemoveALFIDAddressPool(u32 ifIndex)
{
	PMIB_UNICASTIPADDRESS_TABLE table;
	PIN6_ADDR p;

	GetUnicastIpAddressTable(AF_INET6, &table);
	for (register long i = table->NumEntries - 1; i >= 0; i--)
	{
		// UNRESOLVED!!	// only for unspecified/global scope:?
		// Filter MUST be the same as LearnAddresses
		if (table->Table[i].ScopeId.Value != 0)
			continue;
		if (table->Table[i].DadState != IpDadStatePreferred)
			continue;

		p = &table->Table[i].Address.Ipv6.sin6_addr;
		// See also LearnAddresses, MakeALFIDsPool, operator::[], AllocItem, FreeItem
		if (table->Table[i].InterfaceIndex == ifIndex && be32toh(*(ALFID_T *)& p->u.Byte[12]) > LAST_WELL_KNOWN_ALFID)
			DeleteUnicastIpAddressEntry(&table->Table[i]);
	}
	FreeMibTable(table);
}
#else
// Given
//	SOCKET		The UDP socket to set options
// Return
//	0 if no error
//	negative, as the error number
inline int CLowerInterface::SetInterfaceOptions(SOCKET sd)
{
	DWORD enablePktInfo = TRUE;

	// enable return of packet information by WSARecvMsg, so that make difference between IPv4 and IPv6
	return setsockopt(sd, IPPROTO_IP, IP_PKTINFO, (char *)& enablePktInfo, sizeof(enablePktInfo));
}



// Given
//	PSOCKADDR_IN
//	int			the position that the address is provisioned
// Return
//	0 if no error
//	negative, as the error number
int CLowerInterface::BindSendRecv(const SOCKADDR_IN *pAddrListen, int k)
{
	printf_s("Bind to listen at UDP socket address: %d.%d.%d.%d:%d\n"
		, pAddrListen->sin_addr.S_un.S_un_b.s_b1
		, pAddrListen->sin_addr.S_un.S_un_b.s_b2
		, pAddrListen->sin_addr.S_un.S_un_b.s_b3
		, pAddrListen->sin_addr.S_un.S_un_b.s_b4
		, be16toh(pAddrListen->sin_port));
	//
	if (::bind(sdSend, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot bind to the selected address");
		return -1;
	}
	if (SetInterfaceOptions(sdSend) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IP address");
		return -1;
	}

	memcpy(&addresses[k], pAddrListen, sizeof(SOCKADDR_IN));
	interfaces[k] = 0;
	FD_SET(sdSend, &sdSet);
	return 0;
}



// learn all configured IPv4 address (for FSP over UDP)
inline bool CLowerInterface::LearnAddresses()
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
		return false;
	}

	if (listAddress.iAddressCount < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot figure out interface address");
		return false;
	}

	u_int & k = sdSet.fd_count;
	register PSOCKADDR_IN p;
	FD_ZERO(& sdSet);
	for (register int i = 0; i < listAddress.iAddressCount; i++)
	{
		p = (PSOCKADDR_IN)listAddress.Address[i].lpSockaddr;
		if (p->sin_family != AF_INET)
		{
			REPORT_ERRMSG_ON_TRACE("memory corruption!");
			return false;
		}
		//
		// When BindSemdRecv, k++; as k is the alias of sdSet.fd_count
		// -1: reserve loopback address as the last resort
		if (k >= SD_SETSIZE - 1)
		{
			REPORT_ERRMSG_ON_TRACE("run out of socket set space");
			break;		//^Only a warning
		}
		//
		p->sin_port = DEFAULT_FSP_UDPPORT;
		if(BindSendRecv(p, k) != 0)
			closesocket(sdSend);		// instead of return false;

		sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sdSend == INVALID_SOCKET)
		{
			REPORT_ERRMSG_ON_TRACE("run out of handle space?!");
			return false;
		}
	}

	// Set the loopback address as the last resort of receiving
	SOCKADDR_IN loopback;
	p = &loopback;
	p->sin_family = AF_INET;
	p->sin_port = DEFAULT_FSP_UDPPORT;
	p->sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	*(long long *)p->sin_zero = 0;
	if (BindSendRecv(p, k) != 0)
	{
		REPORT_WSAERROR_TRACE("Fail to bind on loopback interface");
		return false;
	}

	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
	{
		REPORT_ERRMSG_ON_TRACE("run out of handle space?!");
		return false;
	}
	// Set the INADDR_ANY for transmission; reuse storage of loopback address
	p->sin_addr.S_un.S_addr = INADDR_ANY;
	::bind(sdSend, (const struct sockaddr *)p, sizeof(SOCKADDR_IN));
	// SetInterfaceOptions(sdSend);	// unnecessary
	return true;
}
#endif



// retrieve message from remote end point
// it's a thread entry
DWORD WINAPI CLowerInterface::ProcessRemotePacket(LPVOID lpParameter)
{
	try
	{
		((CLowerInterface *)lpParameter)->ProcessRemotePacket();
	}
	catch(HRESULT x)
	{
		printf("PANIC! To restart after diagnose internal exception 0x%X", (unsigned)x);
		return -1;
	}
	return 0;
}



// the real top-level handler to accept and process the remote packets
inline void CLowerInterface::ProcessRemotePacket()
{
	fd_set readFDs;
	register int i;
	int r;
	if (sdSet.fd_count <= 0)
		throw E_INVALIDARG;

	// Unfortunately, it was proven that no matter whether there is MSG_PEEK
	// MSG_PARTIAL is not supported by the underlying raw socket service
	do
	{
		// make it as compatible as possible...
		FD_ZERO(&readFDs);
		r = 0;
		for (i = 0; i < (int)sdSet.fd_count; i++)
#ifndef OVER_UDP_IPv4
			if (!BitTest(&disableFlags, i))
#endif
			{
				FD_SET(sdSet.fd_array[i], &readFDs);
				r++;
			}
#if !defined(OVER_UDP_IPv4) && defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("Number of registered socket = %d, usable = %d\n", sdSet.fd_count, r);
#endif
		// during hand-off there might be no IPv6 interface available
		// for simplicity hard code the polling interval.
		// a more sophisticated implementation should be event-driven - wait the IP change event instead
		if (r <= 0)
		{
			Sleep(TIMER_SLICE_ms * 20);
			continue;
		}
		// It is documented that select returns total number of sockets that are ready, however, if one socket is closed
		// 'select' success while following WSARecvMsg will fail
		// Cannot receive packet information, error code = 10038
		// Error: An operation was attempted on something that is not a socket.
		// a more sophisticated implementation should be asynchronous on reading/receiving
		r = select(readFDs.fd_count, &readFDs, NULL, NULL, NULL);
		if (r == SOCKET_ERROR)
		{
			int	err = WSAGetLastError();
			if (err == WSAENETDOWN)
			{
				Sleep(TIMER_SLICE_ms * 20);	// wait for the network service up again
				continue;
			}
			else if (err == WSAENOTSOCK)
				// One of the descriptor sets contains an entry that is not a socket. deliberately close a socket
			{
				Sleep(TIMER_SLICE_ms);
				continue;
			}
			REPORT_WSAERROR_TRACE("select failure");
			BREAK_ON_DEBUG();
			break;	// TODO: crash recovery from select
		}
		//
		for (i = 0; i < (int)readFDs.fd_count; i++)
		{
			SOCKET sdRecv = readFDs.fd_array[i];
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("\nPacket on socket #%X: to process...\n", (unsigned)sdRecv);
#endif
			// Note that SendBack changes iovec[1]. SendBack is inherently unable to be de-coupled.
			iovec[1].buf = (CHAR*)&pktBuf->hdr;
			iovec[1].len = sizeof(FSP_NormalPacketHeader) + MAX_BLOCK_SIZE;
			if ((r = WSARecvMsg(sdRecv, &mesgInfo, (LPDWORD)&countRecv, NULL, NULL)) < 0)
			{
				r = WSAGetLastError();
				if (r == EADDRNOTAVAIL)
				{
					DisableSocket(sdRecv);
				}
				else if (r != WSAENOTSOCK)
				{
					ReportErrorAsMessage(r);
					throw - E_ABORT;		// Unrecoverable error
				}
				// TO DO: other errors which could not undertake crash recovery
				continue;
			}
#ifdef OVER_UDP_IPv4
			SOCKADDR_ALFID(mesgInfo.name) = pktBuf->fidPair.source;
#else
			pktBuf->fidPair.source = SOCKADDR_ALFID(mesgInfo.name);
#endif
			ProcessReceived();
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("\nPacket on socket #%X: processed, result = %d\n", (unsigned)sdRecv, r);
#endif
		}
	} while (1, 1);
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
//	and the remote address is kept till this function returns, by mutex-locking
int LOCALAPI CLowerInterface::SendBack(char * buf, int len)
{
	DWORD n = 0;
	iovec[1].buf = buf;
	iovec[1].len = len;
#ifdef OVER_UDP_IPv4
	// Store the local(near end) fiber ID as the source, the remote end fiber ID as
	// the destination fiber ID in the given fiber ID association
	pktBuf->fidPair.peer = _InterlockedExchange((PLONG)&pktBuf->fidPair.source, pktBuf->fidPair.peer);
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("\nSend back to peer socket address:\n");
	DumpNetworkUInt16((uint16_t *)& addrFrom, sizeof(SOCKADDR_IN6) / 2);
#endif
	int r = WSASendTo(sdSend
		, iovec, 2, &n
		, 0
		, (const sockaddr *)& addrFrom, mesgInfo.namelen
		, NULL, NULL);
#else
	int r = WSASendMsg(sdSend, &mesgInfo, 0, &n, NULL, NULL);
#endif
	if (r != 0)
	{
		ReportWSAError("CLowerInterface::SendBack");
		return 0;
	}
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf("%s, line %d, %d bytes sent back.\n", __FILE__, __LINE__, n);
	printf_s("  Send from msghdr:\n\t");
	DumpNetworkUInt16((uint16_t *)& nearInfo, sizeof(nearInfo) / 2);
	printf_s("  Send back to (namelen = %d):\n\t", mesgInfo.namelen);
	DumpNetworkUInt16((uint16_t *)& addrFrom, mesgInfo.namelen / 2);
#endif
	return n;
}




// Given
//	char *		The error message prefix string in multi-byte character set
// Do
//	Print the system message mapped to the last error to the standard output, prefixed by the given message prefix
// Return
//	the WSA error number, which is greater than zero. may be zero if no error at all.
static int LOCALAPI ReportWSAError(const char * msg)
{
	int	err = WSAGetLastError();

	printf("%s, error code = %d\n", msg, err);
	ReportErrorAsMessage(err);

	return err;
}



// Given
//	int		the known error number
// Do
//	Print the standard system error message mapped to the error number to the standard output
static void LOCALAPI ReportErrorAsMessage(int err)
{
	LPVOID lpMsgBuf;
	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL))
	{
		printf("\tError: %s\n", (char *)lpMsgBuf);
		LocalFree(lpMsgBuf);
	}
}



// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(const char * fileName, int lineNo, const char *funcName, const char *s1)
{
	TCHAR buffer[ERROR_SIZE];
	DWORD err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buffer, ERROR_SIZE, NULL);
	printf_s("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", fileName, lineNo, funcName, s1);
	if(buffer[0] != 0)
		_tprintf_s((TCHAR *)buffer);
}



/**
 *	POSIX gettimeofday(); get current UTC time
 */
// Return the number of microseconds elapsed since Jan 1, 1970 UTC (Unix epoch)
extern "C" timestamp_t NowUTC()
{
	// return the number of 100-nanosecond intervals since January 1, 1601 (UTC), in host byte order
	FILETIME systemTime;
	GetSystemTimeAsFileTime(&systemTime);

	timestamp_t & t = *(timestamp_t *)& systemTime;
	t /= 10;
	return (t - DELTA_EPOCH_IN_MICROSECS);
}




// Return
//	Whether the ULA process associated with the LLS socket is still alive
// Remark
//	It is assumed that process ID is 'almost never' reused
bool CSocketItemEx::IsProcessAlive()
{
	// PROCESS_QUERY_LIMITED_INFORMATION
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, idSrcProcess);
	DWORD exitCode;
	if (hProcess == NULL)
		return false;	// no such process at all. maybe information may not be queried, but it is rare

	BOOL r = GetExitCodeProcess(hProcess, &exitCode);
	CloseHandle(hProcess);

	return (r && exitCode == STILL_ACTIVE);
}



// Given
//	uint32_t		number of millisecond delayed to trigger the timer
// Return
//	true if the timer was set, false if it failed.
bool LOCALAPI CSocketItemEx::ReplaceTimer(uint32_t period)
{
	return (
		(timer == NULL 
		 &&	::CreateTimerQueueTimer(& timer, globalTimerQueue
			, KeepAlive	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, period
			, period
			, WT_EXECUTEINTIMERTHREAD))
		|| (timer != NULL && ::ChangeTimerQueueTimer(globalTimerQueue, timer, period, period))
		);
}


// Assume a mutex has been obtained
void CSocketItemEx::RemoveTimers()
{
	HANDLE h;
	if((h = (HANDLE)InterlockedExchangePointer(& timer, NULL)) != NULL)
		::DeleteTimerQueueTimer(globalTimerQueue, h, NULL);
}



// For ScheduleConnect
DWORD WINAPI HandleConnect(LPVOID p)
{
	try
	{
		((CommandNewSessionSrv *)p)->DoConnect();
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}



// The OS-dependent implementation of scheduling connection-request queue
void CSocketItemEx::ScheduleConnect(int i)
{
	CommandNewSessionSrv & cmd = ConnectRequestQueue::requests[i];
	cmd.pSocket = this;
	cmd.index = i;
	QueueUserWorkItem(HandleConnect, &cmd, WT_EXECUTELONGFUNCTION);
}



// Given
//	CommandNewSessionSrv	the command context
// Clone the control block whose handle is passed by the command and bind the interfaces
// Initialize near and remote fiber ID as well
// Return
//	true if succeeded
//	false if failed
bool CSocketItemEx::MapControlBlock(const CommandNewSessionSrv &cmd)
{
#ifndef NDEBUG
	printf_s("%s called, source process id = %d, size of the shared memory = 0x%X\n", __FUNCTION__, cmd.idProcess, cmd.dwMemorySize);
#endif
	if(hMemoryMap != NULL)
		Destroy();

	HANDLE hThatProcess = OpenProcess(PROCESS_DUP_HANDLE
		, false
		, cmd.idProcess);
	if(hThatProcess == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return false;
	}
#if (TRACE & TRACE_ULACALL)
	printf_s("Handle of the source process is %I64X, handle of the shared memory in the source process is %I64X\n"
		, (long long)hThatProcess
		, (long long)cmd.hMemoryMap);
#endif

	// get the near-end shared memory handle
	if(! DuplicateHandle(hThatProcess
		, cmd.hMemoryMap
		, GetCurrentProcess()
		, & hMemoryMap
		, 0	// ignored, because of the duplicate same access option
		, FALSE
		, DUPLICATE_SAME_ACCESS))
	{
		REPORT_ERROR_ON_TRACE();
		goto l_bailout;
	}

#if (TRACE & TRACE_ULACALL)
	printf_s("Handle of the mapped memory in current process is %I64X\n", (long long)hMemoryMap);
#endif

	dwMemorySize = cmd.dwMemorySize;
	pControlBlock = (ControlBlock *)MapViewOfFile(hMemoryMap
		, FILE_MAP_ALL_ACCESS
		, 0, 0, dwMemorySize);
	if(pControlBlock == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		goto l_bailout1;
	}
#if (TRACE & TRACE_ULACALL)
	printf_s("Successfully take use of the shared memory object.\r\n");
#endif

	CloseHandle(hThatProcess);
	// this->fiberID == cmd.fiberID, provided it is a passive/welcome socket, not a initiative socket
	// assert: the queue of the returned value has been initialized by the caller already
	idSrcProcess = cmd.idProcess;
	hEvent = cmd.hEvent;
	return true;

l_bailout1:
	CloseHandle(hMemoryMap);
l_bailout:
	CloseHandle(hThatProcess);
	return false;
}



// See also CSocketItem::Destroy();
void CSocketItemEx::ClearInUse()
{
	register HANDLE h;
	if ((h = InterlockedExchangePointer((PVOID *)& pControlBlock, NULL)) != NULL)
		::UnmapViewOfFile(h);
}




// UNRESOLVED! TODO: enforce rate-limit (and rate-limit based congestion avoidance/control)
// TODO: UNRESOLVED! is it multi-home aware?
// Given
//	ULONG	number of WSABUF descriptor to gathered in sending
//	ScatteredSendBuffers
// Return
//	number of bytes sent, or 0 if error
// 'Prefer productivity over cleverness' - if there is some 'cleverness'
int CSocketItemEx::SendPacket(register u32 n1, ScatteredSendBuffers s)
{
	DWORD n = 0;
	int r;

#ifndef OVER_UDP_IPv4
	CtrlMsgHdr nearInfo;
	WSAMSG wsaMsg;
	//
	wsaMsg.Control.buf = (CHAR *)& nearInfo;
	wsaMsg.Control.len = sizeof(nearInfo);
	nearInfo.pktHdr = CLowerInterface::Singleton.nearInfo.pktHdr;
	if(! CLowerInterface::Singleton.SelectPath
		(& nearInfo.u, fidPair.source, pControlBlock->nearEndInfo.ipi6_ifindex, sockAddrTo))
	{
		return 0;	// no selectable path
	}
	wsaMsg.dwBufferCount = n1;
	wsaMsg.lpBuffers = & s.scattered[1];
	wsaMsg.name = (LPSOCKADDR)sockAddrTo;
	wsaMsg.namelen = sizeof(sockAddrTo->Ipv6);
# ifndef NDEBUG
	s.scattered[0].buf = NULL;
	s.scattered[0].len = 0;
	if(nearInfo.u.idALF != fidPair.source)
		BREAK_ON_DEBUG();
# endif
# if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("Near end's address info:\n");
	// Level: [0 for IPv4, 41 for IPv6]]
	printf("Len = %d, level = %d, type = %d, local interface address:\n"
		, (int)nearInfo.pktHdr.cmsg_len
		, nearInfo.pktHdr.cmsg_level
		, nearInfo.pktHdr.cmsg_type);
	DumpHexical(& nearInfo.u, sizeof(nearInfo.u));
	printf_s("Target address:\n\t");
	DumpNetworkUInt16((uint16_t *)wsaMsg.name, wsaMsg.namelen / 2);
# endif
	timestamp_t t = NowUTC();
	r = WSASendMsg(CLowerInterface::Singleton.sdSend, & wsaMsg, 0, &n, NULL, NULL);
#else
	s.scattered[0].buf = (CHAR *)& fidPair;
	s.scattered[0].len = sizeof(fidPair);
	n1++;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("\nPeer socket address:\n");
	DumpNetworkUInt16((uint16_t *)sockAddrTo, sizeof(SOCKADDR_IN6) / 2);
#endif
	timestamp_t t = NowUTC();
	r = WSASendTo(CLowerInterface::Singleton.sdSend
		, s.scattered, n1
		, &n
		, 0
		, (const struct sockaddr *)sockAddrTo
		, sizeof(sockAddrTo->Ipv4)
		, NULL
		, NULL);
#endif

	if (r != 0)
	{
		ReportWSAError("CSocketItemEx::SendPacket");
		return 0;
	}
	tRecentSend = t;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("\n#%u(Near end's ALFID): %d bytes sent.\n", fidPair.source, n);
#endif
	return n;
}



/**
 *	Manipulation of the host firewall
 *	Return
 *		0 if no error
 *		positive if warning
 */
#ifdef __MINGW32__

static int CreateFWRules() { return 0; }

#else

static int CreateFWRules()
{
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	INetFwPolicy2 *pNetFwPolicy2 = NULL;
	INetFwRules *pFwRuleSet = NULL;
	INetFwRule *pFwRule = NULL;
	BSTR bstrRuleName = SysAllocString(L"Flexible Session Protocol");
	BSTR bstrRuleDescription = SysAllocString(L"Allow network traffic from/to FSP over IPv6");
	BSTR bstrRuleDescription2 = SysAllocString(L"Allow network traffic from/to FSP over UDP/IPv4");
	BSTR bstrRuleGroup = SysAllocString(L"FSP/IPv6");	//  and optionally FSP over UDP/IPv4
	BSTR bstrRuleGroup2 = SysAllocString(L"FSP/UDP");	//  and optionally FSP over IPv6
	//
	OLECHAR strUDPport[6];
	_itow_s(be16toh(DEFAULT_FSP_UDPPORT), strUDPport, 6, 10);
	BSTR bstrRulePorts = SysAllocString(strUDPport);
	//
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
	pFwRule->put_Description(bstrRuleDescription2);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);	// NET_FW_IP_VERSION_V4
	pFwRule->put_LocalPorts(bstrRulePorts);
	// For sake of NAT the REMOTE port is NOT particularly specified
	// pFwRule->put_RemotePorts(bstrRulePorts);
	pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
	pFwRule->put_Grouping(bstrRuleGroup2);
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
	pFwRule->put_Description(bstrRuleDescription2);
	pFwRule->put_ApplicationName(bstrRuleApplication);
	// pFwRule->put_ServiceName(bstrRuleService);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_UDP);	// NET_FW_IP_VERSION_V4
	pFwRule->put_LocalPorts(bstrRulePorts);
	// For sake of NAT the REMOTE port is NOT particularly specified
	// pFwRule->put_RemotePorts(bstrRulePorts);
	pFwRule->put_Direction(NET_FW_RULE_DIR_IN);		// By default the direcion is in
	pFwRule->put_Grouping(bstrRuleGroup2);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	// Allow applications to receive unsolicited traffic directly
	// from the Internet through a NAT edge device
	// Note that edge traversal is allowed for UDP traffic only.
	// For IPv6 it is assumed that no NAT except simple network prefix substitution is involved.
	pFwRule->put_EdgeTraversal(VARIANT_TRUE);
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
	SysFreeString(bstrRuleDescription2);
	SysFreeString(bstrRuleGroup);
	SysFreeString(bstrRuleGroup2);
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
#endif


/**
 * Mobility support, in FSP over IPv6 only.
 */
#ifndef OVER_UDP_IPv4
// Mark sdRecv as disabled
inline void	CLowerInterface::DisableSocket(SOCKET sdRecv)
{
	for (register u_int i = 0; i < sdSet.fd_count; i++)
	{
		if (sdRecv == sdSet.fd_array[i])
		{
			InterlockedBitTestAndSet(&disableFlags, i);
			return;
		}
	}
}


// hard coded: when the 96-bit prefix are equal the two addresses are considered at the same interface
inline bool CLowerInterface::IsPrefixDuplicated(int ifIndex, PIN6_ADDR p)
{
	for (register u_int j = 0; j < sdSet.fd_count; j++)
	{
		if (interfaces[j] == ifIndex
		&& *(uint64_t *)(addresses[j].sin6_addr.u.Byte) == *(uint64_t *)(p->u.Byte)
		&& *(uint32_t *) & (addresses[j].sin6_addr.u.Byte[8]) == *(uint32_t *) & (p->u.Byte[8])
		)
		{
			return true;
		}
	}

	return false;
}



// Note that at run time adding an IPv6 address is done when MibParameterChange event is received
// This simple algorithm support adding new IPv6 address once only!
inline void CLowerInterface::OnAddingIPv6Address(u32 ifIndex, const SOCKADDR_IN6 & sin6Addr)
{
	// See also LearnAddresses, MakeALFIDsPool, operator::[], AllocItem, FreeItem
	if (be32toh(*(ALFID_T *)& sin6Addr.sin6_addr.u.Byte[12]) > LAST_WELL_KNOWN_ALFID)
		return;

	register u_int i;
	for(i = 0; i < sdSet.fd_count; i++)
	{
		if (SOCKADDR_SUBNET(addresses + i) == SOCKADDR_SUBNET(& sin6Addr)
		 && SOCKADDR_HOSTID(addresses + i) == SOCKADDR_HOSTID(& sin6Addr)
		 && interfaces[i] == ifIndex
		 && !BitTest(&disableFlags, i))
		{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
			printf_s("Found redundant address configured, index = %d\n", i);
#endif
			return;
		}
	}
	// try to replace the first disabled
	for (i = 0; i < sdSet.fd_count; i++)
	{
		if (interfaces[i] == ifIndex && BitTest(&disableFlags, i))
		{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
			printf_s("Found a disabled interface due to address reconfiguration, index = %d\n", i);
#endif
			break;
		}
	}
	//
	if (i >= SD_SETSIZE)
		return;

	interfaces[i] = ifIndex;
	InterlockedBitTestAndSet(& ::enableFlags, i);
}



// This simple algorithm support one new IPv6 address for each interface only!
inline void CLowerInterface::OnIPv6AddressMayAdded(u32 ifIndex, const SOCKADDR_IN6 & sin6Addr)
{
	// See also LearnAddresses, MakeALFIDsPool, operator::[], AllocItem, FreeItem
	if (be32toh(*(ALFID_T *)& sin6Addr.sin6_addr.u.Byte[12]) > LAST_WELL_KNOWN_ALFID)
		return;

	register u_int i;
	//
	for (i = 0; i <= sdSet.fd_count; i++)
	{
		if (interfaces[i] == ifIndex && InterlockedBitTestAndReset(&enableFlags, i))
		{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
			printf_s("Try to enable/re-enable an interface, index = %d\n", i);
#endif
			break;
		}
	}
	if (i > sdSet.fd_count)
		return;
	//
	SOCKET sdRecv = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
	if (sdRecv == INVALID_SOCKET)
		return; // throw E_HANDLE;	//??
	//
	addresses[i] = sin6Addr;
	if (::bind(sdRecv, (const sockaddr *)& addresses[i], sizeof(SOCKADDR_IN6)) < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot bind to new interface address");
		return;
	}
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	CHAR strIPv6Addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, (PVOID)& sin6Addr.sin6_addr, strIPv6Addr, sizeof(strIPv6Addr));
	printf_s("Set IPv6 interface#%d IPv6 address to %s\n", i, strIPv6Addr);
#endif
	if (SetInterfaceOptions(sdRecv) == 0)
		iRecvAddr = i;
	//
	SetLocalApplicationLayerFiberIDs(i);
	// re-enable the new socket. if unnecessary, little harm is done
	InterlockedCompareExchange(&sdSet.fd_count, i + 1, i);
	sdSet.fd_array[i] = sdRecv;
	InterlockedBitTestAndReset(& disableFlags, i);

	// The code is naive but simple enough to explain itself
	for (register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		InterlockedExchange8(&itemStorage[i].isNearEndHandedOver, 1);
	}
}



// Linear search and remove the entry. The set is too small to exploit more complicate search algorithm
// We assume if ever one address is removed, all the remain address of the same 96-bit prefix, if any, would be eventually removed as well
inline void CLowerInterface::OnRemoveIPv6Address(u32 ifIndex, const IN6_ADDR & in6Addr)
{
	for (register u_int i = 0; i < sdSet.fd_count; i++)
	{
		if (be32toh(((PFSP_IN6_ADDR)& in6Addr)->idALF) <= LAST_WELL_KNOWN_ALFID
		&& interfaces[i] == ifIndex
		&& ((PFSP_IN6_ADDR)& in6Addr)->idHost == SOCKADDR_HOSTID(addresses + i)
		&& ((PFSP_IN6_ADDR)& in6Addr)->subnet == SOCKADDR_SUBNET(addresses + i))
		{
			if (!InterlockedBitTestAndSet(&disableFlags, i))
			{
				RemoveALFIDAddressPool(ifIndex);	// so, all IP address bound to the same interface is removed
				//
				if (sdSet.fd_array[i] == sdPromiscuous)
				{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
					printf_s("To disable promiscuous mode on IPv6 interface #%d\n", i);
#endif
					DisablePromiscuous();
				}
				//
				closesocket(sdSet.fd_array[i]);
			}
			// See also CSocketItemEx::OnLocalAdressChanged. It is a special case for effective loop-back
			// UNRESOLVED!
			// When porting to Linux should implement a high-efficiency local socket, transparently for ULA
			for (register int j = 0; j < MAX_CONNECTION_NUM; j++)
			{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
				printf_s("To disable a effective loopback socket for connection#%d @%d\n", j, i);
#endif
				if (SOCKADDR_HOSTID(itemStorage[j].sockAddrTo) == ((PFSP_IN6_ADDR)& in6Addr)->idHost
				 && SOCKADDR_SUBNET(itemStorage[j].sockAddrTo) == ((PFSP_IN6_ADDR)& in6Addr)->subnet)
				{
					SOCKADDR_HOSTID(itemStorage[j].sockAddrTo) = 0;
					SOCKADDR_SUBNET(itemStorage[j].sockAddrTo) = 0;
				}
			}
			return;
		}
	}
}


/**
	mobility support, for IPv6 only...
	scan all configured FSP socket, modify the near end addresses accordingly
	0.There's no way to listen in a real promiscuous mode
	1.There's no way to rebind a socket to a new IP address.
	2.On Windows platform an interface change it IPv6 address by delete the old address then add the new address
	On delete an address, if no prefix mapping to the address remained, the mapped bit is set 1 in the disableFlag, the socket is closed 
	On add an address, firstly try to append new one if fd_count < SD_SETSIZE, else scan the bit to find the free entry
	On select, 
	// TODO: if one socket is closed, would select return? Sleep?
 **/
// The information returned in the MIB_UNICASTIPADDRESS_ROW structure is only enough information that an application can
// call the GetUnicastIpAddressEntry function to query complete information on the IP address that changed. 
// At run time MibAddInstance is called BEFORE the new IPv6 address is thoroughly configured
VOID NETIOAPI_API_ OnUnicastIpChanged(PVOID, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE notificationType)
{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
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
#endif
	// As we have already filter out MibInitialNotification
	if (row == NULL)
	{
		BREAK_ON_DEBUG();	// Cannot guess which IP interface was changed
		return;
	}

	if (notificationType == MibAddInstance)
		CLowerInterface::Singleton.OnAddingIPv6Address(row->InterfaceIndex, row->Address.Ipv6);
	else if (notificationType == MibParameterNotification)
		CLowerInterface::Singleton.OnIPv6AddressMayAdded(row->InterfaceIndex, row->Address.Ipv6);
	else if (notificationType == MibDeleteInstance)
		CLowerInterface::Singleton.OnRemoveIPv6Address(row->InterfaceIndex, row->Address.Ipv6.sin6_addr);
	// else just ignore
}
#endif