/*
 * FSP lower-layer service program, collection of the platform-dependent
 * / IPC-machanism-dependent functions
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

#include <netfw.h>
#include <Psapi.h>
#include <tchar.h>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")



#define REPORT_WSAERROR_TRACE(s) (\
	printf("\n/**\n * %s, line# %d\n * %s\n */\n", __FILE__, __LINE__, __FUNCDNAME__), \
	ReportWSAError(s)\
	)


// The reference to the singleton instance of the lower service interface 
CLowerInterface	* CLowerInterface::pSingleInstance;

// The hanlde of the timer queue singleton instance
HANDLE	TimerWheel::timerQueue;

// The preconfigured ALFID, for FSP emulator with user-mode Windows socket only
static ALFID_T preallocatedIDs[MAX_CONNECTION_NUM];

// The function called by the macro REPORT_WSAERROR_TRACE
static int LOCALAPI ReportWSAError(char * msg);

// The function called directly or by ReportWSAError
static void LOCALAPI ReportErrorAsMessage(int);

// Forward declartion of the firewall manipulation function
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


#if (_WIN32_WINNT < 0x0600)
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


// Forward declaration of the callback function for handling the event that some IPv6 inferface was changed
VOID NETIOAPI_API_ OnUnicastIpChanged(PVOID, PMIB_UNICASTIPADDRESS_ROW, MIB_NOTIFICATION_TYPE);


#ifndef NDEBUG
void CSocketSrvTLB::AcquireMutex()
{
	uint64_t t0 = GetTickCount64();
	while(!TryAcquireSRWLockExclusive(& rtSRWLock))
	{
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			BREAK_ON_DEBUG();	// To trace the call stack
			throw -EDEADLK;
		}
		Sleep(50);	// if there is some thread that has exclusive access on the lock, wait patiently
	}
}
#endif



// The constructor of the lower service interface instance
//	- Startup the socket service
//	- Create rule entries in the firewall setting to enable FSP traffic
//	- Bind the listening sockets besides the default sending socket
//	- Pre-allocate Application Layer Fiber ID pool
//	- Enable acception and processing of the remote FSP packets
//	- Enable mobility detection
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
		throw (HRESULT)r;
	}
#if (_WIN32_WINNT < 0x0600)
	if((r = GetPointerOfWSASendMsg(sdSend)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot get function pointer WSASendMsg");
		throw (HRESULT)r;
	}
#endif

	mesgInfo.name =  (struct sockaddr *) & addrFrom;
	mesgInfo.namelen = sizeof(addrFrom);
	mesgInfo.Control.buf = (char *) & nearInfo;
	mesgInfo.Control.len = sizeof(nearInfo);

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
	printf_s("Thead ID of the receiver of the packet from the remote end point = %d\r\n", idReceiver);
	if(thReceiver == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		throw E_ABORT;
	}

#ifndef OVER_UDP_IPv4
	disableFlags = 0;
	NotifyUnicastIpAddressChange(AF_INET6, OnUnicastIpChanged, NULL, FALSE, &hMobililty);
#endif
}



// The destructor: kill the listening thread at first?
CLowerInterface::~CLowerInterface()
{
	CancelMibChangeNotify2(hMobililty);
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



// Preallocate a pool of re-usable random ALFIDs. Prealloction would later make the lower network interface to preconfigure the corresponding IP addresses
// This is a workaround as we cannot receive a unicasted packet whose destination IPv6 address does not match any known unicast IP address on an NIC
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
			rand_w32(&id, 1);
			k = be32toh(id) & (MAX_CONNECTION_NUM - 1);
		} while (be32toh(id) <= LAST_WELL_KNOWN_ALFID || tlbSockets[k]->fidPair.source != 0);
		//
		tlbSockets[k]->fidPair.source = preallocatedIDs[i] = id;
	}
}



// TODO: fill in the allowed prefixes with properly multihome support (utilize concept of 'zone')
// multihome/mobility/resilence support (see also CInterface::EnumEffectiveAddresses):
// MAX_PHY_INTERFACES is hard-coded to 4
// sockAddrTo[0] is the most preferred address (care of address)
// sockAddrTo[3] is the home-address
// while sockAddr[1], sockAddr[2] are backup-up/load-balance address (might be zero)
int LOCALAPI CLowerInterface::EnumEffectiveAddresses(uint64_t *prefixes)
{
	// UNRESOLVED! could we make sure u is 64-bit aligned?
	if (nearInfo.IsIPv6())
	{
		prefixes[0] = *(uint64_t *) & nearInfo.u;
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


// There's the document glich when this code snippet was written: the output buffer MUST be specified
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
inline void CLowerInterface::LearnAddresses()
{
	PMIB_UNICASTIPADDRESS_TABLE table;
	PIN6_ADDR p;
	u_int & k = sdSet.fd_count;
	CHAR strIPv6Addr[INET6_ADDRSTRLEN];

	FD_ZERO(&sdSet);
	memset(addresses, 0, sizeof(addresses));

	GetUnicastIpAddressTable(AF_INET6, &table);
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

		if (table->Table[i].DadState != IpDadStatePreferred)
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
			throw E_OUTOFMEMORY;

		interfaces[k] = table->Table[i].InterfaceIndex;
		addresses[k].sin6_family = AF_INET6;
		addresses[k].sin6_addr = *p;
		// port number and flowinfo are all zeroed already
		addresses[k].sin6_scope_id = table->Table[i].ScopeId.Value;

		if (::bind(sdSend, (const struct sockaddr *)& addresses[k], sizeof(SOCKADDR_IN6)) != 0)
		{
			REPORT_WSAERROR_TRACE("Bind failure");
			throw E_ABORT;
		}
		//
		if(SetInterfaceOptions(sdSend) == 0)
			iRecvAddr = i;
		// UNRESOLVED!? But if SetInterfaceOptions failed thoroughly?
		FD_SET(sdSend, &sdSet);
		// k++;	// When FD_SET, the alias target is already increased

		sdSend = socket(AF_INET6, SOCK_RAW, IPPROTO_FSP);
		if (sdSend == INVALID_SOCKET)
			throw E_HANDLE;
	}
	if (k == 0)
	{
		printf_s("IPv6 not enabled?");
		throw E_NOINTERFACE;
	}

	// note that k is alias of fd_count of the socket set for this instance
	FreeMibTable(table);
}



// For FSP over IPv6 raw-socket, preconfigure an IPv6 interface with ALFID pool
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
inline void CLowerInterface::RemoveALFIDAddressPool(NET_IFINDEX ifIndex)
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
	if (setsockopt(sd, IPPROTO_IP, IP_PKTINFO, (char *)& enablePktInfo, sizeof(enablePktInfo)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot set socket option to fetch the source IP address");
		return -1;
	}

	return 0;
}



// Given
//	PSOCKADDR_IN
//	int			the position that the address is provisioned
// Return
//	0 if no error
//	negative, as the error number
int CLowerInterface::BindSendRecv(const SOCKADDR_IN *pAddrListen, int k)
{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("Bind to listen at UDP socket address: %d.%d.%d.%d:%d\n"
		, pAddrListen->sin_addr.S_un.S_un_b.s_b1
		, pAddrListen->sin_addr.S_un.S_un_b.s_b2
		, pAddrListen->sin_addr.S_un.S_un_b.s_b3
		, pAddrListen->sin_addr.S_un.S_un_b.s_b4
		, be16toh(pAddrListen->sin_port));
#endif
	memcpy(&addresses[k], pAddrListen, sizeof(SOCKADDR_IN));
	interfaces[k] = 0;

	if (::bind(sdSend, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN)) != 0)
	{
		REPORT_WSAERROR_TRACE("Cannot bind to the selected address");
		return -1;
	}

	SetInterfaceOptions(sdSend);
	FD_SET(sdSend, &sdSet);
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

	u_int & k = sdSet.fd_count;
	register PSOCKADDR_IN p;
	FD_ZERO(& sdSet);
	for (register int i = 0; i < listAddress.iAddressCount; i++)
	{
		p = (PSOCKADDR_IN)listAddress.Address[i].lpSockaddr;
		if (p->sin_family != AF_INET)
			throw E_UNEXPECTED;	// memory corruption!
		//
		if (k >= SD_SETSIZE)
			throw E_OUTOFMEMORY;
		//
		p->sin_port = DEFAULT_FSP_UDPPORT;
		if(BindSendRecv(p, k) != 0)
		{
			REPORT_WSAERROR_TRACE("Bind failure");
			throw E_ABORT;
		}

		sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(sdSend == INVALID_SOCKET)
			throw E_HANDLE;
		// On BindInterface, k++; as k is the alias of sdSet.fd_count
	}
	if (k >= SD_SETSIZE)
		throw E_OUTOFMEMORY;

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
		throw E_ABORT;
	}

	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
		throw E_HANDLE;
	// Set the INADDR_ANY for transmission; reuse storage of loopback address
	p->sin_addr.S_un.S_addr = INADDR_ANY;
	::bind(sdSend, (const struct sockaddr *)p, sizeof(SOCKADDR_IN));
	// SetInterfaceOptions(sdSend);	// unnecessary
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
		printf("PANIC! To restart after diagnose internal exception 0x%X", x);
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
	if(sdSet.fd_count <= 0)
		throw E_INVALIDARG;
	//
	do
	{
		// make it as compatible as possible...
		FD_ZERO(& readFDs);
		r = 0;
		for(i = 0; i < (int)sdSet.fd_count; i++)		
#ifndef OVER_UDP_IPv4
		if(! BitTest(& disableFlags, i))
#endif
		{
			FD_SET(sdSet.fd_array[i], & readFDs);
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
			Sleep(1000);
			continue;
		}
		// It is documented that select returns total number of sockets that are ready, however, if one socket is closed
		// 'select' success while following WSARecvMsg will fail
		// Cannot receive packet information, error code = 10038
		// Error: An operation was attempted on something that is not a socket.
		// a more sophisticated implementation should be asynchronous on reading/receiving
		r = select(readFDs.fd_count, & readFDs, NULL, NULL, NULL);
		if(r == SOCKET_ERROR)
		{
			int	err = WSAGetLastError();
			if(err == WSAENETDOWN)
			{
				Sleep(1000);	// wait for the network service up again
				continue;
			}
			else if (err = WSAENOTSOCK)
			// One of the descriptor sets contains an entry that is not a socket. deliberately close a socket
			{
				Sleep(50);
				continue;
			}
			REPORT_WSAERROR_TRACE("select failure");
			BREAK_ON_DEBUG();
			break;	// TODO: crash recovery from select
		}
		//
		for(i = 0; i < (int) readFDs.fd_count; i++)
		{
			// Unfortunately, it was proven that no matter whether there is MSG_PEEK
			// MSG_PARTIAL is not supported by the underlying raw socket service
			mesgInfo.dwFlags = 0;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("\nPacket on socket #%X: to process...\n", (unsigned)readFDs.fd_array[i]);
#endif
			r = AcceptAndProcess(readFDs.fd_array[i]);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
			printf_s("\nPacket on socket #%X: processed, result = %d\n", (unsigned)readFDs.fd_array[i], r);
#endif
			if (r == EADDRNOTAVAIL)
			{
				DisableSocket(readFDs.fd_array[i]);
			}
			else if (r != 0)	// E_ABORT or ENOMEM
			{
				printf_s("AcceptAndProcess error return %d\n", r);
				if (r == E_ABORT)
					throw - E_ABORT;
			}
		}
	} while(1, 1);
}



// The handler's mainbody to accept and process one particular remote packet
// See also SendPacket
int CLowerInterface::AcceptAndProcess(SOCKET sdRecv)
{
	// Unfortunately, it was proven that no matter whether there is MSG_PEEK
	// MSG_PARTIAL is not supported by the underlying raw socket service
	// FSP is meant to optimize towards IPv6. OVER_UDP_IPv4 is just for conceptual test
	// NO! We don't intend to support dual-stack in FSP.
	WSABUF	scatteredBuf[1];
#ifdef OVER_UDP_IPv4
	scatteredBuf[0].buf = (CHAR *) & pktBuf->idPair;
#else
	scatteredBuf[0].buf = (CHAR *) & pktBuf->hdr;
#endif
	scatteredBuf[0].len = MAX_LLS_BLOCK_SIZE;
	mesgInfo.lpBuffers = scatteredBuf;
	mesgInfo.dwBufferCount = 1;

	if (WSARecvMsg(sdRecv, &mesgInfo, &countRecv, NULL, NULL) < 0)
	{
		int err = WSAGetLastError();
		if (err != WSAENOTSOCK)
		{
			ReportErrorAsMessage(err);
			return E_ABORT;		// Unrecoverable error
		}
		// TO DO: other errors which could not undertake crash recovery
		//
		return EADDRNOTAVAIL;
	}

	// From the receiver's point of view the local fiber id was stored in the peer fiber id field of the received packet
#ifdef OVER_UDP_IPv4
	countRecv -= sizeof(PairALFID);	// extra prefixed bytes are substracted
	nearInfo.u.idALF = pktBuf->idPair.peer;
	SOCKADDR_ALFID(mesgInfo.name) = pktBuf->idPair.source;
#else
	pktBuf->idPair.peer = nearInfo.u.idALF;
	pktBuf->idPair.source = SOCKADDR_ALFID(mesgInfo.name);
#endif

	FSPOperationCode opCode = (FSPOperationCode) pktBuf->hdr.hs.opCode;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("#%u(Near end's ALFID): packet %s(%d) received\n\tALFID of packet source is #%u\n"
		, nearInfo.u.idALF
		, opCodeStrings[opCode], (int)opCode, pktBuf->idPair.source);
	printf_s("Remote address:\n");
	DumpNetworkUInt16((uint16_t *) & addrFrom, sizeof(addrFrom) / 2);
	printf_s("Near sink:\n");
	DumpNetworkUInt16((uint16_t *) & nearInfo.u, sizeof(nearInfo.u) / 2);
	printf_s("Fixed header:\n");
	DumpNetworkUInt16((uint16_t *) & pktBuf->hdr, sizeof(pktBuf->hdr) / 2);
#endif
	CSocketItemEx *pSocket = NULL;
	switch (opCode)
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
		if (pSocket == NULL)
			break;
		pSocket->OnConnectRequestAck(pktBuf, countRecv);
		break;
	case RESET:
		OnGetResetSignal();
		break;
		// TODO: get hint of explicit congest notification
	case PERSIST:
	case PURE_DATA:
	case ACK_FLUSH:
	case RELEASE:
	case MULTIPLY:
	case KEEP_ALIVE:
		pSocket = MapSocket();
		if (pSocket == NULL)
		{
#ifdef TRACE
			printf_s("Cannot map socket for local fiber#%u(_%X_)\n", GetLocalFiberID(), be32toh(GetLocalFiberID()));
#endif
			break;
		}
		pktBuf->lenData = countRecv - be16toh(pktBuf->GetHeaderFSP()->hs.hsp);
		if (pktBuf->lenData < 0 || pktBuf->lenData > MAX_BLOCK_SIZE)
			break;
		// illegal packet is simply discarded!
		pktBuf->pktSeqNo = be32toh(pktBuf->GetHeaderFSP()->sequenceNo);
#if defined(TRACE) && (TRACE & TRACE_PACKET)
		printf_s("%s[%d] packet #%u\n\tpayload length %d, to put onto the queue\n"
			, opCodeStrings[opCode], opCode, pktBuf->pktSeqNo, pktBuf->lenData);
#endif
		// save the source address temporarily as it is not necessariy legitimate
		pSocket->sockAddrTo[MAX_PHY_INTERFACES] = addrFrom;
		pSocket->HandleFullICC(pktBuf, opCode);
		break;
		// UNRECOGNIZED packets are simply discarded
	}

	return 0;
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
	WSABUF wsaData[2];
	DWORD n = 0;
	wsaData[1].buf = buf;
	wsaData[1].len = len;
#ifdef OVER_UDP_IPv4
	// Store the local(near end) fiber ID as the source, the remote end fiber ID as
	// the destination fiber ID in the given fiber ID association
	pktBuf->idPair.peer = _InterlockedExchange((LONG *) & pktBuf->idPair.source, pktBuf->idPair.peer);
	wsaData[0].buf = (char *) & pktBuf->idPair;
	wsaData[0].len = sizeof(pktBuf->idPair);
	int r = WSASendTo(sdSend
		, wsaData, 2, &n
		, 0
		, (const sockaddr *)& addrFrom, mesgInfo.namelen
		, NULL, NULL);
#else
	mesgInfo.lpBuffers = & wsaData[1];
	mesgInfo.dwBufferCount = 1;
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
//	CSocketItemEx *	the pointer to the premature socket (default NULL)
//	uint32_t			reason code flags of reset (default zero)
// Do
//	Send back the echoed reset at the same interface of receiving
//	in CHALLENGING, CONNECT_AFFIRMING, unresumable CLOSABLE and unrecoverable CLOSED state,
//	and of course, throttled LISTENING state
void LOCALAPI CLowerInterface::SendPrematureReset(uint32_t reasons, CSocketItemEx *pSocket)
{
	struct FSP_RejectConnect reject;
	reject.reasons = reasons;
	reject.hs.Set<FSP_RejectConnect, RESET>();
	if(pSocket)
	{
		// In CHALLENGING, CONNECT_AFFIRMING where the peer address is known
		reject.u.timeStamp = htobe64(NowUTC());
		// See also CSocketItemEx::Emit() and SetIntegrityCheckCode():
		reject.u2.fidPair = pSocket->fidPair;
		pSocket->SendPacket(1, ScatteredSendBuffers(&reject, sizeof(reject)));
	}
	else
	{
		memcpy(& reject, pktBuf->GetHeaderFSP(), sizeof(reject.u) + sizeof(reject.u2));
		SendBack((char *) & reject, sizeof(reject));
	}
}



// Given
//	char *		The error message prefix string in multi-byte character set
// Do
//	Print the system message mapped to the last error to the standard output, prefixed by the given message prefix
// Return
//	the WSA error number, which is greater than zero. may be zero if no error at all.
static int LOCALAPI ReportWSAError(char * msg)
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
 *	The timer queue
 */
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



// Return
//	Whether the ULA process assocated with the LLS socket is still alive
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



// Return
//	true if the timer was set, false if it failed.
bool CSocketItemEx::AddTimer()
{
	return (
		::CreateTimerQueueTimer(& timer, TimerWheel::Singleton()
			, KeepAlive	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, tKeepAlive_ms
			, tKeepAlive_ms
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE
		);
}



// Given
//	uint32_t		number of millisecond delayed to trigger the timer
// Return
//	true if the timer was set, false if it failed.
bool LOCALAPI CSocketItemEx::ReplaceTimer(uint32_t period)
{
	tKeepAlive_ms = period;
	return ( timer == NULL 
		&&	::CreateTimerQueueTimer(& timer, TimerWheel::Singleton()
			, KeepAlive	// WAITORTIMERCALLBACK
			, this		// LPParameter
			, period
			, period
			, WT_EXECUTEINTIMERTHREAD)
		|| timer != NULL
		&& ::ChangeTimerQueueTimer(TimerWheel::Singleton(), timer, period, period)
		);
}



// Return
//	true if the timer was set, false if it failed.
// Remark
// A lazy acknowledgement is hard coded to one RTT, with an implementation depended floor value
bool CSocketItemEx::AddLazyAckTimer()
{
	return (lazyAckTimer == NULL
		&& ::CreateTimerQueueTimer(&lazyAckTimer, TimerWheel::Singleton()
			, LazilySendSNACK
			, this
			, max(LAZY_ACK_DELAY_MIN_ms, (tRoundTrip_us >> 10))
			, 0
			, WT_EXECUTEINTIMERTHREAD));
}



// Return
//	true if the timer was set, false if it failed.
// Remark
// A retransmission timer should be hard coded to 4 RTT, with an implementation depended floor value
bool CSocketItemEx::AddResendTimer(uint32_t tPeriod_ms)
{
#if !defined(TRACE) || !(TRACE & TRACE_PACKET)
			tPeriod_ms = max(LAZY_ACK_DELAY_MIN_ms, tPeriod_ms);
#else
			tPeriod_ms = INIT_RETRANSMIT_TIMEOUT_ms;
#endif
	return (resendTimer == NULL
		&& ::CreateTimerQueueTimer(&resendTimer, TimerWheel::Singleton()
			, DoResend
			, this
			, tPeriod_ms
			, tPeriod_ms
			, WT_EXECUTEINTIMERTHREAD));
}



// Assume a mutex has been obtained
void CSocketItemEx::RemoveTimers()
{
	HANDLE h;
	if((h = (HANDLE)InterlockedExchangePointer(& timer, NULL)) != NULL)
		::DeleteTimerQueueTimer(TimerWheel::Singleton(), h, NULL);
	
	if((h = (HANDLE)InterlockedExchangePointer(& lazyAckTimer, NULL)) != NULL)
		::DeleteTimerQueueTimer(TimerWheel::Singleton(), h, NULL);

	if((h = (HANDLE)InterlockedExchangePointer(& resendTimer, NULL)) != NULL)
		::DeleteTimerQueueTimer(TimerWheel::Singleton(), h, NULL);
}



// The OS-depending implementation of scheduling transmission queue
void CSocketItemEx::ScheduleEmitQ()
{
	QueueUserWorkItem(HandleSendQ, this, WT_EXECUTEDEFAULT);
}



// The OS-depending implementation of scheduling connection-request queue
void CSocketItemEx::ScheduleConnect(CommandNewSessionSrv *pCmd)
{
	pCmd->pSocket = this;
	QueueUserWorkItem(HandleConnect, pCmd, WT_EXECUTELONGFUNCTION);
}



// Given
//	PktBufferBlock *	Pointer to the buffer block that holds the remote packet received by the underling network service
//	FSPOperationCode	The code point of the remote 'operation'
// Do
//	Process the packet saved in the buffer that is assumed to have a full ICC
// Remark
//	Used to be OS-dependent. TODO: fight against single thread congestion (because of WaitUseMutex) of the socket pool
inline 
void CSocketItemEx::HandleFullICC(PktBufferBlock *pktBuf, FSPOperationCode opCode)
{
	if (!WaitUseMutex())
		return;
	// Because some service call may recycle the FSP socket in a concurrent way
	if (lowState <= 0 || lowState > LARGEST_FSP_STATE)
	{
#ifdef TRACE
		printf_s("Socket#%p for local fiber#%u(_%X_) not in use or not in workable state: %s[%d]\n"
			, this, fidPair.source, be32toh(fidPair.source)
			, stateNames[lowState], lowState);
#endif
		goto l_return;
	}
	// We assume that it costs neglectible time to test whether the ULA process is alive
	if (!IsProcessAlive())
	{
#ifdef TRACE
		printf_s("Socket#%p for local fiber#%u(_%X_), ULA not alive. State: %s[%d]\n"
			, this, fidPair.source, be32toh(fidPair.source)
			, stateNames[lowState], lowState);
#endif
		AbortLLS();
		goto l_return;
	}

	// MULTIPLY is semi-out-of-band COMMAND starting from a fresh new ALFID. Note that pktBuf is the received
	// In the CLONING state only PERSIST is the legitimate acknowledgement to MULTIPLY,
	// while the acknowledgement itself shall typically originate from some new ALFID.
	if (fidPair.peer != pktBuf->idPair.source	// it should be rare
		&& opCode != MULTIPLY && (lowState != CLONING || opCode != PERSIST)
		)
	{
#ifdef TRACE
		printf_s("Source fiber ID #%u the packet does not matched context\n", pktBuf->idPair.source);
#endif
		goto l_return;
	}
	//

	// synchronize the state in the 'cache' and the real state
	lowState = pControlBlock->state;
	headPacket = pktBuf;
	switch (opCode)
	{
	case PERSIST:
		OnGetPersist();
		break;
	case PURE_DATA:
		OnGetPureData();
		break;
	case ACK_FLUSH:
		OnAckFlush();
		break;
	case RELEASE:
		OnGetRelease();
		break;
	case MULTIPLY:
		OnGetMultiply();
		break;
	case KEEP_ALIVE:
		OnGetKeepAlive();
	}
	//
l_return:
	SetMutexFree();
}



// Return true if successed to obtain the mutex lock, false if waited but timed-out
bool CSocketItemEx::WaitUseMutex()
{
	uint64_t t0 = GetTickCount64();
	while (_InterlockedCompareExchange8(& locked, 1, 0) != 0)
	{
		if (! IsInUse() || GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			return false;
		Sleep(50);	// if there is some thread that has exclusive access on the lock, wait patiently
	}

	if(IsInUse())
		return true;
	//
	locked = 0;
	return false;
}



void CSocketItemEx::SetMutexFree()
{
	if(_InterlockedExchange8(& locked, 0) == 0)
		printf_s("Warning: to release the spinlock of the socket#0x%p, but it was released\n", this);
	// yield out the CPU as soon as the mutex is free
	Sleep(0);
}



/*
 * The OS-dependent CommandNewSessionSrv constructor
 */
CommandNewSessionSrv::CommandNewSessionSrv(const CommandToLLS *p1)
{
	CommandNewSession *pCmd = (CommandNewSession *)p1;
	memcpy(this, pCmd, sizeof(CommandToLLS));
	hMemoryMap = pCmd->hMemoryMap;
	dwMemorySize = pCmd->dwMemorySize;
	hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, (LPCSTR)pCmd->szEventName);
}



/**
 *	The OS-depending callback functions of QueueUserWorkItem
 */

// For ScheduleEmitQ
DWORD WINAPI HandleSendQ(LPVOID p)
{
	try
	{
		CSocketItemEx *p0 = (CSocketItemEx *)p;
		p0->WaitUseMutex();
		p0->EmitQ();
		p0->SetMutexFree();
		return 1;
	}
	catch(...)
	{
		return 0;
	}
}



// For ScheduleConnect
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



// UNRESOLVED! TODO: enforce rate-limit (and rate-limit based congestion avoidance/control)
// TODO: UNRESOLVED! is it multi-home awared?
// Given
//	ULONG	number of WSABUF descriptor to gathered in sending
//	ScatteredSendBuffers
// Return
//	number of bytes sent, or 0 if error
int CSocketItemEx::SendPacket(register ULONG n1, ScatteredSendBuffers s)
{
	DWORD n = 0;
	int r;

	// 'Prefer productivity over cleverness - if there is some cleverness'
	if (pControlBlock->nearEndInfo.IsIPv6())
	{
		CtrlMsgHdr nearInfo;
		WSAMSG wsaMsg;
		//
		wsaMsg.Control.buf = (CHAR *)& nearInfo;
		wsaMsg.Control.len = sizeof(nearInfo);
		nearInfo.pktHdr = CLowerInterface::Singleton()->nearInfo.pktHdr;
		if(! CLowerInterface::Singleton()->SelectPath
			(& nearInfo.u, fidPair.source, pControlBlock->nearEndInfo.ipi6_ifindex, sockAddrTo))
		{
			return 0;	// no selectable path
		}
		wsaMsg.dwBufferCount = n1;
		wsaMsg.lpBuffers = & s.scattered[1];
		wsaMsg.name = (LPSOCKADDR)sockAddrTo;
		wsaMsg.namelen = sizeof(sockAddrTo->Ipv6);
#ifndef NDEBUG
		s.scattered[0].buf = NULL;
		s.scattered[0].len = 0;
		if(nearInfo.u.idALF != fidPair.source)
			BREAK_ON_DEBUG();
#endif
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("Near end's address info:\n");
		// Level: [0 for IPv4, 41 for IPv6]]
		printf("Len = %d, level = %d, type = %d, local interface address:\n"
			, (int)nearInfo.pktHdr.cmsg_len
			, nearInfo.pktHdr.cmsg_level
			, nearInfo.pktHdr.cmsg_type);
		DumpHexical(& nearInfo.u, sizeof(nearInfo.u));
		printf_s("Target address:\n\t");
		DumpNetworkUInt16((uint16_t *)wsaMsg.name, wsaMsg.namelen / 2);
#endif
		r = WSASendMsg(CLowerInterface::Singleton()->sdSend, & wsaMsg, 0, &n, NULL, NULL);
	}
	else
	{
		s.scattered[0].buf = (CHAR *)& fidPair;
		s.scattered[0].len = sizeof(fidPair);
		n1++;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf_s("\nPeer socket address:\n");
		DumpNetworkUInt16((uint16_t *)sockAddrTo, sizeof(SOCKADDR_IN6) / 2);
#endif
		r = WSASendTo(CLowerInterface::Singleton()->sdSend
			, s.scattered, n1
			, &n
			, 0
			, (const struct sockaddr *)sockAddrTo
			, sizeof(sockAddrTo->Ipv4)
			, NULL
			, NULL);
	}

	tRecentSend = NowUTC();
	if (r != 0)
	{
		ReportWSAError("CSocketItemEx::SendPacket");
		return 0;
	}
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("\n#%u(Near end's ALFID): %d bytes sent.\n", fidPair.source, n);
#endif
	return n;
}



/**
 *	Manipulation of connection request queue
 */

bool CLightMutex::WaitSetMutex()
{
	uint64_t t0 = GetTickCount64();
	while(_InterlockedCompareExchange8(& mutex, 1, 0))
	{
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			BREAK_ON_DEBUG();
			return false;
		}
		//
		Sleep(0);	// if there is some thread that has exclusive access on the lock, wait patiently
	}
	return true;
}


// Given
//	CommandNewSessionSrv		The request for new connection
// Return
//	non-negative is the position of the new request in the queue
//	negative if error
int ConnectRequestQueue::Push(const CommandNewSessionSrv *p)
{
	WaitSetMutex();
	//
	if(mayFull != 0 && tail == head)
	{
		SetMutexFree();
		return -1;
	}

	register int i = tail;
	if(++tail >= CONNECT_BACKLOG_SIZE)
		tail = 0;
	q[i] = *p;
	mayFull = 1;
	//
	SetMutexFree();
	return i;
}



// Given
//	int		the index of the item to be removed
// Return
//	0	if no error
//	-1	if no item could be removed
int ConnectRequestQueue::Remove(int i)
{
	WaitSetMutex();
	// 
	if (tail < 0 || tail >= CONNECT_BACKLOG_SIZE)
	{
		REPORT_ERRMSG_ON_TRACE("check tail in case of falling into dead loop");
		SetMutexFree();
		return -1;
	}
	//
	if(mayFull == 0 && head == tail)
	{
		SetMutexFree();
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
	SetMutexFree();
	return 0;
}	



/**
 *	Manipulation of the host firewall
 *	Return
 *		0 if no error
 *		positive if warning
 */
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



// Given
//	PFSP_SINKINF 		[out] pointer to the local 'sink' info to be filled
//	ALFID_T				the intent ALFID
//	int					the send-out interface
//	const SOCKADDR_INET * the destination address
// Do
//	Fill in the IPv6 header's source and destination IP address by select the proper path
//	A path is proper if the source IP is on the designated interface, or
//	if there's no interface match try to match the scope.
//	The last resort is the last enabled interface
// Return
//	true if there exists some path
//	false if no path exists, typically because all interfaces were disabled
/**
 * Remark
	Prefix/Precedence/Label/Usage
	::1/128			50 0 Localhost 
	::/0			40 1 Default unicast 
	::ffff:0:0/96	35 4 IPv4-mapped IPv6 address 
	2002::/16		30 2 6to4 
	2001::/32		5 5 Teredo tunneling 
	fc00::/7		3 13 Unique local address 
	::/96 1			3 IPv4-compatible addresses (deprecated) 
	fec0::/10		1 11 Site-local address (deprecated) 
	3ffe::/16		1 12 6bone (returned) 
 */
bool LOCALAPI CLowerInterface::SelectPath(PFSP_SINKINF pNear, ALFID_T nearId, NET_IFINDEX ifIndex, const SOCKADDR_INET *sockAddrTo)
{
	register u_int i;
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("%s fiberId#0x%X, ifIndex = %d\n", __FUNCTION__, nearId, ifIndex);
#endif

	// Link-local first
	if (*(int64_t *)& sockAddrTo->Ipv6.sin6_addr.u == *(int64_t *)& in6addr_linklocalprefix.u)	// hard coded 8 byte address prefix lenth
	{
		for (i = 0; i < sdSet.fd_count; i++)
		{
			if (!BitTest(&disableFlags, i) && *(int64_t *)& addresses[i].sin6_addr.u == *(int64_t *)& in6addr_linklocalprefix.u)
				goto l_matched;
		}
	}
	// then in6addr_6to4prefix
	if (sockAddrTo->Ipv6.sin6_addr.u.Word[0] == in6addr_6to4prefix.u.Word[0])	// hard coded 2 byte address prefix lenth
	{
		for (i = 0; i < sdSet.fd_count; i++)
		{
			if (!BitTest(&disableFlags, i) && addresses[i].sin6_addr.u.Word[0] == in6addr_6to4prefix.u.Word[0])
				goto l_matched;
		}
	}
	// then match terodo tunnelling
	if (*(int32_t *)& sockAddrTo->Ipv6.sin6_addr.u == *(int32_t *)& in6addr_teredoprefix.u)	// hard coded 4 byte address prefix lenth
	{
		for (i = 0; i < sdSet.fd_count; i++)
		{
			if (!BitTest(&disableFlags, i) && *(int32_t *)& addresses[i].sin6_addr.u == *(int32_t *)& in6addr_teredoprefix.u)
				goto l_matched;
		}
	}
	// then a ULA (but site-local is obsolete)
	if ((sockAddrTo->Ipv6.sin6_addr.u.Byte[0] & 0xFE) == 0xFC)	// hard coded unique local address
	{
		for (i = 0; i < sdSet.fd_count; i++)
		{
			if (!BitTest(&disableFlags, i) && (addresses[i].sin6_addr.u.Byte[0] & 0xFE) == 0xFC)
				goto l_matched;
		}
	}
	// user-defined scope matching is the last resort (v4mapped, or arbitrary global IPv6 address)
	int lastResort = -1;
	for (i = 0; i < sdSet.fd_count; i++)
	{
		if (!BitTest(& disableFlags, i))
		{
			if(addresses[i].sin6_scope_id == sockAddrTo->Ipv6.sin6_scope_id
				&& (ifIndex == 0 || interfaces[i] == ifIndex)
				&& *(int64_t *)& addresses[i].sin6_addr.u != *(int64_t *)& in6addr_linklocalprefix.u
				&& addresses[i].sin6_addr.u.Word[0] != in6addr_6to4prefix.u.Word[0]
				&& *(int32_t *)& addresses[i].sin6_addr.u.Word[0] != *(int32_t *)& in6addr_teredoprefix.u
				&& (addresses[i].sin6_addr.u.Byte[0] & 0xFE) != 0xFC	// ULA
			)
			{
				goto l_matched;
			}
			//
			lastResort = i;
		}
	}
	// By default the last enabled interface is selected as the last resort for out-going interface
	if(lastResort < 0)
		return false;
	//
	i = lastResort;
	//
l_matched:
	// memcpy(& pNear->ipi_addr, addresses[i].sin6_addr.u.Byte, 12);	// hard-coded network prefix length, including the host id
	*(uint64_t *)&pNear->ipi_addr = SOCKADDR_SUBNET(addresses + i);
	pNear->idHost = SOCKADDR_HOSTID(addresses + i);
	pNear->idALF = nearId;
	pNear->ipi6_ifindex = 0;	// pNear->ipi6_ifindex = ifIndex;
	//^always send out from the default interface so that underlying routing service can do optimization
	//
	return true;
}



// Note that at run time adding an IPv6 address is done when MibParameterChange event is received
// This simple algorithm support adding new IPv6 address once only!
inline void CLowerInterface::OnAddingIPv6Address(NET_IFINDEX ifIndex, const SOCKADDR_IN6 & sin6Addr)
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
inline void CLowerInterface::OnIPv6AddressMayAdded(NET_IFINDEX ifIndex, const SOCKADDR_IN6 & sin6Addr)
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
	// reenable the new socket. if unnecessary, little harm is done
	InterlockedCompareExchange(&sdSet.fd_count, i + 1, i);
	sdSet.fd_array[i] = sdRecv;
	InterlockedBitTestAndReset(& disableFlags, i);

	// The code is naive but simple enough to explain itself
	for (i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		itemStorage[i].OnLocalAddressChanged();
	}
}



// Linear search and remove the entry. The set is too small to exploit more complicate search algorithm
// We assume if ever one address is removed, all the remain address of the same 96-bit prefix, if any, would be eventually removed as well
inline void CLowerInterface::OnRemoveIPv6Address(NET_IFINDEX ifIndex, const IN6_ADDR & in6Addr)
{
	for (register u_int i = 0; i < sdSet.fd_count; i++)
	{
		if (be32toh(((PFSP_IN6_ADDR)& in6Addr)->idALF) <= LAST_WELL_KNOWN_ALFID
		&& interfaces[i] == ifIndex
		&& ((PFSP_IN6_ADDR)& in6Addr)->idHost == SOCKADDR_HOSTID(addresses + i)
		&& ((PFSP_IN6_ADDR)& in6Addr)->u.subnet == SOCKADDR_SUBNET(addresses + i))
		{
			if (!InterlockedBitTestAndSet(&disableFlags, i))
			{
				RemoveALFIDAddressPool(ifIndex);	// so, all IP address bound to the same interface is removed
				//
				if (sdSet.fd_array[i] == sdPromiscuous)
				{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
					printf_s("To disable promiscous mode on IPv6 interface #%d\n", i);
#endif
					DisablePromiscuous();
				}
				//
				closesocket(sdSet.fd_array[i]);
			}
			// See also CSocketItemEx::OnLocalAdressChanged. It is a special case for effective loop-back
			// UNRESOLVED!
			// When porting to Linux should implement a high-effiency local socket, transparently for ULA
			for (register int j = 0; j < MAX_CONNECTION_NUM; j++)
			{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
				printf_s("To disable a effective loopback socket for connection#%d @%d\n", j, i);
#endif
				if (SOCKADDR_HOSTID(itemStorage[j].sockAddrTo) == ((PFSP_IN6_ADDR)& in6Addr)->idHost
				 && SOCKADDR_SUBNET(itemStorage[j].sockAddrTo) == ((PFSP_IN6_ADDR)& in6Addr)->u.subnet)
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
		CLowerInterface::Singleton()->OnAddingIPv6Address(row->InterfaceIndex, row->Address.Ipv6);
	else if (notificationType == MibParameterNotification)
		CLowerInterface::Singleton()->OnIPv6AddressMayAdded(row->InterfaceIndex, row->Address.Ipv6);
	else if (notificationType == MibDeleteInstance)
		CLowerInterface::Singleton()->OnRemoveIPv6Address(row->InterfaceIndex, row->Address.Ipv6.sin6_addr);
	// else just ignore
}
#endif