/*
 * FSP lower-layer service program, collection of the platform-dependent
 * / IPC-mechanism-dependent functions
 *
    Copyright (c) 2019, Jason Gao
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

#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include "blake2b.h"

static ALFID_T	preallocatedIDs[MAX_CONNECTION_NUM];
static octet	keyInternalRand[FSP_MAX_KEY_SIZE];

/*
 * The OS-dependent CommandNewSessionSrv constructor
 */
CommandNewSessionSrv::CommandNewSessionSrv(const CommandToLLS *p1)
{
	memcpy(this, p1, sizeof(CommandToLLS));
	dwMemorySize = ((CommandNewSession *)p1)->dwMemorySize;
	hShm = shm_open(((CommandNewSession *)p1)->shm_name, O_RDWR, 0777);
	if (hShm < 0)
		perror("Cannot get the handle of the shared memory when MapControlBlock");
	// And we assign fixed signal number for reverse IPC in linux 
}


// To initialize:
//	- Bind the listening sockets besides the default sending socket
//	- Preallocate Application Layer Fiber ID pool
//	- Enable accepting and processing of the remote FSP packets
//	- Enable mobility detection
// Remark
//	IPv6 implementation is put in the kernel
// TODO: create rule entries in the firewall setting to enable FSP traffic?
bool CLowerInterface::Initialize()
{
	// Safely assume length of pid_t is no greater than FSP_MAX_KEY_SIZE
	u32 key32[FSP_MAX_KEY_SIZE / sizeof(u32)];
	*(pid_t *)keyInternalRand = getpid();
	rand_w32(key32, FSP_MAX_KEY_SIZE / sizeof(u32));
	memcpy(keyInternalRand, key32, FSP_MAX_KEY_SIZE);

	memset(& nearInfo, 0, sizeof(nearInfo));

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

	if(! LearnAddresses())
		return false;
	MakeALFIDsPool();

	mesgInfo.msg_name =  (struct sockaddr *) & addrFrom;
	mesgInfo.msg_namelen = sizeof(addrFrom);
	mesgInfo.msg_control = (void *) & nearInfo;
	mesgInfo.msg_controllen = sizeof(nearInfo);
	iovec[0].iov_base = (void*)&pktBuf->fidPair;
	iovec[0].iov_len = sizeof(ALFIDPair);
	mesgInfo.msg_iov = iovec;
	mesgInfo.msg_iovlen = 2;

	// only after the required fields initialized may the listener thread started
	// fetch message from remote endpoint and deliver them to upper layer application
	if(pthread_create(&thReceiver, NULL, ProcessRemotePacket, this) != 0)
	{
		perror("Cannot create the thread to handle incoming packet");
		return false;
	}

	return true;
}



// The body of the class destructor
void CLowerInterface::Destroy()
{
	pthread_cancel(thReceiver);

	// close all of the listening socket
	for(register int i = 0; i < countInterfaces; i++)
	{
		close(sdSet[i]);
	}

	// close the unbound socket for sending
	close(sdSend);
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



// this implementation is for user-mode FSP over UDP/IPv4
int LOCALAPI CLowerInterface::EnumEffectiveAddresses(uint64_t *prefixes)
{
	memset(prefixes, 0, sizeof(TSubnets));
	return 0;
}



// Given
//	int		The UDP socket to set options
// Return
//	0 if no error
//	negative, as the error number
inline int CLowerInterface::SetInterfaceOptions(int sd)
{
	int enablePktInfo = 1;
	return setsockopt(sd, IPPROTO_IP, IP_PKTINFO, & enablePktInfo, sizeof(enablePktInfo));
}



// Given
//	PSOCKADDR_IN
//	int			the position that the address is provisioned
// Return
//	0 if no error
//	negative, as the error number
int CLowerInterface::BindSendRecv(const SOCKADDR_IN *pAddrListen, int k)
{
	if (::bind(sdSend, (const struct sockaddr *)pAddrListen, sizeof(SOCKADDR_IN)) != 0)
	{
		perror("Cannot bind to the selected address");
		return -1;
	}
	if (SetInterfaceOptions(sdSend) != 0)
	{
		perror("Cannot set socket option to fetch the source IP address");
		return -1;
	}

	memcpy(&addresses[k], pAddrListen, sizeof(SOCKADDR_IN));
	interfaces[k] = 0;
	sdSet[k] = sdSend;
	return 0;
}



// learn all configured IPv4 address (for FSP over UDP)
inline bool CLowerInterface::LearnAddresses()
{
    char strAddr[INET6_ADDRSTRLEN];
    struct ifaddrs *ifap;
    int r = getifaddrs(& ifap);
    if(r != 0)
    {
        perror("Cannot get the interface/address list");
        return false;
    }

	register PSOCKADDR_IN p;
	countInterfaces = 0;
	memset(sdSet, 0, sizeof(sdSet));
    for(register struct ifaddrs *pIf = ifap; pIf != NULL; pIf = pIf->ifa_next)
    {
		p = (PSOCKADDR_IN)pIf->ifa_addr;
        if (p->sin_family != AF_INET)   // define PF_PACKET	17
        {
			printf("Address family %d not cared for %s\n", p->sin_family, pIf->ifa_name);
			continue;
        }
		else if(p->sin_addr.s_addr == 0)
		{
			printf("What? IN_ARPA_ANY address is retrieved? Interface: %s\n", pIf->ifa_name);
			continue;
		}
		else if(!(pIf->ifa_flags & IFF_UP))
		{
			printf("%s not up.\n", pIf->ifa_name);
			continue;
		}
		p->sin_port = DEFAULT_FSP_UDPPORT;
		printf("%s bind to listen at UDP socket address: %s:%d\n..."
			, pIf->ifa_name
            , inet_ntop(AF_INET, &p->sin_addr, strAddr, sizeof(SOCKADDR_IN) )
			, be16toh(p->sin_port));
		if(BindSendRecv(p, countInterfaces) != 0)
			continue;
		// In cygwin many unexpected interfaces are enumerated...
		// {
		// 	close(sdSend);
		//	freeifaddrs(ifap);
		// 	return false;
		// }
		printf("done\n");

		sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sdSend == INVALID_SOCKET)
		{
			perror("Create socket: run out of handle space?!");
		    freeifaddrs(ifap);
			return false;
		}

		// -1: reserve loopback address as the last resort
		if (++countInterfaces >= SD_SETSIZE - 1)
			break;
    }

	// // Set the loopback address as the last resort of receiving
	// SOCKADDR_IN loopback;
	// p = &loopback;
	// p->sin_family = AF_INET;
	// p->sin_port = DEFAULT_FSP_UDPPORT;
	// *(uint64_t *)p->sin_zero = 0;
	// // (binding removed when migrating to linux because loopback interface is already enumerated)

	// // Set the INADDR_ANY for transmission; reuse storage of loopback address
	// p->sin_addr.s_addr = INADDR_ANY;
	sdSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sdSend == INVALID_SOCKET)
	{
		perror("Create socket: run out of handle space?!");
	    freeifaddrs(ifap);
		return false;
	}
	
	// if (::bind(sdSend, (const struct sockaddr *)p, sizeof(SOCKADDR_IN)) != 0)
	// {
	// 	perror("Cannot prevent the socket from specific address binding");
	//     freeifaddrs(ifap);
	// 	return false;
	// }

    freeifaddrs(ifap);
	return true;
}



// retrieve message from remote end point
// it's a thread entry
void * CLowerInterface::ProcessRemotePacket(void *pInstance)
{
	try
	{
		((CLowerInterface *)pInstance)->ProcessRemotePacket();
	}
	catch(...)
	{
		printf("PANIC!");
		return NULL;
	}
	return pInstance;
}



// the real top-level handler to accept and process the remote packets
inline void CLowerInterface::ProcessRemotePacket()
{
	struct pollfd readFDs[SD_SETSIZE];
	register int i;
	int r;

	if(countInterfaces <= 0)
		throw EDOM;
	//
	do
	{
		// there's some bug in select (limit of file decriptor value)
		memset(readFDs, 0, sizeof(readFDs));
		for(i = 0; i < countInterfaces; i++)
		{
			readFDs[i].fd = sdSet[i];
			readFDs[i].events = POLLIN;
			readFDs[i].revents = 0;
		}
		// It is documented that select returns total number of sockets that are ready, however, if one socket is closed
		// 'select' success while following WSARecvMsg will fail
		// Cannot receive packet information, error code = 10038
		// Error: An operation was attempted on something that is not a socket.
		// a more sophisticated implementation should be asynchronous on reading/receiving
		// poll() conforms to POSIX.1-2001 and POSIX.1-2008.
		r = poll(readFDs, countInterfaces, -1);
		if(r == -1)
		{
			int	err = errno;
			if(err == ENETDOWN)			// 100
			{
				Sleep(TIMER_SLICE_ms * 20);	// wait for the network service up again
				continue;
			}
			else if (err == ENOTSOCK)	// 88
			// One of the descriptor sets contains an entry that is not a socket. deliberately close a socket
			{
				Sleep(TIMER_SLICE_ms);
				continue;
			}
			// printf("Error number: %d, ", err);
			perror("Select failure");
			break;	// TODO: crash recovery from select
		}
		//
		for(i = 0; i < countInterfaces; i++)
		{
			iovec[1].iov_base = (void*)&pktBuf->hdr;
			iovec[1].iov_len = MAX_BLOCK_SIZE + sizeof(FSP_NormalPacketHeader);
			mesgInfo.msg_flags = 0;
			r = 0;
			if(readFDs[i].revents != 0)
			{
#if defined(TRACE) && (TRACE & TRACE_PACKET)
				printf_s("\nTo process packet on socket #%X:\n", (unsigned)readFDs[i].fd);
#endif				
				countRecv = recvmsg(readFDs[i].fd, &mesgInfo, 0);
				if (countRecv < 0)
				{
					perror("Cannot recvmsg");
					continue;
				}
				SOCKADDR_ALFID(mesgInfo.msg_name) = pktBuf->fidPair.source;	// For FSP over UDP/IPv4
				r = ProcessReceived();
#if defined(TRACE) && (TRACE & TRACE_PACKET)
				printf_s("\nPacket on socket #%X: processed, result = %d\n", (unsigned)readFDs[i].fd, r);
#endif
			}
		}
	} while(1, 1);
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
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("\nSend back to peer socket address:\n");
	DumpNetworkUInt16((uint16_t *)& addrFrom, sizeof(SOCKADDR_IN6) / 2);
#endif
	pktBuf->fidPair.peer = _InterlockedExchange((u32*)&pktBuf->fidPair.source, pktBuf->fidPair.peer);
	iovec[1].iov_base = buf;
	iovec[1].iov_len = len;
	int n = (int)sendmsg(sdSend, &mesgInfo, 0);
	if (n < 0)
	{
		perror("CLowerInterface::SendBack");
		return 0;
	}
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf("%s, line %d, %d bytes sent back.\n", __FILE__, __LINE__, n);
	printf_s("  Send from msghdr:\n\t");
	DumpNetworkUInt16((uint16_t *)& nearInfo, sizeof(nearInfo) / 2);
	printf_s("  Send back to (namelen = %d):\n\t", mesgInfo.msg_namelen);
	DumpNetworkUInt16((uint16_t *)& addrFrom, mesgInfo.msg_namelen / 2);
#endif
	return n;
}



// Return the number of microseconds elapsed since Jan 1, 1970 UTC (Unix epoch)
// Let the link-time-optimizer embed the code in the caller block
extern "C" timestamp_t NowUTC()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec);
}



// Given
//	u32 *	pointer to the buffer to store the random 32-bit word
//	int		number of 32-bit words to generate
// Do
//	Generate (pseudo) random number of designated length and store it in the buffer given
extern "C" void rand_w32(u32 *p, int n)
{
	static uint64_t nonce;
	struct
	{
		struct timeval tv;
		uint64_t nonce;
	} _rm;	// random material
	_rm.nonce = _InterlockedIncrement(&nonce);
	gettimeofday(&_rm.tv, NULL);
	blake2b(p, n * sizeof(u32), keyInternalRand, sizeof(keyInternalRand), &_rm, sizeof(_rm));
}



// Return
//	Whether the ULA process associated with the LLS socket is still alive
// Remark
//	It is assumed that process ID is 'almost never' reused
bool CSocketItemEx::IsProcessAlive()
{
	const int START_POSITON = 6;
	char procName[] = "/proc/000000000";
	// implement itoa locally
	uint32_t r = (uint32_t)idSrcProcess;
	register int i = START_POSITON + 8;
	while(i >= START_POSITON)
	{
		procName[i] = '0' + (char)(r % 10);
		r = r / 10;
		i--;
		if(r == 0)
			break;
	}
	if(i >= START_POSITON)
		memmove(procName + START_POSITON, procName + i + 1, START_POSITON + 9 - i);	// include the terminating '\0'
	int fd = open(procName, O_RDONLY);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}


// Given
//	uint32_t		number of millisecond delayed to trigger the timer
// Return
//	true if the timer was set, false if it failed.
bool LOCALAPI CSocketItemEx::ReplaceTimer(uint32_t period)
{
    struct itimerspec its;
	if (timer == 0)
	{
	    struct sigevent sigev;
		pthread_attr_t tattr;
		pthread_attr_init(&tattr);
		sigev.sigev_notify = SIGEV_THREAD;
		sigev.sigev_value.sival_ptr = this;
		sigev.sigev_notify_function = KeepAlive;
		sigev.sigev_notify_attributes = &tattr;
		int k = timer_create(CLOCK_MONOTONIC, &sigev, &timer);
		pthread_attr_destroy(&tattr);
		if (k == -1)
			return false;
	}

    its.it_value.tv_sec = period / 1000;
    its.it_value.tv_nsec = period % 1000 * 1000000;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;
    //^ periodic timer

    if (timer_settime(timer, 0, &its, NULL) == 0)
		return true;

	timer_delete(timer);
	timer = 0;
	return false;
}



// Assume a mutex has been obtained
void CSocketItemEx::RemoveTimers()
{
	timer_t h;
	if((h = (timer_t)_InterlockedExchange(& timer, 0)) != 0)
		timer_delete(h);
}



// For ScheduleConnect
static void * HandleConnect(void *p)
{
	try
	{
		((CommandNewSessionSrv *)p)->DoConnect();
		return p;
	}
	catch (...)
	{
		return NULL;
	}
}



// The OS-dependent implementation of scheduling connection-request queue
void CSocketItemEx::ScheduleConnect(int i)
{
	CommandNewSessionSrv &cmd = ConnectRequestQueue::requests[i];
	cmd.pSocket = this;
	cmd.index = i;
	// TODO: but if it failed?
	int r = pthread_create(&cmd.idThread, NULL, &HandleConnect, this);
    if (r != 0)
#ifndef NDEBUG
		perror("Cannot initialize the thread attribute to set")
#endif
		;
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
	printf("MapControlBlock called, source process id = %d, size of the shared memory = 0x%X\n"
		, cmd.idProcess, cmd.dwMemorySize);
#endif
	if(pControlBlock != NULL)
	{
		perror("The target controlblock should be zeroed when MapControlBlock");
		// TODO: report error to the caller?
		return false;
	}

	if (cmd.hShm < 0)
	{
		printf("Cannot open the shared memory allocated by ULA");
		return false;
	}

	dwMemorySize = cmd.dwMemorySize;
	pControlBlock = (ControlBlock *)mmap(NULL, dwMemorySize,  PROT_READ | PROT_WRITE, MAP_SHARED, cmd.hShm, 0);
	if (pControlBlock == NULL)
	{
		perror("Cannot map the shared memeroy into address space of the service process");
		close(cmd.hShm);
		return false;
	}

#if (TRACE & TRACE_ULACALL)
	printf_s("Successfully take use of the shared memory object.\r\n");
#endif
	close(cmd.hShm);
	mlock(pControlBlock, dwMemorySize);

	idSrcProcess = cmd.idProcess;
	return true;
}



// See also CSocketItem::Destroy();
void CSocketItemEx::ClearInUse()
{
	register void *buf;
	if ((buf =  _InterlockedExchangePointer((PVOID *)& pControlBlock, NULL)) != NULL)
	{
		munlock(pControlBlock,dwMemorySize);
		munmap(buf, dwMemorySize);
	}
}




// UNRESOLVED! TODO: enforce rate-limit (and rate-limit based congestion avoidance/control)
// TODO: UNRESOLVED! is it multi-home aware?
// Given
//	ULONG	number of WSABUF descriptor to gathered in sending
//	ScatteredSendBuffers
// Return
//	number of bytes sent, or 0 if error
int CSocketItemEx::SendPacket(register u32 n1, ScatteredSendBuffers s)
{
	struct msghdr msg;

	s.scattered[0].iov_base = & fidPair;
	s.scattered[0].iov_len = sizeof(fidPair);

	// This implementation is for FSP over UDP/IPv4 only, where it needn't to select path
	CtrlMsgHdr & nearInfo = CLowerInterface::Singleton.nearInfo;
	msg.msg_control = & nearInfo;
	msg.msg_controllen = sizeof(nearInfo);
	msg.msg_iov = & s.scattered[0];
	msg.msg_iovlen = n1 + 1;
	msg.msg_name = sockAddrTo;
	msg.msg_namelen = sizeof(sockAddrTo->Ipv4);

#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
	printf_s("\nPeer socket address:\n");
	DumpNetworkUInt16((uint16_t *)sockAddrTo, sizeof(SOCKADDR_IN6) / 2);
#endif
	timestamp_t t = NowUTC();
	int n = (int)sendmsg(CLowerInterface::Singleton.sdSend, &msg, 0);
	if (n < 0)
	{
		perror("CSocketItemEx::SendPacket");
		return 0;
	}
	tRecentSend = t;
#if defined(TRACE) && (TRACE & TRACE_PACKET)
	printf_s("\n#%u(Near end's ALFID): %d bytes sent.\n", fidPair.source, n);
#endif
	return n;
}
