/*
 * FSP lower-layer service program, handle command given by the upper layer application
 * This module meant to be platform-independent part
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

#ifdef _MSC_VER
# pragma warning(disable:4996)	//#define _CRT_SECURE_NO_WARNINGS
#endif


// Register a passive FSP socket
// Given
//	CommandNewSessionSrv&	the command context given by ULA
// Do
//	Register a listening FSP socket at the specific application layer fiberID
// Remark
//	If the command context memory block cannot be mapped into the LLS's memory space the function fails
//	The notice queue of the command context is preset to FSP_IPC_CannotReturn
//	If 'Listen' succeeds the notice will be replaced by FSP_NotifyListening
//	or else LLS triggers the upper layer DLL to handle the preset notice
void LOCALAPI Listen(const CommandNewSessionSrv& cmd)
{
	CSocketItemEx* socketItem = CLowerInterface::Singleton.AllocItem(cmd.fiberID);
	if (socketItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Multiple call to listen on the same local fiber ID?");
		goto l_bailout1;
	}

	if (!socketItem->MapControlBlock(cmd))
	{
		REPORT_ERRMSG_ON_TRACE("Fatal situation when to share memory with DLL");
		goto l_bailout2;
	}

	socketItem->Listen();
	return;

l_bailout2:
	CLowerInterface::Singleton.FreeItem(socketItem);
l_bailout1:
	cmd.TriggerULA();
	return;
}



// Register an initiative FSP socket
// Given
//	CommandNewSessionSrv&	the command context given by ULA
// Do
//	Map the command context and put the connect request into the queue
//	LLS try to make the connection request to the remote end in the queued thread
// Remark
//	If the command context memory block cannot be mapped into LLS's memory space the function fails
//	The notice queue of the command context is preset to FSP_IPC_CannotReturn
//	If the function succeeds the notice will be replaced by FSP_NotifyListening
//	or else LLS triggers the upper layer DLL to handle the preset notice
void LOCALAPI Connect(const CommandNewSessionSrv& cmd)
{
	CSocketItemEx* socketItem;

	int index = ConnectRequestQueue::requests.Push(&cmd);
	if (index < 0)
		goto l_bailout1;

	socketItem = CLowerInterface::Singleton.AllocItem();
	if (socketItem == NULL)
		goto l_bailout2;

	if (!socketItem->MapControlBlock(cmd))
		goto l_bailout3;

	socketItem->ScheduleConnect(index);
	return;

l_bailout3:
	CLowerInterface::Singleton.FreeItem(socketItem);
l_bailout2:
	ConnectRequestQueue::requests.Remove(index);
l_bailout1:
	cmd.TriggerULA();
}



// Given
//	CommandNewSessionSrv&	the synchronization command context
// Do
//	Map the control block into process space of LLS and go on to emit the head packet of the send queue
//	Register an incarnated FSP socket
// Remark
//	By lookup the SCB item according to the give fiber ID in the command context, the rare but possible
//	collision of the near-end ALFID would be filtered out firstly
//	An FSP socket is incarnated when a listening socket is forked on CONNECT_REQUEST,
//	or a connection is cloned on MULTIPLY received
void LOCALAPI Accept(const CommandNewSessionSrv &cmd)
{
	CSocketItemEx *socketItem = CLowerInterface::Singleton.AllocItem(cmd);
	if(socketItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot map control block of the client into server's memory space");
		cmd.TriggerULA();
		return;
	}

	socketItem->Accept();
	// Only on exception would it signal event to DLL
}


// Given
//	CommandCloneSessionSrv&		The connection multiplication command
// Do
//	Clone the root connection
void Multiply(const CommandCloneSessionSrv &cmd)
{
	CSocketItemEx *srcItem = CLowerInterface::Singleton[cmd.fiberID];
	CSocketItemEx* newItem;
	if(srcItem == NULL)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Cloned connection not found");
		return;
	}

	if(! srcItem->WaitUseMutex())
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("Cloned connect busy");
		return;
	}

	// To make life easier we do not allow clone FSP session across process border
	if(cmd.idProcess != srcItem->idSrcProcess)
	{
#ifdef TRACE
		printf_s("\nCannot clone other user's session, source fiber#%u\n"
				 "\tsource process id = %u, this process id = %u\n"
				 , cmd.fiberID, srcItem->idSrcProcess, cmd.idProcess);
#endif
		goto l_return;
	}

	newItem = CLowerInterface::Singleton.AllocItem();
	if (newItem == NULL || !newItem->MapControlBlock(cmd))
	{
		if(newItem == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot");
		}
		else
		{
			REPORT_ERRMSG_ON_TRACE("Cannot map control block of the client into server's memory space");
			CLowerInterface::Singleton.FreeItem(newItem);
		}
		cmd.TriggerULA();
		goto l_return;
	}

	newItem->transactional = newItem->pControlBlock->GetSendQueueHead()->GetFlag<TransactionEnded>();
	//^See also @DLL::SetHeadPacketIfEmpty
	newItem->InitiateMultiply(srcItem);
l_return:
	// Only on exception would it signal event to DLL
	srcItem->SetMutexFree();
}



// Get upper layer application's commands and process them
// Given
//	_In_ buffer		buffer of the command received from ULA
// Return
//	Nothing
// TODO: UNRESOLVED!there should be performance profiling variables to record how many commands have been processed?
void LOCALAPI ProcessCommand(void *buffer)
{
    static int n = 0;

	CommandToLLS *pCmd = (CommandToLLS *)buffer;
	CSocketItemEx *pSocket;
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
	printf_s("\n#%d command"
		", fiber#%u(_%X_)"
		", %s(code = %d)\n"
		, n
		, pCmd->fiberID, be32toh(pCmd->fiberID)
		, noticeNames[pCmd->opCode], pCmd->opCode);
#endif
	switch(pCmd->opCode)
	{
	case FSP_Listen:		// register a passive socket
		Listen(CommandNewSessionSrv(pCmd));
		break;
	case InitConnection:	// register an initiative socket
		Connect(CommandNewSessionSrv(pCmd));
		break;
	case FSP_Accept:
		Accept(CommandNewSessionSrv(pCmd));
		break;
	case FSP_Multiply:
		Multiply(CommandCloneSessionSrv(pCmd));
		break;
	default:
		pSocket = (CSocketItemEx *)CLowerInterface::Singleton[pCmd->fiberID];
		if(pSocket == NULL)
		{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
			printf_s("Erratic! %s called for invalid local fiber#%u(_%X_)\n"
				, opCodeStrings[pCmd->opCode]
				, pCmd->fiberID, be32toh(pCmd->fiberID));
#endif
			break;
		}
		pSocket->ProcessCommand(pCmd);
	}
	//
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
	printf_s("#%d command processed, operation code = %d\n\n.",  n, pCmd->opCode);
#endif
	n++;
}



// Given
//	CommandToLLS		The service command requested by ULA
// Do
//	Execute ULA's request
void CSocketItemEx::ProcessCommand(CommandToLLS *pCmd)
{
	if (!WaitUseMutex())
	{
		printf_s("Socket %p[fiber#%u] in state %s: process command %s[%d]\n"
			"probably encountered dead-lock: pSCB: %p\n"
			, this, fidPair.source, stateNames[lowState], noticeNames[pCmd->opCode], pCmd->opCode
			, pControlBlock);
		if(lockedAt != NULL)
			printf_s("Lastly called by %s\n", lockedAt);
		return;
	}
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
	printf_s("%s called (%s), LLS state: %s(%d) <== ULA state: %s(%d)\n", __FUNCTION__
		, noticeNames[pCmd->opCode]
		, stateNames[lowState], lowState
		, stateNames[pControlBlock->state], pControlBlock->state);
#endif

	switch(pCmd->opCode)
	{
	case FSP_Start:
		RestartKeepAlive();	// If it happened to be stopped
		DoEventLoop();
		break;
	case FSP_Reject:		// FSP_Reset as well
		RejectOrReset(((CommandRejectRequest *)pCmd)->reasonCode);
		break;
	case FSP_InstallKey:
		InstallSessionKey((CommandInstallKey &)*pCmd);
		break;
	default:
#ifndef NDEUBG
		printf("Internal error: undefined upper layer application command code %d\n", pCmd->opCode);
#endif
		break;
	}
	//
	SetMutexFree();
}



// Do
//	Bind to the interface as soon as the control block mapped into server's memory space
void CSocketItemEx::Listen()
{
	InitAssociation();
	lowState = LISTENING;
	SignalFirstEvent(FSP_NotifyListening);
}



// Do
//	Make initiative connect context and initiate session establishment
void CSocketItemEx::Connect()
{
#if (TRACE & TRACE_ULACALL)
	printf_s("Try to make connection to %s (@local fiber#%u(_%X_)\n", PeerName(), fidPair.source, be32toh(fidPair.source));
#endif
	char nodeName[INET6_ADDRSTRLEN];
	char *peerName = PeerName();
	int r = ResolveToIPv6(peerName);
	if (r <= 0)
	{
		const char *serviceName = strchr(peerName, ':');
		if (serviceName != NULL)
		{
			size_t n = serviceName - peerName;
			n = n < INET6_ADDRSTRLEN ? n : INET6_ADDRSTRLEN - 1;
			strncpy(nodeName, peerName, n);
			nodeName[n] = 0;
			peerName = nodeName;
			serviceName++;
		}
		r = ResolveToFSPoverIPv4(peerName, serviceName);
		if (r <= 0)
		{
			Notify(FSP_NameResolutionFailed);
			Destroy();
			return;
		}
	}
	pControlBlock->connectParams.idRemote = pControlBlock->peerAddr.ipFSP.fiberID;	// Exploited in OnInitConnectAck 

	// By default Connect() prefer initiatiating connection from an IPv6 interface
	// but if the peer is of FSP over UDP/IPv4 address it must be changed
	// See also {FSP_DLL}CSocketItemDl::CreateControlBlock()
	if (((PFSP_IN4_ADDR_PREFIX)pControlBlock->peerAddr.ipFSP.allowedPrefixes)->prefix == PREFIX_FSP_IP6to4)
	{
		int	ifDefault = pControlBlock->nearEndInfo.ipi6_ifindex;
		pControlBlock->nearEndInfo.InitUDPoverIPv4(ifDefault);
	}
	// See also FSP_DLL$$CSocketItemDl::ToConcludeConnect
	pControlBlock->nearEndInfo.idALF = fidPair.source;
	//^For compatibility with passive peer behavior, InitAssociation() does not prepare nearEndInfo

	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();
	InitiateConnect();
	// Only after ACK_CONNECT_REQ received may it 'SignalReturned();'
}



// Send RESET to the remote peer to reject some request in pre-active state.
// The RESET packet is not guaranteed to be received.
// See also DisposeOnReset
void CSocketItemEx::RejectOrReset(uint32_t reasonCode)
{
	if (lowState >= ESTABLISHED)
		SendReset();
	else if (!IsPassive())
		CLowerInterface::Singleton.SendPrematureReset(reasonCode, this);
	SignalFirstEvent(FSP_NotifyRecycled);
	Destroy();	// MUST signal event before Destroy
}



// Given
//	PCTSTR			the name of the node to be resolved, which might be an IPv4 string representation
//	PCTSTR			the name of the service to be resolved, which might be a string of decimal port number
// Do
//	Resolve the UDP socket addresses of the given remote peer and store them in the peerAddr field of SCB
// Return
//	Number of addresses resolved, negative if error
int CSocketItemEx::ResolveToFSPoverIPv4(const char *nodeName, const char *serviceName)
{
	static const struct addrinfo hints = { 0, AF_INET, };
	PADDRINFOA pAddrInfo;

	// assume the project is compiled in ANSI/MBCS language mode
	if(getaddrinfo(nodeName, serviceName, & hints, & pAddrInfo) != 0)
	{
#if !defined(NDEBUG) &&  defined(__WINDOWS__)
		TraceLastError(__FILE__, __LINE__, __FUNCTION__, nodeName);
#elif !defined(NDEBUG) && (defined(__linux__) || defined(__CYGWIN__))
		perror("nodeName");
#endif
		return -1;
	}

	if(pAddrInfo == NULL)
	{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf("Cannot resolve the IP address of the node %s\n", nodeName);
#endif
		return 0;
	}

	// See also CLowerInterface::EnumEffectiveAddresses
	register PFSP_IN4_ADDR_PREFIX prefixes = (PFSP_IN4_ADDR_PREFIX)pControlBlock->peerAddr.ipFSP.allowedPrefixes;
	int n = 0;
	pControlBlock->peerAddr.ipFSP.hostID = 0;
	pControlBlock->peerAddr.ipFSP.fiberID = PORT2ALFID( ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_port );
	do
	{
		// Must keep in consistent with TranslateFSPoverIPv4
		prefixes[n].prefix = PREFIX_FSP_IP6to4;
		prefixes[n].port = DEFAULT_FSP_UDPPORT;
		prefixes[n].ipv4 = *(u32*) & ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_addr;
	} while(++n < MAX_PHY_INTERFACES && (pAddrInfo = pAddrInfo->ai_next) != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}



// Given
//	PCTSTR			the name of the node to be resolved, which might be an IPv6 string representation
// DO
//	Resolve the IPv6 addresses of the given remote peer and store them in the peerAddr field of SCB
// Return
//	Number of addresses resolved, negative if error
int CSocketItemEx::ResolveToIPv6(const char *nodeName)
{
	static const struct addrinfo hints = { 0, AF_INET6, };
	PADDRINFOA pAddrInfo;
	// A value of zero for ai_socktype indicates the caller will accept any socket type. 
	// A value of zero for ai_protocol indicates the caller will accept any protocol. 

	// assume the project is compiled in ANSI/MBCS language mode
	if(getaddrinfo(nodeName, NULL, & hints, & pAddrInfo) != 0)
	{
#if !defined(NDEBUG) &&  defined(__WINDOWS__)
		TraceLastError(__FILE__, __LINE__, __FUNCTION__, nodeName);
#elif !defined(NDEBUG) && (defined(__linux__) || defined(__CYGWIN__))
		perror("nodeName");
#endif
		return -1;
	}

	if(pAddrInfo == NULL)
	{
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		printf("Cannot resolve the IPv6 address of the node %s\n", nodeName);
#endif
		return 0;
	}

	// See also CLowerInterface::EnumEffectiveAddresses
	register uint64_t * prefixes = pControlBlock->peerAddr.ipFSP.allowedPrefixes;
	int n = 0;
	pControlBlock->peerAddr.ipFSP.fiberID = SOCKADDR_ALFID(pAddrInfo->ai_addr);
	pControlBlock->peerAddr.ipFSP.hostID = SOCKADDR_HOSTID(pAddrInfo->ai_addr);
	do
	{
		prefixes[n] = *(uint64_t*) & ((PSOCKADDR_IN6)pAddrInfo->ai_addr)->sin6_addr;
	} while(++n < MAX_PHY_INTERFACES && (pAddrInfo = pAddrInfo->ai_next) != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}



// a helper function which is self-describing
void CommandNewSessionSrv::DoConnect()
{
	pSocket->Connect();
	ConnectRequestQueue::requests.Remove(index);
}


/**
 *	Manipulation of connection request queue
 */

// Given
//	CommandNewSessionSrv		The request for new connection
// Return
//	non-negative is the position of the new request in the queue
//	negative if error
// Remark
//	Make a clone of the connect request information in the queue
//	the caller should set the index of the clone later
//	There is head-of-line block in this implementation,
//	which might be beneficial because it is connection rate throttling
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
