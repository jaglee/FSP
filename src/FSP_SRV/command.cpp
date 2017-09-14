/*
 * FSP lower-layer service program, handle command given by the upper layer application
 * This module meant to be platform-independent part while platform-dependent part
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


/**
 * Detail implementation of connect request queue is OS-specific
 */
static ConnectRequestQueue connectRequests;



// Register a passive FSP socket
// Given
//	CommandNewSessionSrv&	the command context given by ULA
// Do
//	Register a listening FSP socket at the specific applicatio layer fiberID
// Remark
//	If the command context memory block cannot be mapped into the LLS's memory space the function fails
//	The notice queue of the command context is prefilled with the FSP_IPC_CannotReturn notice
//	If 'Listen' succeeds the notice will be replaced by FSP_NotifyListening
//	or else LLS triggers the upper layer DLL to handle the prefilled notice
void LOCALAPI Listen(CommandNewSessionSrv &cmd)
{
	if(cmd.hEvent == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}

	CSocketItemEx *socketItem = CLowerInterface::Singleton.AllocItem(cmd.fiberID);
	if(socketItem == NULL)
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
	::SetEvent(cmd.hEvent);
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
//	The notice queue of the command context is prefilled with an FSP_IPC_CannotReturn notice
//	If the function succeeds the notice will be replaced by FSP_NotifyListening
//	or else LLS triggers the upper layer DLL to handle the prefilled notice
void LOCALAPI Connect(CommandNewSessionSrv &cmd)
{
	if(cmd.hEvent == NULL)
		return;		// Do not trace, in case logging is overwhelmed

	if ((cmd.index = connectRequests.Push(&cmd)) < 0)
		goto l_bailout1;

	CSocketItemEx *socketItem = CLowerInterface::Singleton.AllocItem();
	if (socketItem == NULL)
		goto l_bailout2;

	if (!socketItem->MapControlBlock(cmd))
		goto l_bailout3;

	socketItem->ScheduleConnect(&cmd);
	return;

l_bailout3:
	CLowerInterface::Singleton.FreeItem(socketItem);
l_bailout2:
	connectRequests.Remove(cmd.index);
l_bailout1:
	::SetEvent(cmd.hEvent);
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
void LOCALAPI Accept(CommandNewSessionSrv &cmd)
{
	if(cmd.hEvent == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}

	CSocketItemEx *socketItem = CLowerInterface::Singleton.AllocItem(cmd);
	if(socketItem == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot map control block of the client into server's memory space");
		::SetEvent(cmd.hEvent);
		return;
	}

	socketItem->Accept();
	// Only on exception would it signal event to DLL
}


// Given
//	CommandCloneSessionSrv&		The connection multiplication command
// Do
//	Clone the root connection
void Multiply(CommandCloneSessionSrv &cmd)
{
	if (cmd.hEvent == NULL)
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}

	CSocketItemEx *srcItem = CLowerInterface::Singleton[cmd.fiberID];
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

	CSocketItemEx *newItem = CLowerInterface::Singleton.AllocItem();
	if (newItem == NULL || !newItem->MapControlBlock(cmd))
	{
		srcItem->SetMutexFree();
		if(newItem == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot allocate new socket slot");
		}
		else
		{
			REPORT_ERRMSG_ON_TRACE("Cannot map control block of the client into server's memory space");
			CLowerInterface::Singleton.FreeItem(newItem);
		}
		::SetEvent(cmd.hEvent);
		return;
	}

	newItem->shouldAppendCommit = cmd.isFlushing;
	newItem->InitiateMultiply(srcItem);
l_return:
	// Only on exception would it signal event to DLL
	srcItem->SetMutexFree();
}



// Given
//	CommandToLLS		The service command requested by ULA
// Do
//	Excute ULA's request
// TODO: add it to the task queue to avoid head congestion
void CSocketItemEx::ProcessCommand(CommandToLLS *pCmd)
{
	if (!WaitUseMutex())
	{
#ifdef TRACE
		printf_s("ProcessCommand of socket %p: possible dead-lock, inUse = %d\n", this, inUse);
#endif
		return;
	}

	if(lowState <= 0 || lowState > LARGEST_FSP_STATE)
	{
#ifdef TRACE
		printf_s("Socket(%p) is not in working state, inUse = %d, %s[%d]\n", this, inUse, stateNames[lowState], lowState);
#endif
		SetMutexFree();
		return;
	}
	//
	switch(pCmd->opCode)
	{
	case FSP_Reject:
		RejectOrReset();
		break;
	case FSP_Recycle:
		Recycle();
		break;
	case FSP_Start:
		Start();
		break;
	case FSP_Send:			// send a packet/group of packets
		ScheduleEmitQ();
		break;
	case FSP_Commit:
		UrgeCommit();
		break;
	case FSP_Shutdown:
		SendRelease();
		break;
	case FSP_InstallKey:
		InstallSessionKey((CommandInstallKey &)*pCmd);
		break;
	case FSP_AdRecvWindow:
		if (InState(PEER_COMMIT) || InState(COMMITTING2) || InState(CLOSABLE))
			SendAckFlush();
		else if (InState(ESTABLISHED) || InState(COMMITTING) || InState(COMMITTED))
			SendKeepAlive();
#ifndef NDEUBG
		else
			printf_s("Implementation error: maynot advertise receive window size in state %s(%d)\n", stateNames[lowState], lowState);
#endif
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
#ifdef TRACE
	printf_s("Try to make connection to %s (@local fiber#%u(_%X_)\n", PeerName(), fidPair.source, be32toh(fidPair.source));
#endif
	char nodeName[INET6_ADDRSTRLEN];
	char *peerName = PeerName();
	int r = ResolveToIPv6(peerName);
	if (r <= 0)
	{
		const char *serviceName = strchr(peerName, ':');
		if(serviceName != NULL)
		{
			serviceName++;
			strncpy_s(nodeName, INET6_ADDRSTRLEN - 1, peerName, serviceName - peerName - 1);
			nodeName[serviceName - peerName - 1] = 0;
			peerName = nodeName;
		}
		r = ResolveToFSPoverIPv4(peerName, serviceName);
		if(r <=  0)
		{
			Notify(FSP_NotifyNameResolutionFailed);
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



// Start sending queued packet(s) in the session control block
// Remark
//	Operation code in the given command context would be cleared if send is pending
// See also
//	DLL::FinalizeSend, DLL::ToConcludeConnect
void CSocketItemEx::Start()
{
#ifdef TRACE
	printf_s("To send first packet %s\n\tin %s[%d] => %s[%d] state\n\tfirstSN = %u, nextSN = %u\n"
		, opCodeStrings[(pControlBlock->HeadSend() + pControlBlock->sendWindowHeadPos)->opCode]
		, stateNames[lowState], lowState
		, stateNames[pControlBlock->state], pControlBlock->state
		, pControlBlock->sendWindowFirstSN
		, pControlBlock->sendWindowNextSN);
#endif
	SyncState();
	EmitStart();
	pControlBlock->SetFirstSendWindowRightEdge();
	//
	AddResendTimer(tRoundTrip_us >> 8);
	// While the KEEP_ALIVE_TIMEOUT was set already in OnConnectRequestAck
}



// Mean to urge sending of the End of Transaction flag
void CSocketItemEx::UrgeCommit()
{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
	printf_s("%s called, LLS state: %s(%d), ULA state: %s(%d)\n"
		, __FUNCDNAME__
		, stateNames[lowState], lowState
		, stateNames[pControlBlock->state], pControlBlock->state);
#endif
	// synchronize the state in the 'cache' and the real state
	if (_InterlockedExchange8((char *)& lowState, pControlBlock->state) != pControlBlock->state)
	{
		if (lowState == COMMITTING || lowState == COMMITTING2)
			RestartKeepAlive();
	}
	//
	int r = pControlBlock->MarkSendQueueEOT();
	if (r <= 0)
	{
		shouldAppendCommit = 1;
		SendKeepAlive();
	}
	// See also EmitQ, DoResend
	if (resendTimer == NULL)
		AddResendTimer(tRoundTrip_us >> 8);
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
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		DWORD err = WSAGetLastError();
		char buffer[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR) & buffer, 1024, NULL);
		printf_s("Cannot Resolve the IPv4 address of the node %s, error code = %d\n %s\n", nodeName, err, (LPTSTR) buffer);
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
		prefixes[n].ipv4 = ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_addr.S_un.S_addr;
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
#if defined(TRACE) && (TRACE & TRACE_ADDRESS)
		DWORD err = WSAGetLastError();
		char buffer[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR) & buffer, 1024, NULL);
		printf("Cannot Resolve the IPv6 address of the node %s, error code = %d\n %s\n", nodeName, err, (LPTSTR) buffer);
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
		prefixes[n] = *(uint64_t *)(((PSOCKADDR_IN6)pAddrInfo->ai_addr)->sin6_addr.u.Byte);
	} while(++n < MAX_PHY_INTERFACES && (pAddrInfo = pAddrInfo->ai_next) != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}



// a helper function which is self-describing
void CommandNewSessionSrv::DoConnect()
{
	pSocket->Connect();
	connectRequests.Remove(index);
}