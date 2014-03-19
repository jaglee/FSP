/*
 * FSP lower-layer service program, handle command given by the upper layer application
 * Platform-dependent / IPC-machanism-dependent
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
//	_In_ pCmd point to the command context given by ULA
// Return
//	Nothing
// Remark
//	NON_EXISTENT-->LISTENING
void LOCALAPI Listen(struct CommandNewSession *pCmd)
{
#ifdef TRACE
	printf_s("Requested to listen on local session %d, assigned event trigger is %s\n"
		, pCmd->idSession
		, pCmd->u.szEventName);
#endif
	if(! pCmd->ResolvEvent())
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}

	CSocketItemEx *socketItem = (CLowerInterface::Singleton())->AllocItem(pCmd->idSession);
	if(socketItem == NULL)
	{
		TRACE_HERE("Multiple call to listen on the same local session ID?");
		::SetEvent(pCmd->u.s.hEvent);
		return;
	}

	socketItem->Listen(pCmd);
}



// Register an initiative FSP socket
// Given
//	_In_ pCmd point to the command context given by ULA
// Return
//	Nothing
void LOCALAPI Connect(struct CommandNewSession *pCmd)
{
	if(! pCmd->ResolvEvent())
		return;		// Do not trace, in case logging is overwhelmed

	if( (pCmd->u.s.index = connectRequests.Push(pCmd)) < 0)
l_return:
	{
		::SetEvent(pCmd->u.s.hEvent);
		return;
	}

	CSocketItemEx *socketItem = (CLowerInterface::Singleton())->AllocItem();
	if(socketItem == NULL)
		goto l_return;	// Do not trace, in case logging is overwhelmed

	if(! socketItem->MapControlBlock(*pCmd))
	{
		(CLowerInterface::Singleton())->FreeItem(socketItem);
		goto l_return;	// Do not trace, in case logging is overwhelmed
	}

	socketItem->ScheduleConnect(pCmd);
}


// Register an incarnated FSP socket
// Given
//	CommandNewSession	the synchronization command context
// Do
//	Lookup the SCB item according to the give session ID in the command context, if an existing busy item
//	was found (it is a rare but possible collision) return failure
//	if a free item was found, map the control block into process space of LLS
//	and go on to emit the command and optional data packets in the send queue
void LOCALAPI SyncSession(struct CommandNewSession *pCmd)
{
	if(! pCmd->ResolvEvent())
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}

	CSocketItemEx *socketItem = (*CLowerInterface::Singleton())[*pCmd];
	if(socketItem == NULL)
	{
		TRACE_HERE("Internal panic! Cannot map control block of the client into server's memory space");
		::SetEvent(pCmd->u.s.hEvent);
		return;
	}

	socketItem->SynConnect(pCmd);
}



// Given
//	CommandNewSession
// Do
//	Routine works of registering a passive FSP socket
void LOCALAPI CSocketItemEx::Listen(CommandNewSession *pCmd)
{
	if(! MapControlBlock(*pCmd))
	{
		TRACE_HERE("Fatal situation when to share memory with DLL");
		(CLowerInterface::Singleton())->FreeItem(this);
		::SetEvent(pCmd->u.s.hEvent);
		return;
	}

	// bind to the interface as soon as the control block mapped into server's memory space
	pairSessionID.source = pCmd->idSession;
	InitAssociation();
	//
	SetReturned();
	SignalEvent();
}



// Given
//	CommandNewSession
// Do
//	Routine works of registering a passive FSP socket
void LOCALAPI CSocketItemEx::Connect(CommandNewSession *pCmd)
{
#ifdef TRACE
	printf_s("Try to make connection to %s (@local session #%u)\n", PeerName(), pairSessionID.source);
#endif
	char nodeName[INET6_ADDRSTRLEN];
	char *peerName = PeerName();
	const char *serviceName = strchr(peerName, ':');
	if(serviceName != NULL)
	{
		serviceName++;
		strncpy_s(nodeName, INET6_ADDRSTRLEN - 1, peerName, serviceName - peerName - 1);
		// nodeName would be square-bracketed
		nodeName[serviceName - peerName - 1] = 0;
		peerName = nodeName;
	}

	// in this bootstrap project FSP over UDP/IPv4 takes precedence
	int r = ResolveToFSPoverIPv4(peerName, serviceName);
	if(r <= 0)
	{
		r = ResolveToIPv6(peerName);
		if(r <=  0)
		{
			Notify(FSP_NotifyNameResolutionFailed);
			goto l_return;
		}
	}
	pControlBlock->u.connectParams.idRemote = pControlBlock->peerAddr.ipFSP.sessionID;

	// By default Connect() prefer initiatiating connection from an IPv6 interface
	// but if the peer is of FSP over UDP/IPv4 address it must be changed
	// See also {FSP_DLL}CSocketItemDl::CreateControlBlock()
	if (((PFSP_IN4_ADDR_PREFIX)pControlBlock->peerAddr.ipFSP.allowedPrefixes)->prefix == PREFIX_FSP_IP6to4)
	{
		int	ifDefault = pControlBlock->nearEnd[0].u.ipi6_ifindex;
		for (register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pControlBlock->nearEnd[i].InitUDPoverIPv4(ifDefault);
		}
	}
	// See also FSP_DLL$$CSocketItemDl::ToConcludeConnect
	pControlBlock->nearEnd->u.idALT = pairSessionID.source;
	//^For compatibility with passive peer behavior, InitAssociation() does not prepare nearEnd[0]

	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();
	InitiateConnect();
	SetReturned();
	SignalEvent();

l_return:
	connectRequests.Remove(pCmd->u.s.index);
}



// Send the ACK_ADJOURN command, as the response to in-order ADJOURN
void CSocketItemEx::AckAdjourn()
{
	TRACE_HERE("called");
	// SetState(CLOSABLE);	// Shall be redundant!
	ReplaceTimer(SCAVENGE_THRESHOLD_ms);
	SendPacket<ACK_FLUSH>();
}


// Send the FINISH command, as the last step of shut down connection
void CSocketItemEx::Shutdown()
{
	TRACE_HERE("called");

	ReplaceTimer(SCAVENGE_THRESHOLD_ms);
	SetState(CLOSED);
	SendPacket<FINISH>();
	(CLowerInterface::Singleton())->FreeItem(this);

	Notify(FSP_NotifyRecycled);
}


// Start sending queued packet(s) in the session control block
// Given
//	_In_	ALT_ID_T	the application layer thread id of the session
// Return
//	Nothing
// Remark
//	Operation code in the given command context would be cleared if send is pending
void CSocketItemEx::Send()
{
	TRACE_HERE("called");
	// synchronize the state in the 'cache' and the real state
	lowState = pControlBlock->state;
	ScheduleEmitQ();
}



// Given
//	PCTSTR			the name of the node to be resolved, which might be an IPv4 string representation
//	PCTSTR			the name of the service to be resolved, which might be a string of decimal port number
// Do
//	Resolve the UDP socket addresses of the given remote peer and store them in the peerAddr field of SCB
// Return
//	Number of addresses resolved, negative if error
int LOCALAPI CSocketItemEx::ResolveToFSPoverIPv4(const char *nodeName, const char *serviceName)
{
	static const struct addrinfo hints = { 0, AF_INET, };
	PADDRINFOA pAddrInfo;

	// assume the project is compiled in ANSI/MBCS language mode
	if(getaddrinfo(nodeName, serviceName, & hints, & pAddrInfo) != 0)
	{
#ifdef TRACE
		DWORD err = WSAGetLastError();
		char buffer[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR) & buffer, 1024, NULL);
		printf("Cannot Resolve the IP address of the node %s, error code = %d\n %s\n", nodeName, err, (LPTSTR) buffer);
#endif
		return -1;
	}

	if(pAddrInfo == NULL)
	{
#ifdef TRACE
		printf("Cannot resolve the IP address of the node %s\n", nodeName);
#endif
		return 0;
	}

	// See also CLowerInterface::EnumEffectiveAddresses
	register PFSP_IN4_ADDR_PREFIX prefixes = (PFSP_IN4_ADDR_PREFIX)pControlBlock->peerAddr.ipFSP.allowedPrefixes;
	int n = 0;
	pControlBlock->peerAddr.ipFSP.hostID = 0;
	pControlBlock->peerAddr.ipFSP.sessionID = PORT2ALT_ID( ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_port );
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
int LOCALAPI CSocketItemEx::ResolveToIPv6(const char *nodeName)
{
	static const struct addrinfo hints = { 0, AF_INET6, };
	PADDRINFOA pAddrInfo;
	// A value of zero for ai_socktype indicates the caller will accept any socket type. 
	// A value of zero for ai_protocol indicates the caller will accept any protocol. 

	// assume the project is compiled in ANSI/MBCS language mode
	if(getaddrinfo(nodeName, NULL, & hints, & pAddrInfo) != 0)
	{
#ifdef TRACE
		DWORD err = WSAGetLastError();
		char buffer[1024];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPTSTR) & buffer, 1024, NULL);
		printf("Cannot Resolve the IPv6 address of the node %s, error code = %d\n %s\n", nodeName, err, (LPTSTR) buffer);
#endif
		return -1;
	}

	if(pAddrInfo == NULL)
	{
#ifdef TRACE
		printf("Cannot resolve the IPv6 address of the node %s\n", nodeName);
#endif
		return 0;
	}

	// See also CLowerInterface::EnumEffectiveAddresses
	register UINT64 * prefixes = pControlBlock->peerAddr.ipFSP.allowedPrefixes;
	int n = 0;
	pControlBlock->peerAddr.ipFSP.hostID = SOCKADDR_HOST_ID(pAddrInfo->ai_addr);
	pControlBlock->peerAddr.ipFSP.sessionID = SOCKADDR_ALT_ID(pAddrInfo->ai_addr);
	do
	{
		prefixes[n] = *(UINT64 *)(((PSOCKADDR_IN6)pAddrInfo->ai_addr)->sin6_addr.u.Byte);
	} while(++n < MAX_PHY_INTERFACES && (pAddrInfo = pAddrInfo->ai_next) != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}



// a helper function which is self-describing
bool CommandNewSession::ResolvEvent()
{
	u.s.hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, (LPCSTR)u.szEventName);
	return (u.s.hEvent != NULL);
}
