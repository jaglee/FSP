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

static int LOCALAPI ResolveToFSPoverIPv4(PFSP_IN6_ADDR, int capacity, const char *, const char *);
static int LOCALAPI ResolveToIPv6(PFSP_IN6_ADDR arrDst, int capacity, const char *nodeName);

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
	InitAssociation();
	//
	SetReturned();
	SignalEvent();
}



void LOCALAPI CSocketItemEx::Connect(CommandNewSession *pCmd)
{
	TRACE_HERE("called");

	// Resolve the current IP-socket address of the remote end at first
	FSP_IN6_ADDR addrTo[MAX_PHY_INTERFACES];
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
	int r = ResolveToFSPoverIPv4(addrTo, MAX_PHY_INTERFACES, peerName, serviceName);
	if(r <= 0)
	{
		r = ResolveToIPv6(addrTo, MAX_PHY_INTERFACES, peerName);
		if(r <=  0)
		{
			Notify(FSP_NotifyNameResolutionFailed);
			goto l_return;
		}
	}

	// UNRESOLVED! TODO: mobility support/routing -- find the best interface and local IP address
	SetRemoteAddress(addrTo);
	// bind to the interface as soon as the control block mapped into server's memory space
	InitAssociation();

	InitiateConnect();
	SetReturned();
	SignalEvent();

l_return:
	connectRequests.Remove(pCmd->u.s.index);
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
	if(IsNotReturned())
	{
		SetReturned();
		SignalEvent();
	}
	//else // Only after first SNACK echoed back may the acknowledgement to the send returned to ULA
}



// Given
//	PFSP_IN6_ADDR	the array to hold the output FSP/IPv6 addresses
//	int				the capacity of the array
//	PCTSTR			the name of the node to be resolved, which might be an IPv4 string representation
//	PCTSTR			the name of the service to be resolved, which might be a string of decimal port number
// Return
//	Number of addresses resolved, negative if error
// Remark
//	If (capacity <= 0) it will return 0
static
int LOCALAPI ResolveToFSPoverIPv4(PFSP_IN6_ADDR arrDst
	, int capacity
	, const char *nodeName
	, const char *serviceName)
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

	int n = 0;
	do
	{
		// Must keep in consistent with TranslateFSPoverIPv4
		arrDst->u.st.prefix = IPv6PREFIX_MARK_FSP;
		arrDst->u.st.ipv4 = ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_addr.S_un.S_addr;
		arrDst->u.st.port = DEFAULT_FSP_UDPPORT;
		// arrDst->idHost = 0;	// UNRESOLVED! where is host id set?
		arrDst->idALT = PORT2ALT_ID( ((PSOCKADDR_IN)pAddrInfo->ai_addr)->sin_port );
		// note that port number resolved is already in network byte order
		n++;
		arrDst++;
		pAddrInfo = pAddrInfo->ai_next;
	} while(n < capacity && pAddrInfo != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}


// Given
//	PFSP_IN6_ADDR	the array to hold the output FSP/IPv6 addresses
//	int				the capacity of the array
//	PCTSTR			the name of the node to be resolved, which might be an IPv6 string representation
// Return
//	Number of addresses resolved, negative if error
// Remark
//	If (capacity <= 0) it will return 0
static
int LOCALAPI ResolveToIPv6(PFSP_IN6_ADDR arrDst, int capacity, const char *nodeName)
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

	int n = 0;
	do
	{
		memcpy(arrDst
			, & ((PSOCKADDR_IN6)pAddrInfo->ai_addr)->sin6_addr
			, sizeof(IN6_ADDR));
		n++;
		arrDst++;
		pAddrInfo = pAddrInfo->ai_next;
	} while(n < capacity && pAddrInfo != NULL);

	freeaddrinfo(pAddrInfo);
	return n;
}



// a helper function which is self-describing
bool CommandNewSession::ResolvEvent()
{
	u.s.hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, (LPCSTR)u.szEventName);
	return (u.s.hEvent != NULL);
}
