/*
 * DLL to service FSP upper layer application
 * the DLL entry point, the top-level control structure
 * How does it work
 * - it assumes a micro-kernel environment, where system services are called by IPC
 * - hereby message passing(mailslot) and shared memory are exploited
 * - The ULA and the service process shared the FSP socket state information via the shared memory.
 * - For Windows:
 * -- When the DLL is attached, a mailslot handle is obstained. the handle is closed when the DLL is detached
 * -- When the ULA called a FSP API function, the function module construct a command structure object,
 * --   and pass it via mailslot to the service process via the mailslot
 * -- For each FSP socket, a reverse mailslot is allocated for each passive or initiative connection reqeust
 * -- Return value, if desired, is placed into the mailslot asynchronously. The return value is fetched by OVERLAPPED read.
 * -- Data packets are placed into the shared memory directly.
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
#include "FSP_DLL.h"
#include <stdlib.h>
#include <tchar.h>
#include <assert.h>

// access control is centralized managed in the 'main' source file
#include <Accctrl.h>
#include <Aclapi.h>

HANDLE _mdService = NULL;	// the mailslot descriptor of the service
DWORD nBytesReadWrite;		// number of bytes read/write last time
DWORD idThisProcess = 0;	// the id of the process that attaches this DLL

CSocketDLLTLB socketsTLB;

// A value of zero for ai_socktype indicates the caller will accept any socket type. 
// A value of zero for ai_protocol indicates the caller will accept any protocol. 
static SECURITY_ATTRIBUTES attrSecurity;
static void AllowDuplicateHandle();
static void GetServiceSA(PSECURITY_ATTRIBUTES);


extern "C" 
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	LPCSTR nameContainer = "FSPKeyContainer";
	// to maintain thread local storage
	if(dwReason == DLL_PROCESS_ATTACH)
	{
        DisableThreadLibraryCalls(hInstance);
		AllowDuplicateHandle();
		GetServiceSA(& attrSecurity);
#ifdef TRACE
		if(AllocConsole())
		{
//			_cprintf("_cprintf: Console window of the GUI application created.\n");
			printf("Console window of the GUI application created.\n");
		}
#endif
		_mdService = CreateFile(SERVICE_MAILSLOT_NAME
				, GENERIC_WRITE	
				// no GENERIC_READ needed, but MUST shared read, because LLS create the mailslot for read
				, FILE_SHARE_WRITE | FILE_SHARE_READ
				, NULL
				, OPEN_EXISTING
				, 0
				, NULL);
		if(_mdService == INVALID_HANDLE_VALUE)
		{
			REPORT_ERROR_ON_TRACE();
			return FALSE;
		}
		idThisProcess = GetCurrentProcessId();
	}
	else if(dwReason == DLL_PROCESS_DETACH)
	{
		if(_mdService != NULL)
			CloseHandle(_mdService);
	}
	//
	return TRUE;
}


// Return the number of microseconds elapsed since Jan 1, 1970 (unix epoch time)
extern "C" timestamp_t NowUTC()
{
	// return the number of 100-nanosecond intervals since January 1, 1601 (UTC), in host byte order
	FILETIME systemTime;
	GetSystemTimeAsFileTime(& systemTime);

	timestamp_t & t = *(timestamp_t *) & systemTime;
	t /= 10;
	return (t - DELTA_EPOCH_IN_MICROSECS);
}



CtrlMsgHdr::CtrlMsgHdr(PFSP_IN6_ADDR p)
{
	if(p->u.st.prefix == IPv6PREFIX_MARK_FSP)
	{
		pktHdr.cmsg_len = sizeof(pktHdr) + sizeof(struct in_pktinfo);
		pktHdr.cmsg_level = IPPROTO_IP;	/* originating protocol */
		pktHdr.cmsg_type = IP_PKTINFO;
		u.ipi_addr = p->u.st.ipv4;
		u.ipi_ifindex = 0;
	}
	else
	{
		pktHdr.cmsg_len = sizeof(CtrlMsgHdr);	/* #bytes, including this header */
		pktHdr.cmsg_level = IPPROTO_IPV6;	/* originating protocol */
		pktHdr.cmsg_type = IPV6_PKTINFO;
		*(PIN6_ADDR) & u = *(PIN6_ADDR)p;
		u.ipi6_ifindex = 0;
	}
}



PFSP_IN6_ADDR CtrlMsgHdr::ExportAddr(struct in6_pktinfo *p)
{
	if(IsIPv6MSGHDR(*this))
	{
		memcpy(p, & u, sizeof(struct in6_pktinfo));
	}
	else
	{	// FSP over UDP/IPv4
		((PFSP_IN6_ADDR) & p->ipi6_addr)->u.st.prefix = IPv6PREFIX_MARK_FSP;
		((PFSP_IN6_ADDR) & p->ipi6_addr)->u.st.ipv4 = u.ipi_addr;
		((PFSP_IN6_ADDR) & p->ipi6_addr)->u.st.port = DEFAULT_FSP_UDPPORT;
		((PFSP_IN6_ADDR) & p->ipi6_addr)->idHost = u.host_id;
		((PFSP_IN6_ADDR) & p->ipi6_addr)->idALT = u.idALT;
		p->ipi6_ifindex = u.ipi_ifindex;
	}
	return (PFSP_IN6_ADDR) & p->ipi6_addr;
}



// Given
//	uint32_t	the limit of the size of the control block. set to 0 to minimize
//	char []		the buffer to hold the name of the event
// Return
//	0 if no error, negative is the error code
int LOCALAPI CSocketItemDl::Initialize(PFSP_Context psp1, char szEventName[MAX_NAME_LENGTH])
{
	// TODO: evaluate configurable shared memory block size? // UNRESOLVED!? MTU?
	if(psp1->sendSize < 0 || psp1->recvSize < 0 || psp1->sendSize + psp1->recvSize > MAX_FSP_SHM_SIZE + MIN_RESERVED_BUF)
		return -ENOMEM;

	if(psp1->sendSize < MIN_RESERVED_BUF)
		psp1->sendSize = MIN_RESERVED_BUF;
	if(psp1->recvSize < MIN_RESERVED_BUF)
		psp1->recvSize = MIN_RESERVED_BUF;

	if(! psp1->u.st.passive)
	{
		int n = (psp1->sendSize - 1) / MAX_BLOCK_SIZE + (psp1->recvSize - 1) / MAX_BLOCK_SIZE + 2;
		// See also Init()
		dwMemorySize = ((sizeof(ControlBlock) + 7) >> 3 << 3)
			+ ((n * sizeof(ControlBlock::FSP_SocketBuf) + 7) >> 3 << 3)
			+ n * MAX_BLOCK_SIZE;
	}
	else
	{
		dwMemorySize = ((sizeof(ControlBlock) + 7) >> 3 << 3)
			+ sizeof(TSingleProviderMultipleConsumerQ<BackLogItem>) * FSP_BACKLOG_SIZE;
	}

	hMemoryMap = CreateFileMapping(INVALID_HANDLE_VALUE	// backed by the system paging file
		, NULL	// not inheritable
		, PAGE_READWRITE | SEC_COMMIT
		, 0, dwMemorySize	// file mapping size, we limit it to less than 4GB
		, NULL);
	if(hMemoryMap == INVALID_HANDLE_VALUE || hMemoryMap == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create shared memory object by CreateFileMapping");
		return -ENOENT;
	}

	// UNRESOLVED! passive socket and initiative socket are of different memory footprint?
	// if they are, there should be more AllocItem() function
	pControlBlock = (ControlBlock *)MapViewOfFile(hMemoryMap
		, FILE_MAP_ALL_ACCESS
		, 0, 0, dwMemorySize);
	if(pControlBlock == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot take use of shared memory object by MapViewOfFile");
		CloseHandle(hMemoryMap);
		return -ENOMEM;
	}

	// make the event name. the control block address, together with the process id, uniquely identify the event
	sprintf(szEventName, REVERSE_EVENT_NAME "%08X%08X", idThisProcess, (uint32_t)pControlBlock);
	// system automatically resets the event state to nonsignaled after a single waiting thread has been released
	hEvent = CreateEvent(& attrSecurity
		, FALSE // not manual-reset
		, FALSE // the initial state of the event object is nonsignaled
		, (LPCTSTR )szEventName);

#ifdef TRACE
	printf("ID of current process is %d, handle of the event is %08X\n", idThisProcess, hEvent);
#endif
	if(hEvent == INVALID_HANDLE_VALUE || hEvent == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create event object for reverse synchronization");
		UnmapViewOfFile(pControlBlock);
		CloseHandle(hMemoryMap);
		return -EINTR;	// the event mechanism is actually software interrupt mechanism
	}

	if(psp1->u.st.passive)
		pControlBlock->Init(FSP_BACKLOG_SIZE);
	else
		pControlBlock->Init(psp1->sendSize, psp1->recvSize);

	fpRequested = psp1->beforeAccept;
	fpAccepted = psp1->afterAccept;
	fpOnError = psp1->onError;

	uFlags.flags = psp1->u.flags;
	pendingSendBuf = (BYTE *)psp1->welcome;
	pendingSendSize = psp1->len;
	SetListenContext(psp1);	// could be exploited by ULA to make distinguishment of services

	return 0;
}




CSocketItemDl * LOCALAPI CSocketItemDl::CallCreate(CommandNewSession & objCommand, FSP_ServiceCode cmdCode)
{
	objCommand.opCode = cmdCode;
	objCommand.idProcess = ::idThisProcess;
	objCommand.idSession = sessionID;
	objCommand.hMemoryMap = hMemoryMap;
	objCommand.dwMemorySize = dwMemorySize;
	//
	if(! Call(objCommand, sizeof(objCommand)))
	{
		socketsTLB.FreeItem(this);
		return NULL;
	}
	return this;
}


// ULA would be punished if memory is deliberately corrupted as dead-loop occured due to dead-lock consume user-space CPU time only
bool CSocketItemDl::WaitSetMutex()
{
	++recurDepth;
	while(TestSetMutexBusy())
		_sleep(1);
	//
	return inUse;
}



// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	if(! WaitSetMutex())
		return;
	//
	FSP_ServiceCode notice;
	int r = 0;
	while((notice = PopNotice()) != NullCommand)
	{
#ifdef TRACE
		printf_s("\nIn session #%u, state %s, notice %s\n", sessionID
			, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
		switch(notice)
		{
		case FSP_NotifyBufferReady:
			ProcessPendingSend();
			break;
		case FSP_NotifyDataReady:
			ProcessReceiveBuffer();
			break;
		case FSP_NotifyAdjourn:
			SetMutexFree();
			NotifyError(FSP_NotifyAdjourn, 0);
			break;
		case FSP_NotifyFlushed:
			// safely assume that only in the PAUSING state may NotifyFlushed signaled
			ToConcludeAdjourn();
			break;
		// TODO: error handlers
		case FSP_NotifyIOError:
			break;
		case FSP_NotifyNameResolutionFailed:
			break;
		// Termination
		case FSP_NotifyReset:
			OnGetReset();
			return;
		case FSP_Timeout:
			// UNRESOLVED! TODO: review & test
			if(StateEqual(QUASI_ACTIVE))
			{
				SetState(CLOSED);
				SetMutexFree();
				NotifyError(FSP_NotifyRecycled, ENOEXEC);	// Resurrecting is not executed
			}
			break;
		case FSP_NotifyRecycled:
			NotifyError(FSP_NotifyRecycled, 0);	// report 'no error', actually
			SetMutexFree();
			return;
		case FSP_NotifyDisposed:
			NotifyError(FSP_NotifyDisposed, -EINTR);
			SetMutexFree();
			return;
		}
		r++;
		// mutex is free in the subroutines such as ProcessPendingSend, ProcessReceiveBuffer
		if(! WaitSetMutex())
			return;
	}
	//
	if(r > 0)
	{
		SetMutexFree();
		return;
	}
	//
	switch(pControlBlock->state)
	{
	case LISTENING:
		if(pControlBlock->HasBacklog())
		{
			ProcessBacklog();
			SetMutexFree();
		}
		else
		{
			r = (IsNotReturned() ? -EFAULT : 0);
			SetMutexFree();
			NotifyError(FSP_Listen, r);
		}
		break;
	case CONNECT_BOOTSTRAP:
		r = (int)IsNotReturned(); 
		SetMutexFree();
		if(r)
			this->fpAccepted(NULL, GetAndResetContext(), NULL);		// general error
		break;
	case CONNECT_AFFIRMING:
		ToConcludeConnect();		// SetMutexFree();
		break;
	case CHALLENGING:
		// UNRESOLVED!? if(IsNotReturned())	TRACE_HERE("Cannot synchronizing with LLS");
		ToConcludeAccept();			// SetMutexFree();
		break;
	case CLONING:
		ToConcludeMultiply();		// See also case NotifyAdjourn		// SetMutexFree();
		break;
	case RESUMING:
		ToConcludeResume();			// SetMutexFree();
		break;
	case QUASI_ACTIVE:
		ToConcludeResurrect();		// SetMutexFree();
		break;
	case ESTABLISHED:
		TRACE_HERE("ProcessPendingSend without notice: shall be obsolesced");
		// ProcessPendingSend();		// Conclude sending whenever possible
		break;
	}
}



// Given
//	PFSP_IN6_ADDR		const, the listening addresses of the passive FSP socket
//	PFSP_Context		the connection context of the socket, given by ULA
//	CommandNewSession & the command context of the socket,  to pass to LLS
// Return
//	NULL if it failed, or else the new allocated socket whose session control block has been initialized
CSocketItemDl * CSocketItemDl::CreateControlBlock(const PFSP_IN6_ADDR nearAddr, PFSP_Context psp1, CommandNewSession & cmd)
{
	CSocketItemDl *socketItem = socketsTLB.AllocItem();
	if(socketItem == NULL)
		return NULL;

	if(socketItem->Initialize(psp1, cmd.u.szEventName) < 0)
		return NULL;

	if(! socketItem->RegisterDrivingEvent())
	{
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}
	//
	socketItem->sessionID = nearAddr->idALT;
	//
	// TODO: UNRESOLVED! specifies 'ANY' address?
	//
	socketItem->pControlBlock->nearEnd[0] = CtrlMsgHdr(nearAddr);
	CtrlMsgHdr *pNearEnd = socketItem->pControlBlock->nearEnd;
	if(IsIPv6MSGHDR(*pNearEnd))
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pNearEnd[i].InitUDPoverIPv4(psp1->ifDefault);
		}
	}
	else
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pNearEnd[i].InitNativeIPv6(psp1->ifDefault);
		}
	}

	return socketItem;
}



// Given
//	PFSP_Context		the connection context of the socket, given by ULA
//	PFSP_IN6_ADDR		const, the listening addresses of the active FSP socket
//	CommandNewSession & the command context of the socket,  to pass to LLS
// Return
//	NULL if it failed, or else the new allocated socket whose session control block has been initialized
CSocketItemDl * CSocketItemDl::CreateControlBlock(PFSP_Context psp1, const PFSP_IN6_ADDR addrTo, CommandNewSession & cmd)
{
	CSocketItemDl *socketItem = socketsTLB.AllocItem();
	if(socketItem == NULL)
		return NULL;

	if(socketItem->Initialize(psp1, cmd.u.szEventName) < 0)
		return NULL;

	if(! socketItem->RegisterDrivingEvent())	
	{
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}

	// sessionID is yet to be returned by the LLS
	socketItem->pControlBlock->u.connectParams.idRemote = addrTo->idALT;
	//
	CtrlMsgHdr * pNearEnd = socketItem->pControlBlock->nearEnd;
	PSOCKADDR_INET pFarEnd = socketItem->pControlBlock->sockAddrTo;
	if(addrTo->u.st.prefix == IPv6PREFIX_MARK_FSP)
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pNearEnd[i].InitUDPoverIPv4(psp1->ifDefault);
			//
			pFarEnd[i].Ipv4.sin_family = AF_INET;
			pFarEnd[i].Ipv4.sin_port = DEFAULT_FSP_UDPPORT;
			pFarEnd[i].Ipv4.sin_addr.S_un.S_addr = addrTo[i].u.st.ipv4;
			memset(pFarEnd[i].Ipv4.sin_zero	// assert(sizeof(pFarEnd[i].Ipv4.sin_zero) == 8)
				, 0		// idHost is set to zero as well
				, sizeof(SOCKADDR_IN6) - sizeof(SOCKADDR_IN) + 8 - sizeof(ALT_ID_T));
			((PFSP_IN6_ADDR) & (pFarEnd[i].Ipv6.sin6_addr))->idALT = addrTo->idALT;
		}
	}
	else
	{
		// local address is yet to be determined by the LLS
		for(register int i = 0; i < MAX_PHY_INTERFACES; i++)
		{
			pNearEnd[i].InitNativeIPv6(psp1->ifDefault);
			//
			pFarEnd[i].Ipv6.sin6_family = AF_INET6;
			pFarEnd[i].Ipv6.sin6_flowinfo = 0;
			pFarEnd[i].Ipv6.sin6_port = 0;
			pFarEnd[i].Ipv6.sin6_scope_id = 0;
			pFarEnd[i].Ipv6.sin6_addr = *(PIN6_ADDR) & addrTo[i];
		}
	}
	//
	return socketItem;
}


bool LOCALAPI CSocketItemDl::Call(const CommandToLLS & cmd, int size, int returned)
{
	SetReturned(returned);
	return ::WriteFile(_mdService, & cmd, size, & nBytesReadWrite, NULL) != FALSE;
}



int LOCALAPI CSocketItemDl::CopyKey(ALT_ID_T id1)
{
	CSocketItemDl *p1 = socketsTLB[id1];
	if(p1 == NULL || ! p1->IsInUse())
		return -1;
	//
	pControlBlock->idParent = id1;
	pControlBlock->u = p1->pControlBlock->u;
	pControlBlock->mac_ctx = p1->pControlBlock->mac_ctx;
	return 0;
}




DllSpec
bool EOMReceived(FSPHANDLE hFSPSocket)
{
	return ((CSocketItemDl *)hFSPSocket)->EOMRecv();
}



CSocketItemDl * CSocketDLLTLB::AllocItem()
{
	CSocketItemDl * item = header;
	if(item == NULL)
	{
		item = new CSocketItemDl();
		if(item == NULL)
			return NULL;
		// assert: header == NULL);
	}
	else
	{
		header = item->next;
		if(header != NULL)
			header->prev = NULL;
	}

	memset((BYTE *)item + sizeof(CSocketItem)
		, 0
		, sizeof(CSocketItemDl) - sizeof(CSocketItem));
	// item->prev = item->next = NULL;	// so does other connection state pointers and flags
	// item->recurDepth = 0;
	// item->mutex = SHARED_FREE;
	item->inUse = TRUE;

#ifdef TRACE
	printf_s("New item allocated, initially recurDepth, mutex, inUse = %d, %d, %d\n",
		item->recurDepth, item->mutex, item->inUse);
#endif

	// sizeof(pSockets) / sizeof(CSocketItem *) == MAX_CONNECTION_NUM
	if(sizeOfSet >= MAX_CONNECTION_NUM)
	{
		Compress();
		if(sizeOfSet >= MAX_CONNECTION_NUM)
		{
			FreeItem(item);
			return NULL;
		}
	}

	pSockets[sizeOfSet++] = item;
	return item;
}


void CSocketDLLTLB::FreeItem(CSocketItemDl *r)
{
	r->inUse = FALSE;
	r->prev = NULL;
	r->next = header;
	if(header != NULL)
		header->prev = r;
	header = r;
}


// The caller should check whether it's really a working connection by check inUse flag
// connection reusable.
CSocketItemDl * CSocketDLLTLB::operator[](ALT_ID_T sessionID)
{
	for(int i = 0; i < sizeOfSet; i++)
	{
		if(pSockets[i]->sessionID == sessionID)
			return pSockets[i];
	}
	return NULL;
}


// make it easy to be searched linearly
void CSocketDLLTLB::Compress()
{
	for(register int i = 0; i < sizeOfSet; i++)
	{
		register int j = 0;
		while(! pSockets[i + j]->IsInUse())
			j++;
		if(j == 0)
			continue;
		//
		sizeOfSet -= j;
		for(register int k = i; k < sizeOfSet; k++)
		{
			pSockets[k] = pSockets[k + j];
		}
	}
}


// LLS MUST RunAs NT AUTHORITY\NETWORK SERVICE account 
void AllowDuplicateHandle()
{
	SECURITY_INFORMATION SIRequested = DACL_SECURITY_INFORMATION;
	SECURITY_DESCRIPTOR sd;

    PSID pServiceSID = NULL;
	PSID pOwnerSID = NULL;
    PACL pACL = NULL;
    EXPLICIT_ACCESS ea[2];
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

    // Create a well-known SID for the account that LLS could RunAs
    if(! AllocateAndInitializeSid(& SIDAuthNT, 1,
                     SECURITY_NETWORK_SERVICE_RID,	// dwSubAuthority0
                     0, 0, 0, 0, 0, 0, 0,	// dwSubAuthority 2~7
                     & pServiceSID)
	|| ! AllocateAndInitializeSid(& SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,	// dwSubAuthority0
                     DOMAIN_ALIAS_RID_ADMINS,
					 0, 0, 0, 0, 0, 0,	// dwSubAuthority 2~7
                     & pOwnerSID)
	)
    {
#ifndef NDEBUG
        printf("AllocateAndInitializeSid Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
	ZeroMemory(ea, sizeof(EXPLICIT_ACCESS) * 2);
	ea[0].grfAccessPermissions = GENERIC_ALL | PROCESS_DUP_HANDLE;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance= NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea[0].Trustee.ptstrName  = (LPTSTR) pServiceSID;
	//
	ea[1].grfAccessPermissions = GENERIC_ALL | PROCESS_DUP_HANDLE;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance= NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName  = (LPTSTR) pOwnerSID;

    // Create a new ACL that contains the new ACEs.
    if (SetEntriesInAcl(2, ea, NULL, & pACL) != ERROR_SUCCESS) 
    {
#ifndef NDEBUG
        printf("SetEntriesInAcl Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }
 
    if (! InitializeSecurityDescriptor(& sd, SECURITY_DESCRIPTOR_REVISION)) 
    {  
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %u\n", GetLastError());
#endif
        goto Cleanup; 
    } 
 
    // Add the ACL to the security descriptor. 
    if (! SetSecurityDescriptorDacl(& sd, 
            TRUE,     // bDaclPresent flag   
            pACL, 
            FALSE))   // not a default DACL 
    {  
        printf("SetSecurityDescriptorDacl Error %u\n", GetLastError());
        goto Cleanup; 
    } 

	if(! SetUserObjectSecurity(GetCurrentProcess()
		, & SIRequested
		, & sd))
	{
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %u\n", GetLastError());
#endif
		//UNRESOLVED! is it a recoverable error or a fatal?
	}

Cleanup:
	if(pServiceSID)
		FreeSid(pServiceSID);
	if(pOwnerSID)
		FreeSid(pOwnerSID);
}


// a security attribute depends on a security descriptor
// while a security descriptor depends on an ACL
// while an ACL contains at least one explicit access entry (ACL entry) [if it is NULL, by default everyone access]
// while an explicit access entry requires a SID
static void GetServiceSA(PSECURITY_ATTRIBUTES pSA)
{
    PSID pEveryoneSID = NULL;
    PACL pACL = NULL;
    EXPLICIT_ACCESS ea;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	static SECURITY_DESCRIPTOR sd;	// as it is referenced by pSA

    // Create a well-known SID for the Everyone group.
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                     SECURITY_WORLD_RID,	// dwSubAuthority0
                     0, 0, 0, 0, 0, 0, 0, // dwSubAuthority 1~7
                     & pEveryoneSID))
    {
#ifndef NDEBUG
        printf("AllocateAndInitializeSid Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_ALL;	// SPECIFIC_RIGHTS_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName  = (LPTSTR) pEveryoneSID;

    // Create a new ACL that contains the new ACEs.
    if (SetEntriesInAcl(1, & ea, NULL, &pACL) != ERROR_SUCCESS) 
    {
#ifndef NDEBUG
        printf("SetEntriesInAcl Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }
 
    if (!InitializeSecurityDescriptor(& sd, SECURITY_DESCRIPTOR_REVISION)) 
    {  
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %u\n", GetLastError());
#endif
        goto Cleanup; 
    } 
 
    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(& sd, 
            TRUE,     // bDaclPresent flag   
            pACL, 
            FALSE))   // not a default DACL 
    {  
        printf("SetSecurityDescriptorDacl Error %u\n", GetLastError());
        goto Cleanup; 
    } 

    // Initialize a security attributes structure.
	
    pSA->nLength = sizeof (SECURITY_ATTRIBUTES);
    pSA->lpSecurityDescriptor = & sd;
    pSA->bInheritHandle = FALSE;

Cleanup:
	;	// do not free SID or ACL, until the process terminated(?) 
    //if (pEveryoneSID) 
    //    FreeSid(pEveryoneSID);
	// if(pACL)
	//	  LocalFree(pACL);
}





// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(char * fileName, int lineNo, char *funcName, char *s1)
{
	DWORD err = GetLastError();
	CHAR buffer[ERROR_SIZE];
	printf("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", fileName, lineNo, funcName, s1);

	buffer[0] = 0;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
		, NULL
		, err
		, LANG_USER_DEFAULT
		, (LPTSTR) & buffer
		, ERROR_SIZE
		, NULL);
	if(buffer[0] != 0)
		puts(buffer);
}
