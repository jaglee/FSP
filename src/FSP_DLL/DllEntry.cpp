/*
 * DLL to service FSP upper layer application, the DLL entry point and the top-level control structure
 * How does it work
 * - combines of micro-kernel message-passing IPC metaphor and hardware interrupt vector mechanism
 * - The ULA and the service process shared the FSP socket state information via the shared memory
 * - For Windows:
 * -- When LLS is created the global shared FSP mailslot is created
 * -- When DLL is attached, a handle to the global FSP mailslot is obstained
 * -- For each FSP socket a block of shared memory is allocated by DLL
 *    preferably with address space layout randomiation applied
 * -- When ULA called an FSP API the corresponding function module construct a command structure object
 *    and pass it via the uni-direction mailslot to the service process
 * -- A limited-size notice queue is allocated by DLL in the shared memory for LLS to 'interrupt' ULA through DLL callback
 * -- Return value, if desired, is placed into some rendezvous location in the shared memory block
 * -- Data packets either sent or received are placed into the shared memory directly
 * -- The handle of the global FSP mailslot is released when the DLL is detached
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

// UNRESOLVED! TODO: Dynamically allocate memory for each process!
HANDLE		_mdService = NULL;	// the mailslot descriptor of the service
HANDLE		timerQueue = NULL;
DWORD		nBytesReadWrite;		// number of bytes read/write last time
DWORD		idThisProcess = 0;	// the id of the process that attaches this DLL
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
		AllocConsole();
#endif
		_mdService = CreateFileA(SERVICE_MAILSLOT_NAME
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
		//
		timerQueue = CreateTimerQueue();
	}
	else if(dwReason == DLL_PROCESS_DETACH)
	{
		DeleteTimerQueueEx(timerQueue, NULL);
		//
		if(_mdService != NULL)
			CloseHandle(_mdService);
	}
	//
	return TRUE;
}



// Remark
//	Exploit _InterlockedXor8 to keep memory access order as the coded order
bool CSocketItemDl::WaitUseMutex()
{
	if(!IsInUse())
		return false;
#ifndef NDEBUG
#ifdef TRACE
	printf_s("\nFSPSocket#0x%X  WaitUseMutex\n", (CSocketItem *)this);
#endif
	uint64_t t0 = GetTickCount64();
	while(!TryAcquireSRWLockExclusive(& rtSRWLock))
	{
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			DebugBreak();	// To trace the call stack, there may be deadlock
			return false;
		}
		Sleep(50);	// if there is some thread that has exclusive access on the lock, wait patiently
	}
#else
	AcquireSRWLockExclusive(& rtSRWLock);
#endif
	return IsInUse();
}



#if !defined(NDEBUG) && defined(TRACE)
void CSocketItemDl::SetMutexFree()
{
	ReleaseSRWLockExclusive(& rtSRWLock);
	printf_s("\nFSPSocket#0x%X  SetMutexFree\n", (CSocketItem *)this);
}
#endif



int CSocketItemDl::SelfNotify(FSP_ServiceCode c)
{
	uint64_t t0 = GetTickCount64();
	int r;
	//
	while((r = pControlBlock->notices.Put(c)) < 0)
	{
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			DebugBreak();	// To trace the call stack, there may be deadlock on waiting for free notice slot
			return -EINTR;
		}
		Sleep(50);
	}
#ifdef TRACE
	printf_s("Self notice %s[%d] in local fiber#0x%X, state %s\t\n", noticeNames[c], c, fidPair.source, stateNames[pControlBlock->state]);
	if(r > 0)
		printf_s("--- merged ---\n");
#endif

	// in case loss of event we do not eliminate redundant notice
	::SetEvent(hEvent);
	return 0;
}



DllExport
int FSPAPI FSPControl(FSPHANDLE hFSPSocket, FSP_ControlCode controlCode, ULONG_PTR value)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		switch(controlCode)
		{
		case FSP_GET_SIGNATURE:
			*(uint64_t *)value = pSocket->GetULASignature();
			break;
		case FSP_SET_SEND_COMPRESSING:
			pSocket->SetSendCompressing(value != 0);
			break;
		case FSP_SET_CALLBACK_ON_ERROR:
			pSocket->SetCallbackOnError((NotifyOrReturn)value);
			break;
		case FSP_SET_CALLBACK_ON_REQUEST:
			pSocket->SetCallbackOnRequest((CallbackRequested)value);
			break;
		case FSP_SET_CALLBACK_ON_CONNECT:
			pSocket->SetCallbackOnAccept((CallbackConnected)value);
			break;
		default:
			return -EDOM;
		}
		return 0;
	}
	catch(...)
	{
		return -EINTR;
	}
}




// Given
//	PFSP_Context
//	char []		the buffer to hold the name of the event
// Do
//	Create and initialize the shared memory struction of the Session Control Block
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
			+ n * (((sizeof(ControlBlock::FSP_SocketBuf) + 7) >> 3 << 3) + MAX_BLOCK_SIZE);
	}
	else
	{
		dwMemorySize = ((sizeof(ControlBlock) + 7) >> 3 << 3)
			+ sizeof(LLSBackLog) + sizeof(BackLogItem) * (FSP_BACKLOG_SIZE - MIN_QUEUED_INTR);
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
	sprintf_s(szEventName, MAX_NAME_LENGTH, REVERSE_EVENT_PREFIX "%08X%08X", idThisProcess, (uint32_t)pControlBlock);
	// system automatically resets the event state to nonsignaled after a single waiting thread has been released
	hEvent = CreateEventA(& attrSecurity
		, FALSE // not manual-reset
		, FALSE // the initial state of the event object is nonsignaled
		, szEventName);	// (LPCTSTR)

#ifdef TRACE
	printf_s("ID of current process is %d, handle of the event is %08X\n", idThisProcess, hEvent);
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

	pControlBlock->notices.SetHead(FSP_IPC_CannotReturn);
	//^only after the control block is successfully mapped into the memory space of LLS may it be cleared by SetCallable()

	// could be exploited by ULA to make distinguishment of services
	memcpy(&context, psp1, sizeof(FSP_SocketParameter));
	pendingSendBuf = (BYTE *)psp1->welcome;
	pendingSendSize = psp1->len;

	return 0;
}



CSocketItemDl * LOCALAPI CSocketItemDl::CallCreate(CommandNewSession & objCommand, FSP_ServiceCode cmdCode)
{
	objCommand.fiberID = fidPair.source;
	objCommand.idProcess = ::idThisProcess;
	objCommand.opCode = cmdCode;
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



bool CSocketItemDl::LockAndValidate()
{
	if(! WaitUseMutex())
	{
		if(IsInUse())
			DebugBreak();	// TRACE_HERE("deadlock encountered!?");
		return false;
	}

	if(pControlBlock == NULL)
	{
#ifndef NDEBUG
		printf_s("\nDescriptor=0x%X: event to be processed, but the Control Block is missing!\n", (int32_t)(CSocketItem *)this);
#endif
		socketsTLB.FreeItem(this);
		Reinitialize();
		NotifyError(FSP_NotifyReset, -EBADF);
		return false;
	}

	if(InIllegalState())
	{
#ifndef NDEBUG
		printf_s(
			"\nDescriptor=0x%X, event to be processed, but the socket is in state %s[%d]?\n"
			, (int32_t)(CSocketItem *)this
			, stateNames[pControlBlock->state], pControlBlock->state);
#endif
		InterlockedExchangePointer((PVOID *)& fpRecycled, NULL);
		this->Recycle();
		NotifyError(FSP_NotifyReset, -EBADF);
		return false;
	}

	return true;
}


// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	FSP_ServiceCode notice;
	while(LockAndValidate())
	{
		notice = pControlBlock->notices.Pop();
		if(notice == NullCommand)
		{
			SetMutexFree();
			break;
		}

#ifdef TRACE
		printf_s("\nIn local fiber#0x%X, state %s\tnotice: %s\n", fidPair.source, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
		// If recyled or in the state not earlier than ToFinish, LLS should have recyle the session context mapping already
		if(notice == FSP_NotifyRecycled || notice >= FSP_NotifyToFinish)
			lowerLayerRecycled = 1;
		// Initially lowerLayerRecycled is 0 and it is never reset
		if(! IsInUse() && lowerLayerRecycled != 0)
		{
#ifndef NDEBUG
			printf_s(
				"\nEvent to be processed, but the socket has been recycled!?\n"
				"\tdescriptor=0x%X, state: %s[%d]\n"
				, (int32_t)(CSocketItem *)this
				, stateNames[pControlBlock->state], pControlBlock->state);
#endif
			socketsTLB.FreeItem(this);
			Reinitialize();
			NotifyError(FSP_NotifyReset, -EBADF);
			return;
		}

		shouldChainTimeout = 1;
		switch(notice)
		{
		case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
			if(pControlBlock->HasBacklog())
				ProcessBacklog();
			SetMutexFree();
			break;
		case FSP_NotifyAccepted:
			CancelTimer();			// If any
			// Asychronous return of Connect2, where the initiator may cancel data transmission
			if(InState(CONNECT_AFFIRMING))
			{
				ToConcludeConnect();// SetMutexFree();
				return;
			}
			if(context.onAccepted != NULL)
			{
				SetMutexFree();
				context.onAccepted(this, &context);
				if(! LockAndValidate())
					return;
			}
			ProcessReceiveBuffer();	// SetMutexFree();
			break;
		case FSP_NotifyMultiplied:	// See also @LLS::Connect()
			CancelTimer();			// If any
			fidPair.source = pControlBlock->nearEndInfo.idALF;
			ProcessReceiveBuffer();
			if(! LockAndValidate())
				return;
			ProcessPendingSend();	// To inherently chain WriteTo/SendInline with Multiply
			break;
		case FSP_NotifyDataReady:
			ProcessReceiveBuffer();	// SetMutexFree();
			break;
		case FSP_NotifyBufferReady:
			ProcessPendingSend();	// SetMutexFree();
			break;
		case FSP_NotifyToCommit:
			ProcessReceiveBuffer();	// See FSP_NotifyDataReady, FSP_NotifyFlushed and CSocketItemDl::Shutdown()
			if(! LockAndValidate())
				return;
			if(InState(CLOSABLE) && initiatingShutdown)
				Call<FSP_Shutdown>();
			SetMutexFree();
			break;
		case FSP_NotifyFlushed:
			ProcessPendingSend();	// SetMutexFree();
			if(! LockAndValidate())
				return;
			if(InState(CLOSABLE) && initiatingShutdown)
				Call<FSP_Shutdown>();
			SetMutexFree();
			break;
		case FSP_NotifyToFinish:
			if(initiatingShutdown)
				RespondToRecycle();
			else
				SetMutexFree();
			return;
		case FSP_NotifyRecycled:
			CancelTimer();	// If any; typically for Shutdown 
			RespondToRecycle();
			return;
		case FSP_NotifyReset:
			socketsTLB.FreeItem(this);
			Reinitialize();
			NotifyError(notice, -EINTR);
			return;
		case FSP_IPC_CannotReturn:
			if (pControlBlock->state == LISTENING)
			{
				SetMutexFree();
				NotifyError(FSP_Listen, -EFAULT);
			}
			else if (pControlBlock->state == CONNECT_BOOTSTRAP || pControlBlock->state == CONNECT_AFFIRMING)
			{
				SetMutexFree();
				context.onAccepted(NULL, &context);		// general error
			}
#ifdef TRACE
			else	// else just ignore the dist
			{
				SetMutexFree();
				printf_s("Get FSP_IPC_CannotReturn in the state %s\n", stateNames[pControlBlock->state]);
			}
#endif
			return;
		case FSP_MemoryCorruption:
		case FSP_NotifyOverflow:
		case FSP_NotifyTimeout:
		case FSP_NotifyNameResolutionFailed:
			NotifyError(notice, -EINTR);
			socketsTLB.FreeItem(this);
			Reinitialize();	// SetMutexFree();
			return;
			// UNRESOLVED!? There could be some remedy if name resolution failed?
		}
	}
}



// Given
//	PFSP_IN6_ADDR		const, the listening addresses of the passive FSP socket
//	PFSP_Context		the connection context of the socket, given by ULA
//	CommandNewSession & the command context of the socket,  to pass to LLS
// Return
//	NULL if it failed, or else the new allocated socket whose session control block has been initialized
CSocketItemDl * LOCALAPI CSocketItemDl::CreateControlBlock(const PFSP_IN6_ADDR nearAddr, PFSP_Context psp1, CommandNewSession & cmd)
{
	CSocketItemDl *socketItem = socketsTLB.AllocItem();
	if(socketItem == NULL)
		return NULL;

	if(socketItem->Initialize(psp1, cmd.szEventName) < 0)
		return NULL;

	if(! socketItem->RegisterDrivingEvent())
	{
		socketsTLB.FreeItem(socketItem);
		return NULL;
	}
	//
	socketItem->fidPair.source = nearAddr->idALF;
	//
	FSP_PKTINFO_EX & nearEnd = socketItem->pControlBlock->nearEndInfo;
	if(nearAddr->u.st.prefix == PREFIX_FSP_IP6to4)
	{
		nearEnd.InitUDPoverIPv4(psp1->ifDefault);
		nearEnd.idALF = nearAddr->idALF;
		nearEnd.ipi_addr = nearAddr->u.st.ipv4;
	}
	else
	{
		nearEnd.InitNativeIPv6(psp1->ifDefault);
		*(PIN6_ADDR) & nearEnd = *(PIN6_ADDR)nearAddr;
	}
	// Application Layer Thread ID other than the first default would be set in the LLS

	return socketItem;
}



bool LOCALAPI CSocketItemDl::Call(const CommandToLLS & cmd, int size)
{
	return ::WriteFile(_mdService, & cmd, size, & nBytesReadWrite, NULL) != FALSE;
}



bool LOCALAPI CSocketItemDl::AddOneShotTimer(uint32_t dueTime)
{
	shouldChainTimeout = 0;
	return (timer != NULL
		? ::ChangeTimerQueueTimer(::timerQueue, timer, dueTime, 0)
		: ::CreateTimerQueueTimer(& timer, ::timerQueue
			, WaitOrTimeOutCallBack
			, this		// LPParameter
			, dueTime
			, 0
			, WT_EXECUTEINTIMERTHREAD
			)
		) != FALSE;
}



bool CSocketItemDl::CancelTimer()
{
	if(::DeleteTimerQueueTimer(::timerQueue, timer, NULL))
	{
		timer = NULL;
		return true;
	}
	else
	{
		return false;
	}
}



void CSocketItemDl::TimeOut()
{
	if(pControlBlock->notices.GetHead() == FSP_IPC_CannotReturn)
	{
		Recycle();
		return;
	}
	//
	if(shouldChainTimeout)
		AddOneShotTimer(TRASIENT_STATE_TIMEOUT_ms);
}



CSocketItemDl * CSocketDLLTLB::AllocItem()
{
	AcquireSRWLockExclusive(& srwLock);

	CSocketItemDl * item = NULL;
	// Firstly, make it easy to be searched linearly
	if(sizeOfWorkSet >= MAX_CONNECTION_NUM)
	{
		for(register int i = 0; i < sizeOfWorkSet; i++)
		{
			register int j = 0;
			while(! pSockets[i + j]->IsInUse())
				j++;
			if(j == 0)
				continue;
			//
			sizeOfWorkSet -= j;
			for(register int k = i; k < sizeOfWorkSet; k++)
			{
				pSockets[k] = pSockets[k + j];
			}
		}
		//
		if(sizeOfWorkSet >= MAX_CONNECTION_NUM)
			goto l_bailout;
	}

	if(countAllItems < MAX_CONNECTION_NUM * 3)
	{
		item = new CSocketItemDl();
		if(item == NULL)
			goto l_bailout;	// return NULL; // assert: header == NULL);
		//
		countAllItems++;
	}
	else
	{
		item = head;
		if(item == NULL)
			goto l_bailout;	// return NULL; // assert: header == NULL);
		//
		head = item->next;
		if(head != NULL)
			head->prev = NULL;
		else
			tail = NULL;
		// Make it impossible to be improperly reused
		memset((BYTE *)item->pControlBlock, 0, (BYTE *) & item->pControlBlock->backLog - (BYTE *)item->pControlBlock);
		item->pControlBlock->backLog.Clear();	// UNRESOLVED! Is clear backlog safe!?
	}

	memset((BYTE *)item + sizeof(CSocketItem)
		, 0
		, sizeof(CSocketItemDl) - sizeof(CSocketItem));
	// item->prev = item->next = NULL;	// so does other connection state pointers and flags
	pSockets[sizeOfWorkSet++] = item;
	_InterlockedExchange8(& item->inUse, 1);

l_bailout:
	ReleaseSRWLockExclusive( & srwLock);
	return item;
}



void CSocketDLLTLB::FreeItem(CSocketItemDl *r)
{
	AcquireSRWLockExclusive(& srwLock);

	_InterlockedExchange8(& r->inUse, 0);
	r->next = NULL;
	r->prev = tail;
	if(tail == NULL)
	{
		head = tail = r;
	}
	else
	{
		tail->next = r;
		tail = r;
	}

	ReleaseSRWLockExclusive( & srwLock);
}



bool CSocketDLLTLB::ReuseItem(CSocketItemDl *item)
{
	AcquireSRWLockExclusive(& srwLock);
	if(_InterlockedCompareExchange8(& item->inUse, 1, 0) != 0)
	{
		ReleaseSRWLockExclusive( & srwLock);
		return false;
	}

	if(item->prev != NULL)
		item->prev = item->prev->prev;
	else
		head = item->next;
	//
	if(item->next != NULL)
		item->next = item->next->next;
	else
		tail = item->prev;

	ReleaseSRWLockExclusive( & srwLock);
	return true;
}



// The caller should check whether it's really a working connection by check inUse flag
// connection reusable.
// Performance of linear search is acceptable for small set
CSocketItemDl * CSocketDLLTLB::operator[](ALFID_T fiberID)
{
	for(int i = 0; i < sizeOfWorkSet; i++)
	{
		if(pSockets[i]->fidPair.source == fiberID)
			return pSockets[i];
	}
	return NULL;
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
