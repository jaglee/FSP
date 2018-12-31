/*
 * DLL to service FSP upper layer application, the DLL entry point and the top-level control structure
 * How does it work
 * - Lower-Layer-Service process and DLL exchange the FSP state information via the shared memory
 * - ULA calls the FSP services through DLL
 * - emulate hardware interrupt vector mechanism
 * - For Windows:
 * -- When LLS is created the global shared FSP mailslot is created
 * -- When DLL is attached, a handle to the global FSP mailslot is obstained
 * -- For each FSP socket a block of shared memory is allocated by DLL
 *    preferably with address space layout randomization applied
 * -- When ULA calls an FSP function the corresponding API module construct a command structure object
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

DWORD	CSocketItemDl::idThisProcess = 0;	// the id of the process that attaches this DLL
CSocketDLLTLB CSocketItemDl::socketsTLB;	// the shared class member

static HANDLE		_mdService; // = NULL;	// the mailslot descriptor of the service
static HANDLE		timerQueue;	// = NULL;


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
		CSocketItemDl::SaveProcessId();
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



/**
 *	POSIX gettimeofday(); get current UTC time
 */
// Return the number of microseconds elapsed since Jan 1, 1970 UTC (unix epoch)
DllSpec
timestamp_t NowUTC()
{
	// return the number of 100-nanosecond intervals since January 1, 1601 (UTC), in host byte order
	FILETIME systemTime;
	GetSystemTimeAsFileTime(&systemTime);

	timestamp_t & t = *(timestamp_t *)& systemTime;
	t /= 10;
	return (t - DELTA_EPOCH_IN_MICROSECS);
}



// Return
//	true if obtained the mutual-exclusive lock
//	false if timed out
// Remark
//	Exploit _InterlockedCompareExchange8 to keep memory access order as the coded order
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
		Sleep(TIMER_SLICE_ms);
	}
	return true;
}



// Do
//	Try to obtain the slim-read-write mutual-exclusive lock of the FSP socket
// Return
//	true if obtained the mutual-exclusive lock
//	false if timed out
// Remark
//	if there is some thread that has exclusive access on the lock, wait patiently
bool CSocketItemDl::WaitUseMutex()
{
	uint64_t t0 = GetTickCount64();
	while(!TryAcquireSRWLockExclusive(& rtSRWLock))
	{
		// possible dead lock: should trace the error in debug mode!
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
			return false;
		if(!IsInUse())
			return false;
		//
		Sleep(TIMER_SLICE_ms);
	}
	//
	return IsInUse();
}



// Given
//	FSP_ServiceCode		the notification to be put into the notice queue
// Return
//	0 if no error
//	negative: the error number
int CSocketItemDl::SelfNotify(FSP_ServiceCode c)
{
	uint64_t t0 = GetTickCount64();
	int r;
	//
	while((r = pControlBlock->notices.Put(c)) < 0)
	{
		if(GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			BREAK_ON_DEBUG();	// To trace the call stack, there may be deadlock on waiting for free notice slot
			return -EDEADLK;
		}
		Sleep(TIMER_SLICE_ms);
	}
#ifdef TRACE
	printf_s("Self notice %s[%d] in local fiber#%u(_%X_), state %s\t\n", noticeNames[c], c
		, fidPair.source, be32toh(fidPair.source), stateNames[pControlBlock->state]);
	if(r > 0)
		printf_s("--- merged ---\n");
#endif

	// in case loss of event we do not eliminate redundant notice
	::SetEvent(hEvent);
	return 0;
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

	if(psp1->passive)
	{
		dwMemorySize = ((sizeof(ControlBlock) + 7) >> 3 << 3)
			+ sizeof(LLSBackLog) + sizeof(BackLogItem) * (FSP_BACKLOG_SIZE - MIN_QUEUED_INTR);
	}
	else
	{
		int n = (psp1->sendSize - 1) / MAX_BLOCK_SIZE + (psp1->recvSize - 1) / MAX_BLOCK_SIZE + 2;
		// See also Init()
		dwMemorySize = ((sizeof(ControlBlock) + 7) >> 3 << 3)
			+ n * (((sizeof(ControlBlock::FSP_SocketBuf) + 7) >> 3 << 3) + MAX_BLOCK_SIZE);
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
	sprintf_s(szEventName, MAX_NAME_LENGTH, REVERSE_EVENT_PREFIX "%08X%p", idThisProcess, pControlBlock);
	// system automatically resets the event state to nonsignaled after a single waiting thread has been released
	hEvent = CreateEventA(& attrSecurity
		, FALSE // not manual-reset
		, FALSE // the initial state of the event object is nonsignaled
		, szEventName);	// (LPCTSTR)

#ifdef TRACE
	printf_s("ID of current process is %d, handle of the event is %p\n", idThisProcess, hEvent);
#endif
	if(hEvent == INVALID_HANDLE_VALUE || hEvent == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create event object for reverse synchronization");
		UnmapViewOfFile(pControlBlock);
		CloseHandle(hMemoryMap);
		return -EINTR;	// the event mechanism is actually software interrupt mechanism
	}

	if(psp1->passive)
		pControlBlock->Init(FSP_BACKLOG_SIZE);
	else
		pControlBlock->Init(psp1->sendSize, psp1->recvSize);
	//
	pControlBlock->milky = psp1->milky;
	pControlBlock->noEncrypt = psp1->noEncrypt;
	//
	pControlBlock->notices.SetHead(FSP_IPC_CannotReturn);
	//^only after the control block is successfully mapped into the memory space of LLS may it be cleared by LLS

	// could be exploited by ULA to make distinguishment of services
	memcpy(&context, psp1, sizeof(FSP_SocketParameter));
	pendingSendBuf = (BYTE *)psp1->welcome;
	pendingSendSize = psp1->len;

	return 0;
}



// Given
//	CommandNewSession & [_Out_]	the command context to be filled
//	FSP_ServiceCode				the service code to be passed
// Do
//	Fill in the command context and call LLS. The service code MUST be one that creates an LLS FSP socket
// Return
//	The DLL FSP socket created if succeeded,
//	NULL if failed.
CSocketItemDl * LOCALAPI CSocketItemDl::CallCreate(CommandNewSession & objCommand, FSP_ServiceCode cmdCode)
{
	objCommand.fiberID = fidPair.source;
	objCommand.idProcess = idThisProcess;
	objCommand.opCode = cmdCode;
	objCommand.hMemoryMap = (uint64_t)hMemoryMap;
	objCommand.dwMemorySize = dwMemorySize;
	//
	return Call(objCommand, sizeof(objCommand)) ? this : NULL;
}



// Return
//	true if having obtained the mutual-exclusive lock and having the session control block validated
//	false if either timed out in obtaining the lock or found that the session control block invalid
// Remark
//	Dispose the DLL FSP socket resource if to return false
bool CSocketItemDl::LockAndValidate()
{
	if(! WaitUseMutex())
		return false;

	if(pControlBlock == NULL)
	{
#ifndef NDEBUG
		printf_s("\nDescriptor#%p: event to be processed, but the Control Block is missing!\n", this);
#endif
		DisableAndNotify(FSP_NotifyReset, EBADF);
		return false;
	}

	if(InIllegalState())
	{
#ifndef NDEBUG
		printf_s(
			"\nDescriptor#%p, event to be processed, but the socket is in state %s[%d]?\n"
			, this
			, stateNames[pControlBlock->state], pControlBlock->state);
#endif
		RecycLocked();
		return false;
	}

	return true;
}



// The asynchronous, multi-thread friendly soft interrupt handler
void CSocketItemDl::WaitEventToDispatch()
{
	while(LockAndValidate())
	{
		FSP_ServiceCode notice = pControlBlock->notices.Pop();
		if(notice == NullCommand)
		{
			SetMutexFree();
			break;
		}

#ifdef TRACE
		printf_s("\nIn local fiber#%u(_%X_), state %s\tnotice: %s\n"
			, fidPair.source, be32toh(fidPair.source)
			, stateNames[pControlBlock->state], noticeNames[notice]);
#endif
		// If recycled or in the state not earlier than ToFinish, LLS should have recyle the session context mapping already
		if(notice == FSP_NotifyRecycled || notice >= FSP_NotifyToFinish)
			lowerLayerRecycled = 1;
		// Initially lowerLayerRecycled is 0 and it is never reset
		if(! IsInUse() && lowerLayerRecycled != 0)
		{
#ifndef NDEBUG
			printf_s(
				"\nEvent to be processed, but the socket has been recycled!?\n"
				"\tdescriptor=%p, state: %s[%d]\n"
				, this, stateNames[pControlBlock->state], pControlBlock->state);
#endif
			DisableAndNotify(FSP_NotifyReset, EBADF);
			break;
		}
		//
		FSP_Session_State s0;
		NotifyOrReturn fp1;
		switch(notice)
		{
		case FSP_NotifyListening:
			CancelTimeout();		// See also ::ListenAt
			SetMutexFree();
			break;
		case FSP_NotifyAccepting:	// overloaded callback for either CONNECT_REQUEST or MULTIPLY
			if(context.onAccepting != NULL && pControlBlock->HasBacklog())
				ProcessBacklogs();
			SetMutexFree();
			break;
		case FSP_NotifyAccepted:
			CancelTimeout();		// If any
			// Asychronous return of Connect2, where the initiator may cancel data transmission
			if(InState(CONNECT_AFFIRMING))
			{
				ToConcludeConnect();// SetMutexFree();
				break;
			}
			fp1 = (NotifyOrReturn) context.onAccepted;
			SetMutexFree();
			if(fp1 != NULL)
				((CallbackConnected)fp1)(this, &context);
			break;
		case FSP_NotifyMultiplied:	// See also @LLS::Connect()
			CancelTimeout();		// If any
			fidPair.source = pControlBlock->nearEndInfo.idALF;
			ProcessReceiveBuffer();
			if (!LockAndValidate())
				return;
			// To inherently chain WriteTo/SendInline with Multiply
			ProcessPendingSend();
			break;
		case FSP_NotifyDataReady:
			ProcessReceiveBuffer();	// SetMutexFree();
			break;
		case FSP_NotifyBufferReady:
			ProcessPendingSend();	// SetMutexFree();
			break;
		case FSP_NotifyToCommit:
			// See also FSP_NotifyDataReady, FSP_NotifyFlushed and CSocketItemDl::Shutdown()
			ProcessReceiveBuffer();	// SetMutexFree();
			if (!LockAndValidate())
				return;
			// Even if there's no callback function to accept data/flags (as in blocking receive mode)
			// the peerCommitted flag can be set if no further data to deliver
			if (!HasDataToDeliver())
				peerCommitted = 1;
			//
			if (InState(CLOSABLE) && initiatingShutdown)
			{
				SetState(PRE_CLOSED);
				Call<FSP_Shutdown>();
			}
			SetMutexFree();
			break;
		case FSP_NotifyFlushed:
			ProcessPendingSend();	// SetMutexFree();
			if (!LockAndValidate())
				return;
			//
			if (InState(CLOSABLE) && initiatingShutdown)
			{
				SetState(PRE_CLOSED);
				Call<FSP_Shutdown>();
				SetMutexFree();
			}
			else
			{
				fp1 = NULL;
				if (InState(COMMITTED) || pControlBlock->state >= CLOSABLE)
					fp1 = (NotifyOrReturn)InterlockedExchangePointer((PVOID *)& fpCommitted, fp1);
				CancelTimeout();// If any
				SetMutexFree();
				if (fp1 != NULL)
					fp1(this, FSP_NotifyFlushed, 0);
			}
			break;
		case FSP_NotifyToFinish:
			fp1 = context.onFinish;	// For security reason recycle MAY reset context
			if(initiatingShutdown)
			{
				RecycLocked();		// CancelTimer(); SetMutexFree();
				if (fp1 != NULL)
					fp1(this, FSP_NotifyRecycled, 0);
			}
			else
			{
				SetMutexFree();
				if (fp1 != NULL)
					fp1(this, FSP_NotifyToFinish, 0);
			}
			break;
		case FSP_NotifyRecycled:
			fp1 = context.onError;
			RecycLocked();		// CancelTimer(); SetMutexFree();
			if (!initiatingShutdown && fp1 != NULL)
				fp1(this, notice, -EINTR);
			return;
		case FSP_IPC_CannotReturn:
			s0 = pControlBlock->state;
			fp1 = context.onError;
			RecycLocked();		// CancelTimer(); SetMutexFree();
			if(fp1 == NULL)
				return;
			//
			if (s0 == LISTENING)
				fp1(this, FSP_Listen, -EIO);
			else if (s0 != CHALLENGING)
				fp1(this, (s0 == CLONING ? FSP_Multiply : InitConnection), -EIO);
			return;
		case FSP_MemoryCorruption:
		case FSP_NotifyOverflow:
		case FSP_NotifyTimeout:
		case FSP_NotifyNameResolutionFailed:
		case FSP_NotifyReset:
			DisableAndNotify(notice, EINTR);
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
	FSP_ADDRINFO_EX & nearEnd = socketItem->pControlBlock->nearEndInfo;
	if(nearAddr->_6to4.prefix == PREFIX_FSP_IP6to4)
	{
		nearEnd.InitUDPoverIPv4(psp1->ifDefault);
		nearEnd.idALF = nearAddr->idALF;
		nearEnd.ipi_addr = nearAddr->_6to4.ipv4;
	}
	else
	{
		nearEnd.InitNativeIPv6(psp1->ifDefault);
		*(PIN6_ADDR) & nearEnd = *(PIN6_ADDR)nearAddr;
	}
	// Application Layer Thread ID other than the first default would be set in the LLS

	return socketItem;
}



#ifndef _NO_LLS_CALLABLE
// Given
//	CommandToLLS &		const, the command context to pass to LLS
//	int					the size of the command context
// Return
//	true if the command has been put in the mailslot successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::Call(const CommandToLLS & cmd, int size)
{
	DWORD		nBytesReadWrite;		// number of bytes read/write last time
	return ::WriteFile(_mdService, & cmd, size, & nBytesReadWrite, NULL) != FALSE;
}
#endif



// Given
//	uint32_t		number of milli-seconds to wait till the timer shoot
// Return
//	true if the one-shot timer is registered successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::AddOneShotTimer(uint32_t dueTime)
{
	return (timer == NULL && ::CreateTimerQueueTimer(& timer, ::timerQueue
			, WaitOrTimeOutCallBack
			, this		// LPParameter
			, dueTime
			, 0
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE
		|| timer != NULL && ::ChangeTimerQueueTimer(::timerQueue, timer, dueTime, 0) != FALSE
		);
}



// Return
//	true if the repeative timer is registered successfully
//	false if it failed
bool CSocketItemDl::EnablePolling()
{
#ifndef NDEBUG
	const DWORD interval = 5000;	// hard-coded to 5 seconds per poll for easy to debug
#else
	const DWORD interval = TIMER_SLICE_ms;
#endif
	return (pollingTimer == NULL
		&&::CreateTimerQueueTimer(& pollingTimer, ::timerQueue
			, PollingTimedoutCallBack
			, this		// LPParameter
			, interval
			, interval
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE
		);
}



// Do
//	Try to cancel the registered polling timer
// Return
//	true if the polling timer is successfully canceled
//	false if it failed
bool CSocketItemDl::CancelPolling()
{
	HANDLE h = (HANDLE)InterlockedExchangePointer((PVOID *)& pollingTimer, NULL);
	return (h == NULL || ::DeleteTimerQueueTimer(::timerQueue, h, NULL) != FALSE);
}



// Do
//	Try to cancel the registered one-shot timer
// Return
//	true if the one-shot timer is successfully canceled
//	false if it failed
bool CSocketItemDl::CancelTimeout()
{
	HANDLE h = (HANDLE)InterlockedExchangePointer((PVOID *)& timer, NULL);
	return (h == NULL || ::DeleteTimerQueueTimer(::timerQueue, h, NULL) != FALSE);
}



// The function called back as soon as the one-shot timer counts down to 0
// See also Recycle
void CSocketItemDl::TimeOut()
{
	BOOLEAN b = TryAcquireSRWLockExclusive(&rtSRWLock);
	if (!IsInUse() || pControlBlock == NULL)
	{
		if(b)
			SetMutexFree();
		return;
	}

	assert(timer != NULL);
	if (!b)
	{
		::ChangeTimerQueueTimer(::timerQueue, timer, TIMER_SLICE_ms, 0);
		inUse = 0;	// Force WaitUseMutex to abort
		return;
	}

	if (! lowerLayerRecycled)
		Call<FSP_Recycle>();

	DisableAndNotify(FSP_NotifyTimeout, ETIMEDOUT);
}



void CSocketItemDl::PollingTimedout()
{
	if (!TryAcquireSRWLockExclusive(&rtSRWLock))
		return;	// Patiently wait the next time slice instead to spin here

	if (pControlBlock == NULL)
		return;
	if (!IsInUse() || InIllegalState())
		return;

#if (TRACE & TRACE_SLIDEWIN)
	printf_s("FSPSocket %p, Receive window: \n"
		"  (%u - %u), expected: %u\n"
		" Send window: \n"
		"  (%u - %u), limited: %u\n"
		, this
		, pControlBlock->recvWindowFirstSN
		, pControlBlock->recvWindowNextSN
		, pControlBlock->recvWindowExpectedSN
		, pControlBlock->sendWindowFirstSN
		, pControlBlock->sendWindowNextSN
		, pControlBlock->sendWindowLimitSN);
#endif
	// Receive takes precedence because receiving is to free resource
	if ((fpReceived != NULL || fpPeeked != NULL) && HasDataToDeliver())
	{
		ProcessReceiveBuffer();
		if (!TryAcquireSRWLockExclusive(&rtSRWLock))
			return;
	}
	//
	if ((fpSent != NULL || pendingSendBuf != NULL) && HasFreeSendBuffer())
		ProcessPendingSend();
	else
		SetMutexFree();
}



// For a prototype it does not worth the trouble to exploit hash table 
CSocketItemDl *	CSocketDLLTLB::HandleToRegisteredSocket(FSPHANDLE h)
{
	register CSocketItemDl *p = (CSocketItemDl *)h;
	for(register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		if (CSocketItemDl::socketsTLB.pSockets[i] == p)
			return ((p->pControlBlock == NULL || p->InIllegalState()) ? NULL : p);
	}
	//
	return NULL;
}



// The contructor of the Translation Look-aside Buffer of the DLL FSP socket items
CSocketDLLTLB::CSocketDLLTLB()
{
	InitializeSRWLock(& srwLock);
	countAllItems = 0;
	sizeOfWorkSet = 0;
	head = tail = NULL;
}



// To obtain a free slot from the TLB. Try to allocate a new item if no slot is registered with a valid item
// Return
//	The pointer to the DLL FSP socket if allocated successfully
//	NULL if failed
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
	}

	memset((BYTE *)item + sizeof(CSocketItem)
		, 0
		, sizeof(CSocketItemDl) - sizeof(CSocketItem));
	InitializeSRWLock(&item->rtSRWLock);
	// Are we confident that RTL_SRWLOCK_INIT is all zero
	// so assign to SRWLOCK_INIT is unneccessary?
	pSockets[sizeOfWorkSet++] = item;
	_InterlockedExchange8(& item->inUse, 1);

l_bailout:
	ReleaseSRWLockExclusive( & srwLock);
	return item;
}



// Given
//	CSocketItemDl *		the pointer to the DLL FSP socket
// Do
//	Try to put the socket in the list of the free socket items
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



// Given
//	ALFID_T		the application layer fiber ID of the connectio to find
// Return
//	The pointer to the FSP socket that matches the given ID
// Remark
//	The caller should check whether the returned socket is really in work by check the inUse flag
//	Performance is assumed acceptable
//	as this is a prototyped implementation which exploits linear search in a small set
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
static void AllowDuplicateHandle()
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
