/*
 * DLL to service FSP upper layer application, the DLL entry point and the top-level control structure
 * How does it work
 * - Lower-Layer-Service process and DLL exchange the FSP state information via the shared memory
 * - ULA calls the FSP services through DLL
 * - emulate hardware interrupt vector mechanism
 * - For Windows:
 * -- When LLS is created the global shared FSP mailslot is created
 * -- When DLL is attached, a handle to the global FSP mailslot is obtained
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

#ifndef __MINGW32__
#pragma comment(lib, "Ws2_32.lib")
#endif

static DWORD		idThisProcess;	// the id of the process that attaches this DLL
static HANDLE		timerQueue;		// = NULL;

static void AllowDuplicateHandle();


extern "C" 
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	// to maintain thread local storage
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (CSocketItemDl::socketsTLB.sdPipe == INVALID_HANDLE_VALUE)
			return FALSE;

		WSADATA wsaData;
		// initialize windows socket support
		if (WSAStartup(0x202, &wsaData) < 0)
			return FALSE;

		DisableThreadLibraryCalls(hInstance);
		AllowDuplicateHandle();
#ifdef TRACE
		AllocConsole();
#endif
		timerQueue = CreateTimerQueue();
		if (timerQueue == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot create the timer queue for repetitive tasks");
			return FALSE;
		}

		idThisProcess = GetCurrentProcessId();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if(timerQueue != NULL)
			DeleteTimerQueueEx(timerQueue, NULL);
		WSACleanup();
	}
	//
	return TRUE;
}



void CSocketDLLTLB::Init()
{
	do
	{
		sdPipe = CreateFile(
			SERVICE_NAMED_PIPE,				// pipe name
			GENERIC_READ | GENERIC_WRITE,	// read and write access
			0,								// no sharing
			NULL,							// default security attributes
			OPEN_EXISTING,					// opens existing pipe
			FILE_FLAG_OVERLAPPED,			// asynchronous mode
			NULL);							// no template file

		if (sdPipe != INVALID_HANDLE_VALUE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs.
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			REPORT_ERROR_ON_TRACE();
			return;
		}
		// All pipe instances are busy, so wait for half a minute
		if (WaitNamedPipe(SERVICE_NAMED_PIPE, 30000))
			continue;
	} while (GetLastError() == ERROR_PIPE_BUSY);
	// default byte mode works.
	if (sdPipe == INVALID_HANDLE_VALUE)
	{
		REPORT_ERROR_ON_TRACE();
		return;
	}
	// The pipe connected; change to message-read mode.
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(
		sdPipe,		// pipe handle
		&dwMode,	// new pipe mode
		NULL,		// don't set maximum bytes
		NULL))		// don't set maximum time
	{
		REPORT_ERROR_ON_TRACE();
		CloseHandle(sdPipe);
		sdPipe = INVALID_HANDLE_VALUE;
		return;
	}
}


inline
bool CSocketDLLTLB::InitThread()
{
	if (hThreadWait != NULL)
		return true;

	hThreadWait = CreateThread(NULL // LPSECURITY_ATTRIBUTES, get a default security descriptor inherited
		, 0							// dwStackSize, uses the default size for the executables
		, WaitNoticeCallBack		// LPTHREAD_START_ROUTINE
		, this						// LPVOID lpParameter
		, 0			// DWORD dwCreationFlags: run on creation
		, NULL);	// LPDWORD lpThreadId, not returned here.
	if (hThreadWait == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the thread to handle communication with LLS");
		CloseHandle(sdPipe);
		sdPipe = INVALID_HANDLE_VALUE;
		return false;
	}
	return true;
}



// As the waiting thread is waiting on the pipe, closing the pipe
// will automatically make the thread terminate gracefully
CSocketDLLTLB::~CSocketDLLTLB()
{
	HANDLE h = (HANDLE)_InterlockedExchangePointer(&sdPipe, INVALID_HANDLE_VALUE);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
}



// Return the number of microseconds elapsed since Jan 1, 1970 UTC (Unix epoch)
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




// Do
//	Initialize the IPC structure to call LLS
// Return
//	true if no error, false if failed
bool CSocketItemDl::InitSharedMemory()
{
	hMemoryMap = CreateFileMapping(INVALID_HANDLE_VALUE	// backed by the system paging file
		, NULL	// not inheritable
		, PAGE_READWRITE | SEC_COMMIT
		, 0, dwMemorySize	// file mapping size, we limit it to less than 4GB
		, NULL);
	if (hMemoryMap == INVALID_HANDLE_VALUE || hMemoryMap == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create shared memory object by CreateFileMapping");
		return false;	// return -ENOENT;
	}

	// UNRESOLVED! passive socket and initiative socket are of different memory footprint?
	// if they are, there should be more AllocItem() function
	pControlBlock = (ControlBlock*)MapViewOfFile(hMemoryMap
		, FILE_MAP_ALL_ACCESS
		, 0, 0, dwMemorySize);
	if (pControlBlock == NULL)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot take use of shared memory object by MapViewOfFile");
		CloseHandle(hMemoryMap);
		return false;	// return -ENOMEM;
	}

	return true;
}



void CSocketItemDl::CopyFatMemPointo(CommandNewSession& cmd)
{
	cmd.hMemoryMap = (uint64_t)hMemoryMap;
	cmd.idProcess = idThisProcess;
	cmd.dwMemorySize = dwMemorySize;
}




bool CSocketItemDl::StartPolling()
{
	timeOut_ns = TRANSIENT_STATE_TIMEOUT_ms * 1000000ULL;
	timeLastTriggered = NowUTC();

	if (!socketsTLB.InitThread())
		return false;

	uint32_t dueTime = TIMER_SLICE_ms;
	return ((timer == NULL && ::CreateTimerQueueTimer(& timer, ::timerQueue
			, TimeOutCallBack
			, this		// LPParameter
			, dueTime
#ifdef TRACE_TIMER
			, 8000		// for convenience of debugging
#else
			, TIMER_SLICE_ms
#endif
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE)
		|| (timer != NULL && ::ChangeTimerQueueTimer(::timerQueue, timer, dueTime, TIMER_SLICE_ms) != FALSE)
		);
}



void CSocketItemDl::RecycleSimply()
{
	timer_t h;
	if ((h = (timer_t)_InterlockedExchangePointer(&timer, 0)) != 0)
	{
		::DeleteTimerQueueTimer(::timerQueue, h, INVALID_HANDLE_VALUE);
		socketsTLB.FreeItem(this);
	}
}



// Given
//	const void *	message to send
//	int				size of the message in octets
// Return
//	positive if the result is the number of octets sent out
//	negative if the result is the error number
int CSocketDLLTLB::SendToPipe(const void* pMsg, int n)
{
	OVERLAPPED overlapped;
	DWORD cbTransfer;
	bzero(&overlapped, sizeof(OVERLAPPED));
	BOOL b = WriteFile(
		sdPipe,			// pipe handle 
		pMsg,			// message 
		n,				// message length 
		&cbTransfer,	// bytes written 
		&overlapped);
	if (b)
		return cbTransfer;
	int r = GetLastError();
	if (r != ERROR_IO_PENDING)
		return -r;
	if (!GetOverlappedResult(sdPipe, &overlapped, &cbTransfer, TRUE))
		return -(int)GetLastError();
	return cbTransfer;
}



// Given
//	SNotification *		the buffer to hold LLS's notification
// Return
//	true if a full notification message was successfully received
//	false if it failed
bool CSocketDLLTLB::GetNoticeFromPipe(SNotification *pSig)
{
	OVERLAPPED overlapped;
	DWORD cbTransfer;
	do
	{
		bzero(&overlapped, sizeof(OVERLAPPED));
		if (ReadFile(sdPipe, pSig, sizeof(SNotification), &cbTransfer, &overlapped))
			return true;
		int r = GetLastError();
		if (r != ERROR_IO_PENDING)
			return false;
		if (!GetOverlappedResult(sdPipe, &overlapped, &cbTransfer, TRUE))
			return false;
	} while (cbTransfer == 0);
	//
	assert(cbTransfer == sizeof(SNotification));
	return true;
}



bool CSlimThreadPool::NewThreadFor(CSlimThreadPoolItem* newItem)
{
	newItem->hThread =
		CreateThread(NULL		// Default security descriptor inherited
			, 0					// dwStackSize, uses the default size for the executables
			, ThreadWorkBody	// LPTHREAD_START_ROUTINE
			, newItem			// LPVOID lpParameter
			, 0					// DWORD dwCreationFlags: run on creation
			, NULL);			// LPDWORD lpThreadId, not returned here.
	return (newItem->hThread != NULL);

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
        printf("AllocateAndInitializeSid Error %d\n", (int)GetLastError());
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
        printf("SetEntriesInAcl Error %d\n", (int)GetLastError());
#endif
        goto Cleanup;
    }
 
    if (! InitializeSecurityDescriptor(& sd, SECURITY_DESCRIPTOR_REVISION)) 
    {  
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %d\n", (int)GetLastError());
#endif
        goto Cleanup; 
    } 
 
    // Add the ACL to the security descriptor. 
    if (! SetSecurityDescriptorDacl(& sd, 
            TRUE,     // bDaclPresent flag   
            pACL, 
            FALSE))   // not a default DACL 
    {  
        printf("SetSecurityDescriptorDacl Error %d\n", (int)GetLastError());
        goto Cleanup; 
    } 

	if(! SetUserObjectSecurity(GetCurrentProcess()
		, & SIRequested
		, & sd))
	{
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %d\n", (int)GetLastError());
#endif
		//UNRESOLVED! is it a recoverable error or a fatal?
	}

Cleanup:
	if(pServiceSID)
		FreeSid(pServiceSID);
	if(pOwnerSID)
		FreeSid(pOwnerSID);
}



// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(const char * fileName, int lineNo, const char *funcName, const char *s1)
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
