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

#pragma comment(lib, "Ws2_32.lib")


void CSocketDLLTLB::Init() { }
CSocketDLLTLB::~CSocketDLLTLB() {}

static DWORD		idThisProcess;	// the id of the process that attaches this DLL
static SOCKET		sdPipe;
static HANDLE		timerQueue;		// = NULL;
static pthread_t	hThreadWait;

static void AllowDuplicateHandle();
static bool CreateExecUnitPool();
static void DestroyExecUnitPool();


extern "C" 
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	// to maintain thread local storage
	if (dwReason == DLL_PROCESS_ATTACH)
	{
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
			return false;
		}

		sdPipe = socket(AF_INET, SOCK_STREAM, 0);
		if (sdPipe < 0)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot create the socket to communicate with LLS");
			DeleteTimerQueueEx(timerQueue, NULL);
			return FALSE;
		}

		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htobe16(DEFAULT_FSP_UDPPORT);
		addr.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
		memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
		if (connect(sdPipe, (const sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0)
		{
l_bailout:
			DeleteTimerQueueEx(timerQueue, NULL);
			closesocket(sdPipe);
			sdPipe = INVALID_SOCKET;
			return FALSE;
		}

		DWORD optval = 1;
		setsockopt(sdPipe, IPPROTO_TCP, TCP_NODELAY, (const char*)&optval, sizeof(optval));
		setsockopt(sdPipe, SOL_SOCKET, SO_DONTLINGER, (const char*)&optval, sizeof(optval));

		if (!CreateExecUnitPool())
			goto l_bailout;

		hThreadWait = CreateThread(NULL // LPSECURITY_ATTRIBUTES, get a default security descriptor inherited
			, 0							// dwStackSize, uses the default size for the executables
			, CSocketItemDl::WaitNoticeCallBack		// LPTHREAD_START_ROUTINE
			, CSocketItemDl::headOfInUse			// LPVOID lpParameter
			, 0			// DWORD dwCreationFlags: run on creation
			, NULL);	// LPDWORD lpThreadId, not returned here.
		if (hThreadWait == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot create the thread to handle communication with LLS");
			DestroyExecUnitPool();
			goto l_bailout;
		}

		idThisProcess = GetCurrentProcessId();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		DeleteTimerQueueEx(timerQueue, NULL);
		TerminateThread(hThreadWait, 0);
		DestroyExecUnitPool();
		shutdown(sdPipe, SD_BOTH);
		closesocket(sdPipe);
		WSACleanup();
	}
	//
	return TRUE;
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



SOCKET& CSocketItemDl::SDPipe() { return sdPipe; }


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




// Given
//	uint32_t		number of milliseconds to wait till the timer shoots for the first time
// Return
//	true if the timer is registered successfully
//	false if it failed
bool CSocketItemDl::AddTimer(uint32_t dueTime)
{
	return ((timer == NULL && ::CreateTimerQueueTimer(& timer, ::timerQueue
			, TimeOutCallBack
			, this		// LPParameter
			, dueTime
#ifdef TRACE
			, 8000		// for convenience of debugging
#else
			, TIMER_SLICE_ms
#endif
			, WT_EXECUTEINTIMERTHREAD
			) != FALSE)
		|| (timer != NULL && ::ChangeTimerQueueTimer(::timerQueue, timer, dueTime, TIMER_SLICE_ms) != FALSE)
		);
}



// Given
//	UCommandToLLS *		const, the command context to pass to LLS
//	int					the size of the command context
// Return
//	true if the command has been put in the mailslot successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::Call(const UCommandToLLS* pCmd, int n)
{
	commandLastIssued = pCmd->sharedInfo.opCode;
	return (send(sdPipe, (char*)pCmd, n, 0) > 0);
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



/**
 * Implementation dependent: thread pool to handle soft interrupt of LLS 
 */
static PTP_POOL				pool;	// = NULL;
static PTP_CLEANUP_GROUP	cleanupgroup; // = NULL;

TP_CALLBACK_ENVIRON	CSocketItemDl::envCallBack;

static bool CreateExecUnitPool()
{
	//FILETIME FileDueTime;
	//ULARGE_INTEGER ulDueTime;
	//PTP_TIMER timer = NULL;
	BOOL bRet = FALSE;

	InitializeThreadpoolEnvironment(&CSocketItemDl::envCallBack);
	pool = CreateThreadpool(NULL);
	if (pool == NULL)
	{
		printf_s("CreateThreadpool failed. LastError: %u\n", GetLastError());
		return false;
	}

	SetThreadpoolThreadMaximum(pool, MAX_WORKING_THREADS);
	bRet = SetThreadpoolThreadMinimum(pool, 1);
	if (!bRet)
	{
		printf_s("SetThreadpoolThreadMinimum failed. LastError: %d\n", GetLastError());
		CloseThreadpool(pool);
		return false;
	}

	cleanupgroup = CreateThreadpoolCleanupGroup();
	if (cleanupgroup == NULL)
	{
		printf_s("CreateThreadpoolCleanupGroup failed. LastError: %d\n", GetLastError());
		CloseThreadpool(pool);
		return false;
	}

	SetThreadpoolCallbackPool(&CSocketItemDl::envCallBack, pool);
	SetThreadpoolCallbackCleanupGroup(&CSocketItemDl::envCallBack, cleanupgroup, NULL);

	return true;
}


static void DestroyExecUnitPool()
{
	if (cleanupgroup == NULL)
		return;
	CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
	CloseThreadpoolCleanupGroup(cleanupgroup);
}
