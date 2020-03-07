/*
 * Shared object to service FSP upper layer application in linux, the top-level control structure
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
#if defined(__MINGW32__)

# include "DllEntry.cpp"

#else

#include "FSP_DLL.h"

# define  POLLING_INTERVAL_MICROSECONDS 1000	// For HPET

// the id of the process that call the library
pid_t	CSocketItemDl::idThisProcess = 0;


#if defined(__linux__) || defined(__CYGWIN__)

#include <sys/un.h>

static	struct sockaddr_un addr;
static	int sdClient;

// Called by the default constructor only
void CSocketDLLTLB::Init()
{
	sdClient = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sdClient < 0)
	{
		perror("Cannot create AF_UNIX socket for sending");
		exit(-1);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVICE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	CSocketItemDl::SaveProcessId();
}

CSocketDLLTLB::~CSocketDLLTLB()
{
	// TODO: Delete the time-out timer
	//
	if (sdClient != 0 && sdClient != -1)
		close(sdClient);
}

#endif

// Return the number of microseconds elapsed since Jan 1, 1970 UTC (Unix epoch)
// Let the link-time-optimizer embed the code in the caller block
DllSpec
timestamp_t NowUTC()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec);
}



// Given
//	CommandNewSession	[_inout_]	the buffer to hold the name of the shared memory object
// Do
//	Initialize the IPC structure to call LLS
// Return
//	true if no error, false if failed
bool CSocketItemDl::InitLLSInterface(CommandNewSession & cmd)
{
	cmd.GetShmNameFrom(this);

	int hShm = shm_open(cmd.shm_name, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (hShm < 0)
	{
		perror("Cannot open the shared memory for read/write in ULA");
		return false;
	}

	if (ftruncate(hShm, dwMemorySize) < 0)
	{
		perror("Cannot set the size of the new created shared memory object");
		return false;
	}

	pControlBlock = (ControlBlock*)mmap(NULL, dwMemorySize, PROT_READ | PROT_WRITE, MAP_SHARED, hShm, 0);
	if (pControlBlock == MAP_FAILED)
	{
		perror("Cannot map the shared memory into address space of ULA");
		pControlBlock = NULL;
		return false;
	}
	close(hShm);
	mlock(pControlBlock, dwMemorySize);
	
	return true;
}



// Given
//	CommandNewSession	[not used for Linux platform]
// Do
//	Enable ULA-LLS interaction
// Return
//	true if no error, false if failed
bool CSocketItemDl::EnableLLSInteract(CommandNewSession &)
{
	struct sockaddr_un addr;
	sdPipe = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sdPipe < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the socket to communicate with LLS");
		return false;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVICE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    if (connect(sdPipe, (const sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0)
    {
		SOCKET h = _InterlockedExchange(&sdPipe, INVALID_SOCKET);
		close(h);
		return false;
    }

	return (pthread_create(&hThreadWait, NULL, NoticeHandler, this) == 0);
}



// Given
//	uint32_t		number of milliseconds to wait till the timer shoot
// Return
//	true if the one-shot timer is registered successfully
//	false if it failed
// Remark
//	Only support multiple of thousand milliseconds.
bool LOCALAPI CSocketItemDl::AddOneShotTimer(uint32_t dueTime)
{
	struct itimerspec its;
	struct sigevent sigev;
	sigev.sigev_notify = SIGEV_THREAD;
	sigev.sigev_value.sival_ptr = this;	
	sigev.sigev_notify_function = TimeOutHandler;
	sigev.sigev_notify_attributes = NULL;
	if (timer_create(CLOCK_MONOTONIC, &sigev, &timer) != 0)
	{
		perror("Cannot create the polling timer");
		return false;
	}

	its.it_value.tv_sec = dueTime / 1000;
	its.it_value.tv_nsec = (dueTime % 1000) * 1000000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timer_settime(timer, 0, &its, NULL) != 0)
	{
		perror("Cannot set the polling timer");
		timer_delete(timer);
		timer = 0;
		return false;
	}

	return true;
}



// Do
//	Try to cancel the registered one-shot timer
// Return
//	true for this implementation
bool CSocketItemDl::CancelTimeout()
{
	timer_t h = _InterlockedExchange(&timer, 0);
	return (h != 0 && timer_delete(h) == 0);
}

#endif