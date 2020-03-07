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


#if defined(__linux__)

#include <sys/un.h>

static	struct sockaddr_un addr;
static	int sdClient;

// Called by the default constructor only
void CSocketDLLTLB::Init()
{
	sdClient = socket(AF_UNIX, SOCK_DGRAM, 0); // SOCK_SEQPACKET need listen and accept
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

# ifndef _NO_LLS_CALLABLE
// Given
//	CommandToLLS &		const, the command context to pass to LLS
//	int					the size of the command context
// Return
//	true if the command has been put in the mailslot successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::Call(const CommandToLLS & cmd, int size)
{
#ifdef TRACE
	printf("Fiber#%u %d bytes to send to LLS\n", cmd.fiberID, size);
#endif
	int r = (int)sendto(sdClient, &cmd, size, 0, (struct sockaddr*)&addr, sizeof(addr));
	commandLastIssued = cmd.opCode;
	if (r < 0)
		perror("Cannot send the command to LLS through the domain socket");
	return (r >= 0);
}
# endif

#elif defined(__CYGWIN__)

# include <sys/msg.h>
  ALIGN(sizeof(long long)) const char $_FSP_KEY[8] = "FSP*KEY";
# define FSP_MQ_KEY      (*(uint64_t *)($_FSP_KEY))

static 	key_t	mqKey;
static	int		msqid;

// Called by the default constructor only
void CSocketDLLTLB::Init()
{
    mqKey = (key_t)FSP_MQ_KEY;
    msqid = msgget(mqKey, O_WRONLY);
    if(msqid < 0)
    {
        perror("Cannot abtain the XSI message queue for send");
        exit(-1);
    }

	CSocketItemDl::SaveProcessId();
}

CSocketDLLTLB::~CSocketDLLTLB() { /* no descriptor to close */ }


# ifndef _NO_LLS_CALLABLE
// Given
//	CommandToLLS &		const, the command context to pass to LLS
//	int					the size of the command context
// Return
//	true if the command has been put in the mailslot successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::Call(const CommandToLLS & cmd, int size)
{
#ifdef TRACE
	printf("Fiber#%u %d bytes to send to LLS\n", cmd.fiberID, size);
#endif
    int r = msgsnd(msqid, &cmd, size - sizeof(long), IPC_NOWAIT);
    if(r < 0)
		perror("Cannot send the command to LLS through the XSI message queue");
	return (r == 0);
}
# endif

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
//	Enable ULA-LLS interaction, polling mode
// Return
//	true if no error, false if failed
bool CSocketItemDl::EnableLLSInteract(CommandNewSession &)
{
	struct itimerspec its;
	struct sigevent sigev;
	sigev.sigev_notify = SIGEV_THREAD;
	sigev.sigev_value.sival_ptr = this;	
	sigev.sigev_notify_function = PollingHandler;
	sigev.sigev_notify_attributes = NULL;
	if (timer_create(CLOCK_MONOTONIC, &sigev, &pollingTimer) != 0)
	{
		perror("Cannot create the polling timer");
		return false;
	}
	timeOut_ns = INT64_MAX;

	// Here we wait at least three timer slices to make sure other initialization is ready
	// assume timer-slice is less than one third of a second.
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = TIMER_SLICE_ms * 3000000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = POLLING_INTERVAL_MICROSECONDS * 1000;

	if (timer_settime(pollingTimer, 0, &its, NULL) != 0)
	{
		perror("Cannot set the polling timer");
		timer_delete(pollingTimer);
		return false;
	}

	timeOut_ns = int64_t(TRANSIENT_STATE_TIMEOUT_ms) * 1000000;
	return true;
}



// The actual polling timer handler
void CSocketItemDl::WaitOrTimeOutCallBack()
{
	timer_t h = LCKREAD(pollingTimer);
	if (h == 0)
		return;
	// The timer might have been 'RecycleSimply', and it causes segment fault
	// on calling timer_getoverrun given timer id 0
	int32_t elapsed = (int32_t)timer_getoverrun(h);
	if(elapsed++ < 0)	// but it should not happen!
		elapsed = 1;
	// assume it would not overflow: overrun for 24 days is just too terriable!
	elapsed *= POLLING_INTERVAL_MICROSECONDS * 1000;
#ifdef TRACE
	if(timeOut_ns <= elapsed)
		printf("It is to time out, time remains = %" PRId64 "ns, elapsed = %dns\n", timeOut_ns, elapsed);
#endif
	if((timeOut_ns -= elapsed) <= 0)
		TimeOut();
	else
		WaitEventToDispatch();
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
	if(pollingTimer == 0)
		return false;
	timeOut_ns = int64_t(dueTime) * 1000000;
	return true;
}



// Do
//	Try to cancel the registered one-shot timer
// Return
//	true for this implementation
bool CSocketItemDl::CancelTimeout()
{
	timeOut_ns = INT64_MAX;
	return true;
}

#endif