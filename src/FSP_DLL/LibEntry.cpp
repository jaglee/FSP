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

#if defined(__linux__) || defined(__CYGWIN__)

# ifdef __linux__
#  include <linux/un.h>
# else
#  include <sys/un.h>
# endif

// Called by the default constructor only
void CSocketDLLTLB::Init()
{
	struct sockaddr_un addr;
	sdPipe = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sdPipe < 0)
	{
		perror("Cannot create AF_UNIX socket for sending");
		exit(-1);
	}

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVICE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	if (connect(sdPipe, (const sockaddr*)&addr, sizeof(addr)) < 0)
	{
		perror("Cannot connect with LLS");
		exit(-2);
	}
}


inline
bool CSocketDLLTLB::InitThread()
{
	if(hThreadWait != 0)
		return true;

	// only after the required fields initialized may the listener thread started
	// fetch message from remote endpoint and deliver them to upper layer application
	if(pthread_create(&hThreadWait, NULL, NoticeHandler, this) != 0)
	{
		perror("Cannot create the thread to handle LLS's soft interrupt");
		return false;
	}
	pthread_detach(hThreadWait);

	return true;
}



// As the waiting thread is waiting on the pipe, closing the pipe
// will automatically make the thread terminate gracefully
CSocketDLLTLB::~CSocketDLLTLB()
{
	HPIPE_T sd = (HPIPE_T)_InterlockedExchange(&sdPipe, INVALID_SOCKET);
	if (sd != INVALID_SOCKET)
	{
		printf("To shutdown socket %d\n", sd);
		shutdown(sd, SHUT_RDWR);
		close(sd);
	}
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



// Do
//	Initialize the IPC structure to call LLS
// Return
//	true if no error, false if failed
bool CSocketItemDl::InitSharedMemory()
{
	snprintf(shm_name, sizeof(shm_name), SHARE_MEMORY_PREFIX "%p", (void *)this);
	shm_name[sizeof(shm_name) - 1] = 0;

	int hShm = shm_open(shm_name, O_RDWR | O_CREAT | O_TRUNC, 0777);
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



void CSocketItemDl::CopyFatMemPointo(CommandNewSession &cmd)
{
	memcpy(cmd.shm_name, this->shm_name, sizeof(shm_name));
	cmd.dwMemorySize = dwMemorySize;
}



bool CSocketItemDl::StartPolling()
{
	if (!socketsTLB.InitThread())
		return false;

	timeOut_ns = TRANSIENT_STATE_TIMEOUT_ms * 1000000ULL;
	timeLastTriggered = NowUTC();
	uint32_t dueTime = TIMER_SLICE_ms;

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
	its.it_interval.tv_nsec = POLLING_INTERVAL_MICROSECONDS * 1000;

	if (timer_settime(timer, 0, &its, NULL) != 0)
	{
		perror("Cannot set the polling timer");
		timer_delete(timer);
		timer = 0;
		return false;
	}

	return true;
}



// It makes no difference to send a message or a stream of octets at ULA
int CSocketDLLTLB::SendToPipe(const void *pMsg, int n)
{
	return send(sdPipe, pMsg, n, 0);
}


// For ULA, size of what to receive from LLS is fixed
bool CSocketDLLTLB::GetNoticeFromPipe(SNotification *buf)
{
	int r = recv(sdPipe, buf, sizeof(SNotification), 0);
	if(r < 0)
	{
		perror("Failed to get notification from LLS");
		return false;
	}
	return (r > 0);
}



bool CSlimThreadPool::NewThreadFor(CSlimThreadPoolItem* newItem)
{
	if (pthread_create(&newItem->hThread, NULL, ThreadWorkBody, this) != 0)
	{
		perror("Cannot create new thread for the thread pool");
		return false;
	}
	pthread_detach(newItem->hThread);

	return true;
}

// UNRESOLVED! is there race condition on detecting liveness of the old thread and creating the new thread?
#endif
