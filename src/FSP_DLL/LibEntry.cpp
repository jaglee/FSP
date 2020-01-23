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
#include "FSP_DLL.h"

const int POLLING_INTERVAL_MICROSECONDS = 1000;	// HPET

// the id of the process that call the library
pid_t	CSocketItemDl::idThisProcess = 0;

static	mqd_t	mqdes;



// Called by the default constructor only
void CSocketDLLTLB::Init()
{
	mqdes = mq_open(SERVICE_MAILSLOT_NAME, O_WRONLY);
	if (mqdes == (mqd_t)-1)
	{
		perror("Cannot open the message queue");
		exit(-1);
	}

	CSocketItemDl::SaveProcessId();
}



CSocketDLLTLB::~CSocketDLLTLB()
{
	// TODO: Delete the time-out timer
	//
	if (mqdes != 0 && mqdes != (mqd_t)-1)
		mq_close(mqdes);
}


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
//	CommandNewSession	[_inout_]	the buffer to hold the name of the event
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
	if (pControlBlock == NULL)
	{
		perror("Cannot map the shared memory in server");
		return false;
	}
	close(hShm);
	mlock(pControlBlock, dwMemorySize);

	struct itimerspec its;
	struct sigevent sigev;
	sigev.sigev_notify = SIGEV_THREAD;
	sigev.sigev_value.sival_ptr = this;
	sigev.sigev_notify_function = PollingNotices;
	sigev.sigev_notify_attributes = NULL;
	if (timer_create(CLOCK_MONOTONIC, &sigev, &pollingTimer) != 0)
	{
		perror("Cannot create the polling timer");
		return false;
	}

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = POLLING_INTERVAL_MICROSECONDS * 1000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	if (timer_settime(pollingTimer, 0, &its, NULL) != 0)
	{
		perror("Cannot set the polling timer");
		timer_delete(pollingTimer);
		return false;
	}

	return true;
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
	int r = mq_send(mqdes, (const char *)&cmd, size, 0);
	if (r != 0)
		perror("Cannot send the command to LLS through the message queue");
	return (r == 0);
}
#endif



// Given
//	uint32_t		number of milliseconds to wait till the timer shoot
// Return
//	true if the one-shot timer is registered successfully
//	false if it failed
bool LOCALAPI CSocketItemDl::AddOneShotTimer(uint32_t dueTime)
{
	struct itimerspec its;

	if (timer == 0)
	{
		struct sigevent sigev;
		// pthread_attr_t tattr;
		// pthread_attr_init(&tattr);
		sigev.sigev_notify = SIGEV_THREAD;
		sigev.sigev_value.sival_ptr = this;
		sigev.sigev_notify_function = TimeOutCallBack;
		sigev.sigev_notify_attributes = NULL;
		// Or with CAP_WAKE_ALARM capability, to set a timer against CLOCK_BOOTTIME_ALARM?
		// it is assumed that the clock is still while system is suspended, CLOCK_BOOTTIME (since Linux 2.6.12)
		int k = timer_create(CLOCK_MONOTONIC, &sigev, &timer);
		// pthread_attr_destroy(&tattr)
		if (k == -1)
			return false;
	}

	its.it_value.tv_sec = dueTime / 1000;
	its.it_value.tv_nsec = dueTime % 1000 * 1000000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timer_settime(timer, 0, &its, NULL) == 0)
		return true;

	timer_delete(timer);
	timer = 0;
	return false;
}



// Do
//	Try to cancel the registered one-shot timer
// Return
//	true if the one-shot timer is successfully canceled
//	false if it failed
bool CSocketItemDl::CancelTimeout()
{
	timer_t h;
	if ((h = (timer_t)_InterlockedExchange(&timer, 0)) != 0)
		return (timer_delete(h) == 0);
	return true;
}



// Unlike Free, Recycle-locked does not destroy the control block
// so that the DLL socket may be reused on connection resumption
// assume the socket has been locked
int CSocketItemDl::RecycLocked()
{
	CancelTimeout();

	socketsTLB.FreeItem(this);

	SetMutexFree();
	return 0;
}



// Make sure resource is kept until other threads leave critical section
// Does NOT waits for all callback functions to complete before returning
// in case of deadlock when the function itself is called in some call-back function
void CSocketItemDl::Free()
{
	CancelTimeout();

	socketsTLB.FreeItem(this);

	CSocketItem::Destroy();
	memset((octet *)this + sizeof(CSocketItem), 0, sizeof(CSocketItemDl) - sizeof(CSocketItem));
}
