/*
 * Slim thread pool tailed to provide service for FSP DLL
 *
	Copyright (c) 2020, Jason Gao
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


CSlimThreadPool::CSlimThreadPool()
{
	bzero(items, sizeof(CSlimThreadPoolItem) * SLIM_THREAD_POOL_SIZE);
}


// To make life easier for this conceptual prototype a simple linear search is applied
bool CSlimThreadPool::ScheduleWork(CSocketItemDl *obj, void (CSocketItemDl::*fn)())
{
#ifdef _NO_LLS_CALLABLE
	static int successCount;
#endif
	for(int i = 0; i < SLIM_THREAD_POOL_SIZE; i++)
	{
		CSlimThreadPoolItem& r = items[i];
		void* savedContext = _InterlockedCompareExchangePointer((PVOID*)&r.contextWorkingOn, obj, NULL);
		if (savedContext == NULL)
		{
			if (r.fpWork == NULL && (r.hThread != 0 || NewThreadFor(&r)))
			{
#ifdef _NO_LLS_CALLABLE
				printf_s("%s called successfully %d times\n", __func__, successCount++);
#endif
				r.fpWork = fn;
				return true;
			}
			r.contextWorkingOn = (CSocketItemDl *)savedContext;
		}
	}
	return false;
}



void CSlimThreadPoolItem::LoopWaitJob()
{
	CSocketItemDl* pSocket;
	do
	{
		pSocket = (CSocketItemDl*)_InterlockedExchangePointer((PVOID*)&contextWorkingOn, NULL);
		if (pSocket == NULL)
		{
			Sleep(TIMER_SLICE_ms);
			continue;
		}
		// This is actually a spin-lock: 
		if (fpWork == NULL)
		{
			contextWorkingOn = pSocket;
			continue;
		}
		(pSocket->*fpWork)();
		//
		fpWork = NULL;
	} while (true);
}
