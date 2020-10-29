/*
 * Implement the RequestPool class in FSP http accelerator, SOCKS gateway and tunnel server
 *
    Copyright (c) 2017, Jason Gao
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

#include <memory.h>
#include "defs.h"

// The pool is too small to be bothered to exploit dual-linked queue

bool RequestPool::Init(int n)
{
	if(n <= 0)
		return false;
	//
	size_t requestedSize = sizeof(SRequestPoolItem) * n;
	items = (SRequestPoolItem *)malloc(requestedSize);
	if(items == NULL)
		return false;

	memset(items, 0, requestedSize);

	capacity = n;
#ifdef _DEBUG_PEEK
	printf("Maximum %d threads may be forked\n", n);
#endif
	return true;
}



PRequestPoolItem RequestPool::AllocItem(FSPHANDLE h)
{

	for(register int i = 0; i < capacity; i++)
	{
		if (_InterlockedCompareExchange((long *)&items[i].hSocket, SOCKET_ERROR, 0) == 0)
		{
			FSPControl(h, FSP_SET_EXT_POINTER, ULONG_PTR(items + i));
			items[i].hFSP = h;
			return (items + i);
		}
	}
	//
	return NULL;
}



// For a prototype application, it seems not worth to exploit more complicate data structure
PRequestPoolItem RequestPool::AllocItem()
{
	for(register int i = 0; i < capacity; i++)
	{
		if(_InterlockedCompareExchange((long *)&items[i].hSocket, SOCKET_ERROR, 0) == 0)
			return (items + i);
	}
	//
	return NULL;
}



PRequestPoolItem RequestPool::FindItem(FSPHANDLE h)
{
	for(register int i = 0; i < capacity; i++)
	{
		if(items[i].hFSP == h)
			return (items + i);
	}
	return NULL;
}



// See also AllocItem
bool RequestPool::FreeItem(PRequestPoolItem p)
{
	int offset = int((octet *)p - (octet *)this->items);
	if(offset % sizeof(SRequestPoolItem) != 0)
		return false;

	offset /= sizeof(SRequestPoolItem);

	if(offset < 0 || offset >= capacity)
		return false;

	if(p->hSocket && p->hSocket != (SOCKET)SOCKET_ERROR)
		closesocket(p->hSocket);

	memset(p, 0, sizeof(SRequestPoolItem));
	return true;
}
