#include "defs.h"

// The pool is too small to exploit dual-linked queue

bool RequestPool::Init(int n)
{
	if(n <= 0)
		return false;
	//
	items = (SRequestPoolItem *)malloc(sizeof(SRequestPoolItem) * n);
	if(items == NULL)
		return false;

	for(register int i = 0; i < n; i++)
	{
		items[i].hFSP = NULL;
	}

	capacity = n;
	return true;
}


PRequestPoolItem RequestPool::AllocItem(FSPHANDLE h)
{

	for(register int i = 0; i < capacity; i++)
	{
		if(items[i].hFSP == NULL)
		{
			FSPControl(h, FSP_SET_EXT_POINTER, ulong_ptr(items + i));
			items[i].hFSP = h;
			return (items + i);
		}
	}
	//
	return NULL;
}



PRequestPoolItem RequestPool::AllocItem()
{
	for(register int i = 0; i < capacity; i++)
	{
		if(items[i].hFSP == NULL)
		{
			items[i].hFSP = (FSPHANDLE)(-1);
			return (items + i);
		}
	}
	//
	return NULL;
}



PRequestPoolItem RequestPool::FindItem(FSPHANDLE h)
{
	PRequestPoolItem p;
	FSPControl(h, FSP_GET_EXT_POINTER, (ulong_ptr) & p);
	//
	return (p == NULL || p->hFSP != h ? NULL : p);
}


// See also AllocItem
bool RequestPool::FreeItem(PRequestPoolItem p)
{
	int offset = p - this->items;
	
	if(offset % sizeof(SRequestPoolItem) != 0)
		return false;

	offset /= sizeof(SRequestPoolItem);

	if(offset < 0 || offset >= capacity)
		return false;

	if(p->hFSP != (FSPHANDLE *)(-1))
		FSPControl(p->hFSP, FSP_SET_EXT_POINTER, NULL);
	p->hFSP = NULL;
	return true;
}
