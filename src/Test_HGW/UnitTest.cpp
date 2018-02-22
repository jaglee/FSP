// This program is a mixed test of FSP http and socks gateway server
//
#include "stdafx.h"
#include <assert.h>
#include "../FSP_HGW/defs.h"

static RequestPool requestPool;
static FSPHANDLE hFSP;

bool UnitTestRequestPoolInit()
{
	return requestPool.Init(2);
}

void UnitTestRequestPoolAlloc()
{
	PRequestPoolItem h1 = requestPool.AllocItem();
	assert(h1 != NULL);

	hFSP = CreateFSPHandle();
	if(hFSP == NULL)
		throw("Cannot create the FSP handle!");

	PRequestPoolItem h2 = requestPool.AllocItem(hFSP);
	assert(h2 != NULL);

	PRequestPoolItem h3 = requestPool.AllocItem();
	assert(h3 == NULL);
}


void UnitTestRequestPoolFind()
{
	PRequestPoolItem h2 = requestPool.FindItem(hFSP);
	assert(h2 != NULL);

	PRequestPoolItem h3 = requestPool.FindItem((FSPHANDLE)3);
	assert(h3 == NULL);
}


bool UnitTestRequestPoolFree()
{
	PRequestPoolItem h2 = requestPool.FindItem(hFSP);
	return requestPool.FreeItem(h2);
}



bool unit_test()
{
	try
	{
		if(! UnitTestRequestPoolInit())
			return false;
		UnitTestRequestPoolAlloc();
		UnitTestRequestPoolFind();
		if(! UnitTestRequestPoolFree())
			return false;
		return true;
	}
	catch(...)
	{
		return false;
	}
}