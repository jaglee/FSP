// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <assert.h>

#include "../FSP_DLL/FSP_DLL.h"

#define _CRT_RAND_S
#include "../Crypto/CryptoStub.h"

typedef uint32_t U32;

class CSocketItemDbg: public CSocketItemDl
{
public:
	ControlBlock * GetControlBlock() const { return pControlBlock; }
	FSP_Session_State GetState() { return pControlBlock->state;  }
	void SetEndTransaction() { SetEoTPending(); }

	void OneTestRun();

	friend void UnitTestPrepareToSend();
	friend void UnitTestBufferData();
	friend void LogicTestPackedSend();

	friend void UnitTestAllocRecvBuf();
	friend void UnitTestFetchReceived();
	friend void UnitTestInquireRecvBuf();
	friend void UnitTestCompressAndDecode();

	friend void UnitTestSlimThreadPool();
};
