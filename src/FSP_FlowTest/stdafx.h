// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define _CRT_RAND_S
#include "gmpxx.h"

// MUST include local header before stdio or else _CRT_RAND_S is not defined properly
#include "../UnitTestFSP/FSP_TestClass.h"
#include "../FSP_API.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

#include <assert.h>
#include <tchar.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
