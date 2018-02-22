// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <WinSock2.h>
#include <mstcpip.h>
#include <MSWSock.h>

#pragma comment(lib, "Ws2_32.lib")

bool unit_test();