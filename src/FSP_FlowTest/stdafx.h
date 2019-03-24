// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
// Jason Gao, Jan.6, 2018: Formally apply Multiple Precision Integers and Rationals lib
//

#pragma once

#include "targetver.h"

#define _CRT_RAND_S
#pragma warning(disable:4146 4244 4800)
#include "gmpxx.h"
#pragma warning(default:4146 4244 4800)

// MUST include local header before stdio or else _CRT_RAND_S is not defined properly
#include "../UnitTestFSP/FSP_TestClass.h"
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

#include <assert.h>
#include <tchar.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

void UnitTestCRC();
void UnitTestICC();
void UnitTestHMAC();
void UnitTestTweetNacl();

void EvaluateTimerWheel();
void EvaluateHPET();

void FlowTestAcknowledge();
void FlowTestRetransmission();
void FlowTestRecvWinRoundRobin();

void TrySRP6();
void TryCHAKA();

void TryWideChar();
