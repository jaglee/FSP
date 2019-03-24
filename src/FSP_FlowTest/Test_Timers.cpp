#include "stdafx.h"
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")


#define TARGET_RESOLUTION 1         // 1-millisecond target resolution
void EvaluateHPET()
{
	TIMECAPS tc;
	UINT     wTimerRes;

	if (timeGetDevCaps(&tc, sizeof(TIMECAPS)) != TIMERR_NOERROR)
	{
		DebugBreak();
		return;	// Error; application can't continue.
	}

	wTimerRes = min(max(tc.wPeriodMin, TARGET_RESOLUTION), tc.wPeriodMax);

	MMRESULT r = timeBeginPeriod(wTimerRes);
	if (r != TIMERR_NOERROR)
	{
		DebugBreak();
		return;
	}

	timeEndPeriod(wTimerRes);
}



// Next shot of timerwheel timer would not happen until current thread is finished
static VOID NTAPI UnitTestReenterTimerWheel(PVOID c, BOOLEAN)
{
	static int countReEnter;
	countReEnter++;
	printf_s("Reenter %d times.\n", countReEnter);
	Sleep(1000);
	countReEnter--;
}



void EvaluateTimerWheel()
{
	CSocketItemExDbg socket(0, 0);	// reserve minumum
	socket.AddAdhocTimer(50, UnitTestReenterTimerWheel);
	printf_s("Printer enter to continue:\n");
	getchar();
}
