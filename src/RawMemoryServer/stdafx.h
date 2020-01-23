// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

#include <stdio.h>

#if defined(__WINDOWS__)

# include <tchar.h>

#elif defined(__linux__) || defined(__CYGWIN__)

# include <alloca.h>
# include <time.h>

# define _alloca        alloca
# define _T(s)          s
# define TCHAR          char
# define _tmain         main
# define _tprintf_s     printf

SINLINE void Sleep(int32_t millis)
{
    struct timespec tv;
    tv.tv_sec = millis / 1000;
    tv.tv_nsec = (millis % 1000) * 1000000;
    nanosleep(&tv, NULL);
}

SINLINE int64_t _ttoi64(char *s)
{
    char *p;
    return (int64_t)strtoll(s, &p, 10);
}

#endif