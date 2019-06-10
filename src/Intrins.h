#ifndef _INTEGERS_INTRINSICS_INLINES
#define _INTEGERS_INTRINSICS_INLINES

#if !_MSC_VER || _MSC_VER >= 1600 /* Try stdint.h if non-Microsoft */
#ifdef  __cplusplus
#define __STDC_CONSTANT_MACROS
#endif
#include <stdint.h>
#elif (_MSC_VER)                  /* Microsoft C ealier than VS2010 does not have stdint.h    */
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#define INT32_MAX	0x7FFFFFFF
#define UINT32_MAX	0xFFFFFFFFU
#define UINT64_C(v) v ## UI64
#else                             /* Guess sensibly - may need adaptation  */
typedef long int32_t;
typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned long	uint32_t;
typedef unsigned long long uint64_t;
#define INT32_MAX	0x7FFFFFFF
#define UINT32_MAX	0xFFFFFFFFU
#define UINT64_C(v) v ## ULL
#endif

typedef uint8_t octet;

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

#include <memory.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy)

#if (_MSC_VER >= 1600)
#pragma intrinsic(_InterlockedCompareExchange8, _InterlockedExchange8)
#else
FORCEINLINE char _InterlockedCompareExchange8(volatile char *dest, char newval, char oldval)
{
    __asm
    {
        mov     al, oldval
        mov     edx,dest
        mov     cl,	newval
        lock cmpxchg byte ptr [edx], cl
    }
}

FORCEINLINE char _InterlockedExchange8(volatile char * a, char b)
{
	__asm mov	ecx, a;
	__asm mov	AL, b;
	__asm xchg	AL, byte ptr[ecx];
}

FORCEINLINE char _InterlockedExchange16(volatile short * a, short b)
{
	__asm mov	ecx, a;
	__asm mov	AX, b;
	__asm xchg	AX, word ptr[ecx];
}
#endif


#endif