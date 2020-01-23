#ifndef _INTEGERS_INTRINSICS_INLINES
#define _INTEGERS_INTRINSICS_INLINES

#include "endian.h"

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
typedef uint32_t  u32;

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

#include <memory.h>

#if defined(__WINDOWS__)
# include <basetsd.h>
# include <intrin.h>
# pragma intrinsic(memset, memcpy)

# if (_MSC_VER >= 1600)
#   pragma intrinsic(_InterlockedCompareExchange8, _InterlockedExchange8)
# else
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

# endif

# define LCKREAD(a)                         _InterlockedOr((LONG*)&(a), 0)
# if (_MSC_VER <= 1600)
# define _InterlockedCompareExchangePointer	InterlockedCompareExchangePointer
# define _InterlockedExchange				InterlockedExchange
# define _InterlockedExchange64				InterlockedExchange64
# define _InterlockedExchangeAdd			InterlockedExchangeAdd
# define _InterlockedIncrement				InterlockedIncrement
# define PRId64								"lld"
# define PRIx64                             "llx"
# define snprintf							_snprintf
# else
# include <inttypes.h>
# endif

#elif defined(__linux__) || defined(__CYGWIN__)

#include <inttypes.h>

# ifdef __cplusplus
#   include <atomic>
# else
#   include <stdatomic.h>
# endif

# define LCKREAD(a)					    __atomic_load_n(&(a), __ATOMIC_SEQ_CST)
# define _InterlockedExchange8(a, b)	__atomic_exchange_n((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedExchange(a, b)		__atomic_exchange_n((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedExchange64(a, b)	__atomic_exchange_n((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedExchangeAdd(a, b)	__atomic_fetch_add((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedIncrement(a)		__atomic_add_fetch((a), 1, __ATOMIC_SEQ_CST)
# define _InterlockedOr8(a, b)			__atomic_fetch_or((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedOr(a, b)			__atomic_fetch_or((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedExchangePointer(a, b) __atomic_exchange_n((a), (b), __ATOMIC_SEQ_CST)
# define _InterlockedCompareExchange(ptr, desired, expected)	\
	({	__typeof__(*(ptr)) _b = (expected);	\
        __atomic_compare_exchange_n((ptr), &_b, (desired), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); _b; })
# define _InterlockedCompareExchange8(a, b, c)			_InterlockedCompareExchange(a, b, c)
# define _InterlockedCompareExchangePointer(a, b, c)	_InterlockedCompareExchange(a, b, c)

typedef u32 *	ULONG_PTR;

#endif


#endif