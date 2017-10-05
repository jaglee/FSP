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

// assume the compiler support 64-bit integer. and it is assumed that the operand is properly alligned
#ifndef htobe64

#if !defined(_MSC_VER) || !defined(_M_IA64) && !defined(_M_X64) && (!defined(_M_IX86) || _MSC_VER < 1400)
#define _DWORD_SWAP(l)                \
        ( ( ((l) >> 24) & 0x000000FFL ) |       \
            ( ((l) >>  8) & 0x0000FF00L ) |       \
            ( ((l) <<  8) & 0x00FF0000L ) |       \
            ( ((l) << 24) & 0xFF000000L ) )

#define _QWORD_SWAP(l)            \
        ( ( ((l) >> 56) & 0x00000000000000FFLL ) |       \
            ( ((l) >> 40) & 0x000000000000FF00LL ) |       \
            ( ((l) >> 24) & 0x0000000000FF0000LL ) |       \
            ( ((l) >>  8) & 0x00000000FF000000LL ) |       \
            ( ((l) <<  8) & 0x000000FF00000000LL ) |       \
            ( ((l) << 24) & 0x0000FF0000000000LL ) |       \
            ( ((l) << 40) & 0x00FF000000000000LL ) |       \
            ( ((l) << 56) & 0xFF00000000000000LL ) )

__inline uint32_t be32toh(uint32_t v) 
{ 
	return _DWORD_SWAP(v);
}

__inline uint32_t htobe32(uint32_t v)
{ 
	return _DWORD_SWAP(v);
}


__inline uint64_t be64toh(uint64_t v) 
{ 
	return _QWORD_SWAP(v);
}

__inline uint64_t htobe64(uint64_t v) 
{ 
	return _QWORD_SWAP(v);
}

#else

#include <memory.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy)
#pragma intrinsic(_byteswap_ushort, _byteswap_ulong, _byteswap_uint64)

#define be16toh(v) _byteswap_ushort(v)
#define htobe16(v) _byteswap_ushort(v)
#define be32toh(v) _byteswap_ulong(v)
#define htobe32(v) _byteswap_ulong(v)
#define be64toh(v) _byteswap_uint64(v)
#define htobe64(v) _byteswap_uint64(v)

#endif

#endif



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