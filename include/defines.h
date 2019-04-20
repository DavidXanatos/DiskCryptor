#ifndef _DEFINES_H_
#define _DEFINES_H_

#ifdef IS_DRIVER
 #include <ntifs.h>
#endif

#if !defined(IS_DRIVER) && !defined(BOOT_LDR)
 #include <windows.h>
 #include <stdio.h>
#endif

#ifndef _WCHAR_T_DEFINED 
 typedef short wchar_t;
#endif

typedef unsigned __int64 u64;
typedef unsigned long    u32;
typedef unsigned short   u16;
typedef unsigned char    u8;

typedef __int64 s64;
typedef long    s32;
typedef short   s16;
typedef char    s8;

#define d8(_x)  ((u8)(_x))
#define d16(_x) ((u16)(_x))
#define d32(_x) ((u32)(_x))
#define d64(_x) ((u64)(_x))
#define dSZ(_x) ((size_t)(_x))

#define BE16(x) _byteswap_ushort(x)
#define BE32(x) _byteswap_ulong(x)
#define BE64(x) _byteswap_uint64(x)

#define ROR64(x,y)     (_rotr64((x),(y)))
#define ROL64(x,y)     (_rotl64((x),(y)))
#define ROL32(x,y)     (_rotl((x), (y)))
#define ROR32(x,y)     (_rotr((x), (y)))

#define align16  __declspec(align(16))
#define naked    __declspec(naked)

#define p8(_x)   ((u8*)(_x))
#define p16(_x)  ((u16*)(_x))
#define p32(_x)  ((u32*)(_x))
#define p64(_x)  ((u64*)(_x))
#define p128(_x) ((__m128i*)(_x))
#define pv(_x)   ((void*)(_x))
#define ppv(_x)  ((void**)(_x)) 

#define in_reg(_a, _base, _size) \
    ( (_a) >= (_base) && (_a) < (_base)+(_size) )

#define is_intersect(_start1, _size1, _start2, _size2) \
    ( max(_start1, _start2) < min(_start1 + _size1, _start2 + _size2) )

#define addof(_a, _o)         ( pv(p8(_a) + (ptrdiff_t)(_o)) )
#define countof(_array)       ( sizeof(_array) / sizeof((_array)[0]) )
#define _align(_size, _align) ( ((_size) + ((_align) - 1)) & ~((_align) - 1) )

#ifdef BOOT_LDR
 #pragma warning(disable:4142)
 typedef unsigned long size_t;
 #pragma warning(default:4142)

 #define min(a,b) (((a) < (b)) ? (a) : (b))
 #define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef PAGE_SIZE
 #define PAGE_SIZE 0x1000
#endif
#ifndef MAX_PATH
 #define MAX_PATH 260
#endif

/* zero memory secure (prevent compiler optimization) */
#if defined(BOOT_LDR)
#define burn(_ptr, _len) { volatile char *_p = (volatile char*)(_ptr); size_t _s = (_len); while (_s--) *_p++ = 0; }
#else
#define burn(_ptr, _len) { RtlSecureZeroMemory(_ptr, _len); }
#endif

/* size optimized intrinsics */
#define mincpy(a,b,c) __movsb(pv(a), pv(b), (size_t)(c))
#define minset(a,b,c) __stosb(pv(a), (char)(b), (size_t)(c))

#define lock_inc(_x)             ( _InterlockedIncrement(_x) )
#define lock_dec(_x)             ( _InterlockedDecrement(_x) )
#define lock_xchg(_p, _v)        ( _InterlockedExchange(_p, _v) )
#define lock_xchg_add(_p, _v)    ( _InterlockedExchangeAdd(_p, _v) )
#define lock_cmpxchg64(_d,_e,_c) ( _InterlockedCompareExchange64((_d),(_e),(_c)) )

#ifdef _M_IX86
 u64 __forceinline lock_xchg64(u64 *p, u64 v)
 {
	 u64 ov;
	 do 
	 {
		 ov = *p;
	 } while (lock_cmpxchg64((__int64*)(p), v, ov) != ov);
	 return ov;
 }
#else
 #define lock_xchg64(t,v) ( _InterlockedExchange64((t),(v)) )
#endif

#pragma warning(disable:4995)
#pragma intrinsic(memcpy,memset,memcmp)
#pragma intrinsic(strcpy,strcmp,strlen)
#pragma intrinsic(strcat)
#pragma warning(default:4995)


#endif
