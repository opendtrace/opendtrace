/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*++

Copyright (c) Microsoft Corporation

Module Name:

    ntcompat.h

Abstract:

    This file sets up the environment for the DTrace/NT compatibility layer.

--*/

#pragma once

//
// Common CRT includes.
//

#include <stdlib.h>
#include <stdarg.h>
#include <intsafe.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stddef.h>

//
// Mode-specific includes.
//

#ifdef _KERNEL

#include <ntifs.h>

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    __in PEPROCESS Process
    );

NTKERNELAPI
PCSTR
PsGetProcessImageFileName (
    _In_ PEPROCESS Process
    );

NTKERNELAPI
VOID
FASTCALL
ExAcquirePushLockExclusiveEx (
    _Inout_ PEX_PUSH_LOCK PushLock,
    _In_ ULONG Flags
    );

NTKERNELAPI
VOID
FASTCALL
ExReleasePushLockExclusiveEx (
    _Inout_ PEX_PUSH_LOCK PushLock,
    _In_ ULONG Flags
    );

NTKERNELAPI
NTSTATUS
ZwYieldExecution (
    VOID
    );

#else

#include <windows.h>
#include <winioctl.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <dbghelp.h>
#include <fcntl.h>
#include <io.h>
#include <assert.h>

#endif


//
// Disable misc warnings.
//

#ifdef _MSC_VER
#pragma warning (disable:4100) // unreferenced formal parameter
#pragma warning (disable:4101) // '...': unreferenced local variable
#pragma warning (disable:4189) // '...': local variable is initialized but not referenced
#pragma warning (disable:4018) // signed/unsigned mismatch
#pragma warning (disable:4242) // 'function': conversion from '...' to '..', possible loss of data
#pragma warning (disable:4244) // '=': conversion from '...' to '..', possible loss of data
#pragma warning (disable:4245) // '=': conversion from '...' to '...', signed/unsigned mismatch
#pragma warning (disable:4146) // unary minus operator applied to unsigned type, result still unsigned
#pragma warning (disable:4701) // potentially uninitialized local variable '...' used
#pragma warning (disable:4703) // potentially uninitialized local pointer variable '...' used
#pragma warning (disable:4706) // assignment within conditional expression
#pragma warning (disable:4389) // '!=': signed/unsigned mismatch
#pragma warning (disable:4310) // cast truncates constant value
#pragma warning (disable:4214) // nonstandard extension used: bit field types other than int
#pragma warning (disable:4115) // '...': named type definition in parentheses
#pragma prefast (disable:28719) // banned API usage.
#pragma prefast (disable:6255) // Unprotected use of alloca
#endif

//
// Compatibility macroses.
//

#if defined(_WIN64)
#define _LP64 1
#else
#define _LP32 1
#endif

#ifdef _M_AMD64
#define __amd64
#define __amd64__
#define __x86_64
#define __x86_64__
#endif

#ifdef _M_IX86
#define __i386
#define __i386__
#endif

#define __va_list va_list
#define __noinline __declspec(noinline)
#define __unused
#define va_copy(destination, source) ((destination) = (source))

//
// stdint.h may not be a part of the toolset.
// Define compatible types locally.
//

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef long long          intmax_t;
typedef unsigned long long uintmax_t;

//
// Define compatible types in addition to those defined in stdtypes.h
//

typedef uint8_t   uchar_t;
typedef uint16_t  ushort_t;
typedef int32_t   int_t;    // max 32-bit on *nix
typedef uint32_t  uint_t;   // max 32-bit on *nix
typedef intptr_t  long_t;   // pointer-sized on *nix
typedef uintptr_t ulong_t;  // pointer-sized on *nix
typedef int64_t   longlong_t;
typedef uint64_t  u_longlong_t;
typedef intptr_t  ssize_t;
typedef int       boolean_t;

typedef uint32_t  uid_t;
typedef uint32_t  zoneid_t;
typedef uint32_t  pid_t;
typedef int32_t   id_t;
typedef char*     caddr_t;

//
// Misc helper macroses and other defines.
//

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ABS(x)   ((x) < 0 ? -(x) : (x))

#define B_TRUE  1
#define B_FALSE 0

#define NBBY    8

#define lisalnum(x) \
    (isdigit(x) || ((x) >= 'a' && (x) <= 'z') || ((x) >= 'A' && (x) <= 'Z'))

#define DIGIT(x) \
    (isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')

#define IS_P2ALIGNED(v, a)  ((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)
#define ISP2(x)             (((x) & ((x) - 1)) == 0)
#define P2PHASEUP(x, align, phase) ((phase) - (((phase) - (x)) & -(align)))
#define P2ROUNDUP(x, align) (-(-(x) & -(align)))
#define roundup(x, y)       ((((x)+((y)-1))/(y))*(y))

#define PATH_MAX MAX_PATH
#define MAXPATHLEN MAX_PATH
#define INT64_C(c) (c ## LL)

#define SEC             1
#define MILLISEC        1000
#define MICROSEC        1000000
#define NANOSEC         1000000000
#define MSEC2NSEC(n)    (1ULL * n * 1000 * 1000)

#define hz (NANOSEC / 100)

#define NS_INADDRSZ    4
#define NS_IN6ADDRSZ  16

#define bzero(s, n)         memset((s), 0, (n))
#define bcopy(src, dest, n) memmove((dest), (src), (n))
#define bcmp(s1, s2, n)     memcmp((s1), (s2), (n))

#ifndef EALREADY
#define EALREADY 103
#else
C_ASSERT(EALREADY == 103);
#endif

#define PROT_READ   1
#define PROT_WRITE  2
#define MAP_ANON    1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void*)-1)

#define SHT_PROGBITS 1

//
// CRT name redirection and extra routined not available in MS CRT.
//

#define off_t _off_t
typedef int64_t off64_t;

#define alloca _alloca
#define open _open
#define open64 _open
#define close _close
#define read _read
#define write _write
#define fstat _fstat
#define strcasecmp _stricmp
#define strdup _strdup
#define strlcat(d, s, l) strcat_s((d), (l), (s))
#define lseek _lseek
#define lseek64 _lseek
#define fseeko fseek
#define ftruncate64 ftruncate
#define strtoull _strtoui64
#define fileno _fileno
#define stat _stat

extern void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern int munmap(void *addr, size_t length);
extern int mprotect(void *addr, size_t len, int prot);

extern char *strndup(const char *s, size_t n);
extern char *strdupa(const char *s);
extern size_t strlcpy(char * dst, const char * src, size_t dstsize);
extern char *basename(char *path);
extern int ftruncate(int fd, off_t length);
extern int ioctl(int fd, unsigned long request, void* buf);
extern int gmatch(const char *s, const char *p);
extern int asprintf(char **strp, const char *fmt, ...);
extern char *ctime_r(const time_t *time, char *buf);
extern struct tm *localtime_r(const time_t *timep, struct tm *result);

typedef int64_t hrtime_t;

__inline hrtime_t gethrtime(void)
{
    ULONGLONG rv;
#ifdef _KERNEL
    ULONGLONG CurrentQpc;
    rv = KeQueryInterruptTimePrecise(&CurrentQpc);
#else
    QueryInterruptTimePrecise(&rv);
#endif
    return rv * 100;
}

//
// IO control code definitions compatible with the passthrouth ioctl routine
// implementation.
//
// a - access
// b - index
// c - type.
//

#define FILE_DEVICE_DTRACE FILE_DEVICE_NULL

#define DTRACE_IOC_ENCODE(a, b, c) \
    CTL_CODE(FILE_DEVICE_DTRACE, b + 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#undef _IOR
#undef _IOW
#undef _IOWR
#define _IOR(a, b, c)  DTRACE_IOC_ENCODE(1, b, c)
#define _IOW(a, b, c)  DTRACE_IOC_ENCODE(2, b, c)
#define _IOWR(a, b, c) DTRACE_IOC_ENCODE(3, b, c)


//
// Processor state.
//

typedef int processorid_t;
#define P_ONLINE        0x0002
#define P_STATUS        0x0003
int p_online(processorid_t processorid, int flag);

//
// sysconf - CPU count and max CPU index only.
//

#define _SC_CPUID_MAX           123
#define _SC_NPROCESSORS_MAX     124
extern long sysconf(int name);

//
// getopt package.
//

extern int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;

//
// lex interface
//

extern int yylex(void);
typedef unsigned char YY_CHAR;


//
// Following definitions are only applicable to the kernel mode.
//

#ifdef _KERNEL

typedef struct kthread  kthread_t; // ETHREAD alias
typedef struct proc     proc_t;    // EPROCESS alias
typedef struct file     file_t;    // FILE_OBJECT alias
typedef struct cred     cred_t;    // Token alias
#define trapframe _CONTEXT

//
// kmutex->EX_PUSH_LOCK
//

typedef struct kmutex     {ULONG_PTR Lock;} kmutex_t;
void mutex_enter(kmutex_t* mutex);
void mutex_exit(kmutex_t* mutex);

#define curcpu     KeGetCurrentProcessorIndex()
#define curthread  ((kthread_t*)KeGetCurrentThread())
#define curproc    ((proc_t*)PsGetCurrentProcess())

#define _NOTE(e) {;}
#define ASSERT3U(L, O, R) NT_ASSERT(L O R)

//
// kmem allocators.
//

#define KM_SLEEP     0
#define KM_NOSLEEP   1
#define KM_NORMALPRI 2
extern void *kmem_zalloc(size_t size, int flag);
extern void *kmem_alloc(size_t size, int flag);
extern void kmem_free(void*buf, size_t size);

typedef struct kmem_cache kmem_cache_t;
extern void *kmem_cache_alloc(struct kmem_cache * cachep, int flags);
extern void kmem_cache_free(struct kmem_cache * cachep, void * objp);
extern struct kmem_cache *kmem_cache_create(const char * name, size_t size, size_t offset, unsigned long flags, void (*ctor) (void*, kmem_cache_t *, unsigned long), void (*dtor) (void*, kmem_cache_t *, unsigned long));
extern void kmem_cache_destroy(struct kmem_cache *cachep);

//
// Error reporting.
//

#define CE_WARN 1
#define CE_NOTE 2
extern void cmn_err(int level, char *format, ...);
extern volatile const char* panicstr;

//
// address probe helpers.
//

extern int copyin(const void *uaddr, void *kaddr, size_t len);
extern int copyout(const void *kaddr, void *uaddr, size_t len);

//
// taskq package.
//

#define TQ_SLEEP 0
typedef struct taskq  taskq_t;
typedef uintptr_t taskqid_t;
typedef int pri_t;
typedef void (task_func_t)(void *);
extern taskqid_t taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, unsigned int flags);
extern taskq_t * taskq_create(const char *name, int nthreads, pri_t pri, int minalloc, int maxalloc, unsigned int flags);
extern void taskq_destroy(taskq_t *tq);

//
// Unique number provider package.
//

extern struct unrhdr *new_unrhdr(int low, int high, struct kmutex *mutex);
extern void delete_unrhdr(struct unrhdr *uh);
extern int alloc_unr(struct unrhdr *uh);
extern void free_unr(struct unrhdr *uh, int item);

//
// callout package.
//

typedef void timeout_t (void *);

typedef struct callout    {
    PEX_TIMER Timer;
    timeout_t *Callback;
    void* Context;
} callout_t;

extern void callout_init(struct callout *c, int mpsafe);
extern void callout_cleanup(struct callout *c);
extern int callout_stop(struct callout *c);
extern int callout_drain(struct callout *c);
extern int callout_reset(struct callout *c, int ticks, timeout_t *func, void *arg);

//
// Credentials support.
//

extern void crfree(struct cred * cr);
#define CRED() NULL

//
// inet
//

#define AF_INET         2
#define AF_INET6        23

#define INET_ADDRSTRLEN  22
#define INET6_ADDRSTRLEN 65

typedef uint32_t ipaddr_t;

struct in6_addr {
    union {
        uint8_t  _S6_u8[16];
        uint16_t _S6_u16[8];
    } _S6_un;
};

__inline int IN6_IS_ADDR_V4MAPPED(const struct in6_addr *a)
{
    return ((a->_S6_un._S6_u16[0] == 0) &&
            (a->_S6_un._S6_u16[1] == 0) &&
            (a->_S6_un._S6_u16[2] == 0) &&
            (a->_S6_un._S6_u16[3] == 0) &&
            (a->_S6_un._S6_u16[4] == 0) &&
            (a->_S6_un._S6_u16[5] == 0xffff));
}

__inline int IN6_IS_ADDR_V4COMPAT(const struct in6_addr *a)
{
    return ((a->_S6_un._S6_u16[0] == 0) &&
            (a->_S6_un._S6_u16[1] == 0) &&
            (a->_S6_un._S6_u16[2] == 0) &&
            (a->_S6_un._S6_u16[3] == 0) &&
            (a->_S6_un._S6_u16[4] == 0) &&
            (a->_S6_un._S6_u16[5] == 0) &&
            !((a->_S6_un._S6_u16[6] == 0) &&
              (a->_S6_un._S6_u8[14] == 0) &&
              ((a->_S6_un._S6_u8[15] == 0) ||
               (a->_S6_un._S6_u8[15] == 1))));
}


#endif



