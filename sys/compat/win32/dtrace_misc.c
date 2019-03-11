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

    dtrace_misc.c

Abstract:

    This file contains the implementation of the support routines for the
    DTrace/NT compatibility layer.

--*/

#include <stdlib.h>
#include <sys/dtrace_impl.h>
#include <sys/cpuvar.h>
#include <sys/cpuvar_defs.h>
#include "dtracep.h"

dtrace_cacheid_t dtrace_predcache_id = 1;

cpu_core_t *cpu_core;
kmutex_t cpu_lock;
ULONG NCPU;

static ULONGLONG tsc_scale;
#define TSC_SCALE_SHIFT 28

//
// Per-CPU extended state support.
//

void dtrace_calibrate_tsc(void)
{
    ULONGLONG TscFrequency;
    ULONGLONG Count;
    ULONGLONG Delay;
    ULONGLONG Scale;
    ULONGLONG QpcTimeStamp;
    LARGE_INTEGER SleepTime;
    KIRQL OldIrql;

    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    Delay = KeQueryInterruptTimePrecise(&QpcTimeStamp);
    Count = ReadTimeStampCounter();
    KeLowerIrql(OldIrql);

    SleepTime.QuadPart = -1 * 100 * 1000 * 10; // 100ms
    KeDelayExecutionThread(KernelMode, TRUE, &SleepTime);

    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    Delay = KeQueryInterruptTimePrecise(&QpcTimeStamp) - Delay;
    Count = ReadTimeStampCounter() - Count;
    KeLowerIrql(OldIrql);

    for (Scale = 1; ((NANOSEC * Scale) / Delay) < 1000; Scale += 1) {
    }

    TscFrequency = (Count * ((NANOSEC * Scale) / Delay)) / (100 * Scale);
    tsc_scale = ((uint64_t)NANOSEC << TSC_SCALE_SHIFT) / TscFrequency;
    return;
}

int dtrace_cpusup_init(void)
{
    size_t cb;

    NT_ASSERT(NULL == cpu_core);

    NCPU = KeQueryMaximumProcessorCountEx(0);

    cb = NCPU * sizeof(cpu_core_t);
    cpu_core = ExAllocatePoolWithTag(NonPagedPoolNx, cb, 'CrtD');
    if (NULL == cpu_core) {
        return -1;
    }

    RtlZeroMemory(cpu_core, cb);

    dtrace_calibrate_tsc();

    return 0;
}

void dtrace_cpusup_cleanup(void)
{
    if (NULL != cpu_core) {
        ExFreePoolWithTag(cpu_core, 'CrtD');
    }
}

//
// kmem allocator.
// Directly translates to the NPNX tool allocator.
// The only difference is KM_SLEEP support - it needs to guarantee the
// successful allocation and thus depends on the OS making forward progress.
//

void *kmem_zalloc(size_t size, int flag)
{
    void* p = kmem_alloc(size, flag);

    if (NULL != p) {
        RtlZeroMemory(p, size);
    }

    return p;
}

void *kmem_alloc(size_t size, int flag)
{
    for (;;) {
        void* p = ExAllocatePoolWithTag(NonPagedPoolNx, size, 'crtD');
        if (NULL != p) {
            return p;
        }

        if (KM_SLEEP != flag) {
            return NULL;
        }

        {
            LARGE_INTEGER Delay;
            Delay.QuadPart = -1 * 100 * 1000 * 10; // 100ms
            KeDelayExecutionThread(KernelMode, TRUE, &Delay);
        }
    }
}

void kmem_free(void*buf, size_t size)
{
    ExFreePoolWithTag(buf, 'crtD');
}


//
// kmem fixed-size allocator (i.e. can be changed to lookaside lists if needed)
//

void *kmem_cache_alloc(struct kmem_cache * cachep, int flags)
{
    return kmem_alloc((size_t)cachep, flags);
}

void kmem_cache_free(struct kmem_cache * cachep, void * objp)
{
    kmem_free(objp, (size_t)cachep);
}

struct kmem_cache *kmem_cache_create(const char * name, size_t size, size_t offset, unsigned long flags, void (*ctor) (void*, kmem_cache_t *, unsigned long), void (*dtor) (void*, kmem_cache_t *, unsigned long))
{
    NT_ASSERT(!ARGUMENT_PRESENT(ctor));
    NT_ASSERT(!ARGUMENT_PRESENT(dtor));
    NT_ASSERT(0 == flags);
    return (struct kmem_cache*)size;
}

void kmem_cache_destroy(struct kmem_cache *cachep)
{
}

//
// Unique number provider.
//

struct unrnr {
    int nr;
    struct unrnr* next;
};

struct unrhdr {
    struct kmutex* lock;
    int low, high;
    int watermark;
    struct unrnr* allocated;
    struct unrnr* freed;
};

struct unrhdr *new_unrhdr(int low, int high, struct kmutex *mutex)
{
    struct unrhdr *h = kmem_zalloc(sizeof(*h), KM_SLEEP);
    h->low = low;
    h->high = high;
    h->watermark = low;
    h->lock = mutex;
    return h;
}

void delete_unrhdr(struct unrhdr *uh)
{
    struct unrnr *cur, *p;

    for (cur = uh->allocated; NULL != cur;) {
        p = cur;
        cur = cur->next;
        kmem_free(p, sizeof(*p));
    }

    for (cur = uh->freed; NULL != cur;) {
        p = cur;
        cur = cur->next;
        kmem_free(p, sizeof(*p));
    }

    kmem_free(uh, sizeof(*uh));
}

int alloc_unr(struct unrhdr *uh)
{
    struct unrnr *p;
    int nr;
    mutex_enter(uh->lock);
    if (NULL != uh->freed) {
        p = uh->freed;
        uh->freed = p->next;
        p->next = uh->allocated;
        uh->allocated = p;
        nr = p->nr;
        mutex_exit(uh->lock);
        return nr;
    }

    p = kmem_alloc(sizeof(*p), KM_SLEEP);
    p->nr = uh->watermark;
    uh->watermark += 1;
    p->next = uh->allocated;
    uh->allocated = p;
    nr = p->nr;
    mutex_exit(uh->lock);
    return nr;
}

void free_unr(struct unrhdr *uh, int item)
{
    struct unrnr *p, **pp;
    mutex_enter(uh->lock);
    for (pp = &uh->allocated; NULL != *pp;) {
        p = *pp;
        if (item == p->nr) {
            *pp = p->next;
            p->next = uh->freed;
            uh->freed = p;
            mutex_exit(uh->lock);
            return;
        }

        pp = &p->next;
    }

    NT_ASSERT(FALSE);
    mutex_exit(uh->lock);
}


//
// Misc dtrace subroutines.
//

void dtrace_vtime_enable(void)
{
}

void dtrace_vtime_disable(void)
{
}

int dtrace_getipl(void)
{
    NT_ASSERT(FALSE); // Should have been prefecthed.
    return 0;
}

dtrace_icookie_t dtrace_interrupt_disable(void)
{
    KIRQL Irq;
    KeRaiseIrql(HIGH_LEVEL, &Irq);
    return (dtrace_icookie_t )Irq;
}

void dtrace_interrupt_enable(dtrace_icookie_t c)
{
    KeLowerIrql((KIRQL)c);
}

void dtrace_membar_producer(void)
{
#if defined(_AMD64_) || defined(_X86_)
    _mm_sfence();
#endif
}

void dtrace_membar_consumer(void)
{
#if defined(_AMD64_) || defined(_X86_)
    _mm_lfence();
#endif
}


//
// The purpose of the dtrace_sync is to IPI all cores.
// Since probes are executing with interrupts disabled, this may
// only complete when all of them were inactive at some point.
//

static KIPI_BROADCAST_WORKER dtrace_sync_func;
static ULONG_PTR dtrace_sync_func(ULONG_PTR Argument)
{
    return 0;
}

void dtrace_sync(void)
{
    KeIpiGenericCall(dtrace_sync_func, 0);
    return;
}

//
// dtrace_gethrtime  : ns timestamp
// dtrace_gethrestime: ns systemtime
//

hrtime_t dtrace_gethrtime(void)
{
    LARGE_INTEGER c;

    c.QuadPart = ReadTimeStampCounter();

    return (((c.LowPart * tsc_scale) >> TSC_SCALE_SHIFT) +
            ((c.HighPart * tsc_scale) << (32 - TSC_SCALE_SHIFT)));
}

hrtime_t dtrace_gethrestime(void)
{
    ULONGLONG rv;
    rv = *(volatile ULONGLONG*)&SharedUserData->SystemTime;
    rv -= 0x019DB1DED53E8000; // Rebase from 1601 to 1970.
    return rv * 100; // 100ns to ns
}

//
// Misc helpers
//

uint32_t dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
    return InterlockedCompareExchange((volatile LONG*)target, new, cmp);
}

void *dtrace_casptr(void *target, void *cmp, void *new)
{
    return InterlockedCompareExchangePointer(target, new, cmp);
}

//
// User-mode address space accessors.
//

static BOOLEAN dtrace_inuser(uintptr_t p, size_t len)
{
    uintptr_t end = p + len - 1;
    return ((p <= end) && (end < MM_USER_PROBE_ADDRESS));
}

#define dtrace_fuword(n)                                                 \
    uint##n##_t dtrace_fuword##n(void* p)                                \
    {                                                                    \
        uint##n##_t v;                                                   \
        uintptr_t a = (uintptr_t)p;                                      \
                                                                         \
        if (!dtrace_inuser(a, sizeof(v)) ||                              \
            !dtrace_safememcpy(&v, a, sizeof(v), sizeof(v), TRUE)) {     \
                                                                         \
            DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);                      \
            cpu_core[curcpu].cpuc_dtrace_illval = a;                     \
            v = 0;                                                       \
        }                                                                \
                                                                         \
        return v;                                                        \
    }

dtrace_fuword(8)
dtrace_fuword(16)
dtrace_fuword(32)
dtrace_fuword(64)

void dtrace_copyin(uintptr_t uaddr, uintptr_t kaddr, size_t size, volatile uint16_t *flags)
{
    if (!dtrace_inuser(uaddr, size) ||
        !dtrace_safememcpy((PVOID)kaddr, uaddr, size, 1, TRUE)) {
        cpu_core[curcpu].cpuc_dtrace_illval = uaddr;
        DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
    }
}

void dtrace_copyinstr(uintptr_t uaddr, uintptr_t kaddr, size_t size, volatile uint16_t *flags)
{
    dtrace_copyin(uaddr, kaddr, size, flags);
}

void dtrace_copyout(uintptr_t kaddr, uintptr_t uaddr, size_t size, volatile uint16_t *flags)
{
    if (!dtrace_inuser(uaddr, size) ||
        !dtrace_safememcpy((PVOID)kaddr, uaddr, size, 1, FALSE)) {
        cpu_core[curcpu].cpuc_dtrace_illval = uaddr;
        DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
    }
}

void dtrace_copyoutstr(uintptr_t kaddr, uintptr_t uaddr, size_t size, volatile uint16_t *flags)
{
    dtrace_copyout(kaddr, uaddr, size, flags);
}

uintptr_t dtrace_caller(int skip_frames)
{
    // Return failure so code will fall back to the
    // general stackwalk helper.
    skip_frames;
    return (uintptr_t)-1;
}

__declspec(noinline)
void dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes, uint32_t *intrpc)
{
    int i;
    int depth = 0;
    if (intrpc != 0) {
        pcstack[depth++] = (pc_t) intrpc;
    }

    depth += RtlCaptureStackBackTrace(aframes + 1,
                                      pcstack_limit - depth,
                                      (PVOID*)pcstack,
                                      NULL);

    for (i = 0; i < pcstack_limit; i++) {
        if (i >= depth) {
            pcstack[i] = 0;
        }
    }
}

int dtrace_getstackdepth(int aframes)
{
    return 0;
}

int dtrace_getustackdepth(void)
{
    return 0;
}

void dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
}

void dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
    ULONG captured = dtrace_userstackwalk(pcstack_limit, (PVOID*)pcstack);
    while (captured < pcstack_limit) {
        pcstack[captured++] = 0;
    }
}

uint64_t dtrace_getarg(int arg, int aframes)
{
    return 0;
}

ulong_t dtrace_getreg(struct _KTRAP_FRAME* tf, struct _CONTEXT* ctx, uint_t reg)
{
    ULONG_PTR val;
    PVOID base;
    ULONG offset;

    const struct regdesc {
        USHORT TrapOffset;
        USHORT ContextOffset;
    } regdesc[] = {
#define DTRACE_TABLE_REG(n) \
    { FIELD_OFFSET(KTRAP_FRAME, n), FIELD_OFFSET(CONTEXT, n) }
#define DTRACE_TABLE_REG_CTX(n) \
    { sizeof(KTRAP_FRAME), FIELD_OFFSET(CONTEXT, n) }

#if defined(_AMD64_)
        DTRACE_TABLE_REG(Rax),
        DTRACE_TABLE_REG(Rcx),
        DTRACE_TABLE_REG(Rdx),
        DTRACE_TABLE_REG(Rbx),
        DTRACE_TABLE_REG(Rsp),
        DTRACE_TABLE_REG(Rbp),
        DTRACE_TABLE_REG(Rsi),
        DTRACE_TABLE_REG(Rdi),
        DTRACE_TABLE_REG(R8),
        DTRACE_TABLE_REG(R9),
        DTRACE_TABLE_REG(R10),
        DTRACE_TABLE_REG(R11),
        DTRACE_TABLE_REG_CTX(R12),
        DTRACE_TABLE_REG_CTX(R13),
        DTRACE_TABLE_REG_CTX(R14),
        DTRACE_TABLE_REG_CTX(R15),
        DTRACE_TABLE_REG(Rip),
        DTRACE_TABLE_REG(EFlags),
#elif defined(_X86_)
#elif defined(_ARM64_)
#elif defined(_ARM_)
#else
#error Unsupported architecture
#endif
        0, 0
    };

    if (reg >= RTL_NUMBER_OF(regdesc)) {
        return 0;
    }

    if (ARGUMENT_PRESENT(ctx)) {
        base = ctx;
        offset = regdesc[reg].ContextOffset;
        if (offset < sizeof(CONTEXT)) {
            goto read_reg;
        }
    }

#ifdef _AMD64_
    if (ARGUMENT_PRESENT(tf)) {
        base = tf;
        offset = regdesc[reg].TrapOffset;
        if (offset < sizeof(KTRAP_FRAME)) {
            goto read_reg;
        }
    }
#endif

    if (NULL == base) {
        DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
        cpu_core[curcpu].cpuc_dtrace_illval = 0;
    }

    return 0;

read_reg:
    base = RtlOffsetToPointer(base, offset);
    if (!dtrace_safememcpy(&val, (uintptr_t)base, sizeof(val), sizeof(val), TRUE)) {
        DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
        cpu_core[curcpu].cpuc_dtrace_illval = (uintptr_t)base;
        return 0;
    }

    return val;
}

//
// (v)panic.
//

volatile const char* panicstr;

void dtrace_vpanic(const char *s, __va_list ap)
{
    panicstr = s;
    for (;;) {
        __debugbreak();
    }
    //KeBugCheckEx(<user_induced>, s, ap, 0, 0);
}

void cmn_err(int level, char *format, ...)
{
    // TODO:
}

//
// Token support.
//

void crfree(struct cred * cr)
{
    NT_ASSERT(FALSE);
}


//
// Probe/copy.
//

int copyin(const void *uaddr, void *kaddr, size_t len)
{
    int rv = 0;
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    __try {
        ProbeForRead((void*)uaddr, len, 1);
        RtlCopyMemory(kaddr, uaddr, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rv = EFAULT;
    }

    return rv;
}

int copyout(const void *kaddr, void *uaddr, size_t len)
{
    int rv = 0;
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    __try {
        ProbeForWrite(uaddr, len, 1);
        RtlCopyMemory(uaddr, kaddr, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rv = EFAULT;
    }

    return rv;
}


//
// XCall.
//

typedef struct _DR_XCALL_CTX {
    processorid_t cpu;
    dtrace_xcall_t func;
    void *arg;
} DR_XCALL_CTX;

static KIPI_BROADCAST_WORKER DtpXcallWorker;
static ULONG_PTR DtpXcallWorker(ULONG_PTR Argument)
{
    DR_XCALL_CTX* ctx = (DR_XCALL_CTX*)Argument;
    if ((DTRACE_CPUALL == ctx->cpu) || (curcpu == ctx->cpu)) {
        (ctx->func)(ctx->arg);
    }
    return 0;
}

void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
    DR_XCALL_CTX ctx;

    if (curcpu == cpu) {
        (func)(arg);
        return;
    }

    ctx.cpu = cpu;
    ctx.func = func;
    ctx.arg = arg;
    KeIpiGenericCall(DtpXcallWorker, (ULONG_PTR)&ctx);
    return;
}

//
// taskq stubs. Should never be used.
//
taskqid_t taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, unsigned int flags)
{
    NT_ASSERT(FALSE);
    return 0;
}

taskq_t * taskq_create(const char *name, int nthreads, pri_t pri, int minalloc, int maxalloc, unsigned int flags)
{
    return NULL;
}

void taskq_destroy(taskq_t *tq)
{
}

//
// Simplified pattern matching.
//

int
gmatch(const char* name, const char* expr)
{
    const char* n;
    const char* e;
    if ('\0' == *expr) {
        return 0;
    }

    n = name;
    e = expr;

    for (;;) {
        if ('*' == *e) {
            return 0;
        }

        if ('\0' == *n) {
            return ('\0' == *e) ? 0 : -1;
        }

        if ('?' != *e && *n != *e) {
            return -1;
        }

        n += 1;
        e += 1;
    }
}


//
// Callout API implementation.
//

static EXT_CALLBACK DtpCalloutTimerRoutine;

_Use_decl_annotations_
static
VOID
DtpCalloutTimerRoutine (
    PEX_TIMER Timer,
    PVOID     TimerContext
    )
{
    struct callout *c = (struct callout *)TimerContext;
    timeout_t *Callback;
    void* CallbackContext;

    Callback = c->Callback;
    KeMemoryBarrier();
    CallbackContext = c->Context;
    if (NULL != Callback) {
        (Callback)(CallbackContext);
    }
}

static int DtpCalloutStop(struct callout *c, BOOLEAN Drain)
{
    c->Callback = NULL;
    KeMemoryBarrier();
    c->Context = NULL;
    if (c->Timer && ExCancelTimer(c->Timer, NULL)) {
        return +1;
    } else {
        return -1;
    }
}

int callout_stop(struct callout *c)
{
    return DtpCalloutStop(c, FALSE);
}

int callout_drain(struct callout *c)
{
    return DtpCalloutStop(c, TRUE);
}

int callout_reset(struct callout *c, int ticks, timeout_t *func, void *arg)
{
    c->Callback = func;
    c->Context = arg;
    if (c->Timer) {
        ExSetTimer(c->Timer, -ticks, 0, NULL);
    }
    return 0;
}

void callout_init(struct callout *c, int mpsafe)
{
    RtlZeroMemory(c, sizeof(*c));
    c->Timer = ExAllocateTimer(DtpCalloutTimerRoutine, c, 0);
    return;
}

void callout_cleanup(struct callout *c)
{
    if (NULL != c->Timer) {
        ExDeleteTimer(c->Timer, TRUE, TRUE, NULL);
    }
    RtlZeroMemory(c, sizeof(*c));
    return;
}

void mutex_enter(kmutex_t* mutex)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusiveEx(&mutex->Lock, 0);
}

void mutex_exit(kmutex_t* mutex)
{
    ExReleasePushLockExclusiveEx(&mutex->Lock, 0);
    KeLeaveCriticalRegion();
}

