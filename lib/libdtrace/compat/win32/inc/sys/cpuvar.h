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

    cpuvar.h

Abstract:

    This file defines the extended per-CPU context support for the DTrace/NT
    compatibility layer.

--*/

#pragma once

#ifdef _KERNEL

typedef enum cpu_setup {
    CPU_CONFIG,
    CPU_UNCONFIG
} cpu_setup_t;

typedef struct cpu_core {
    uint16_t    cpuc_dtrace_flags;      // DTrace flags
    uintptr_t   cpuc_dtrace_illval;     // DTrace illegal value
} cpu_core_t;

extern cpu_core_t *cpu_core;
extern kmutex_t cpu_lock;
extern ULONG NCPU;

#define CPU (cpu_core + curcpu)
#define CPU_FOREACH(i) for (i = 0; i < NCPU; i++)

#define CPU_ON_INTR(C) FALSE

#endif

