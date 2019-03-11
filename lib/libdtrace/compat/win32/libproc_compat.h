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

    libproc_compat.h

Abstract:

    This file defines a subset of the libproc interface for the
    DTrace/NT compatibility layer.

--*/

#pragma once

#include <gelf.h>

#define ps_prochandle   proc_handle
#define Lmid_t          int

struct proc_handle;
typedef void* proc_child_func;

typedef struct prsyminfo {
    u_int prs_id;
} prsyminfo_t;

#define PGRAB_FORCE     1
#define PGRAB_RDONLY    2

#define PRELEASE_HANG   1
#define PRELEASE_KILL   2

#define PR_RLC          1
#define PR_KLC          2

#define PR_LMID_EVERY   0

#define PR_SYMTAB       1
#define PR_DYNSYM       2

#define BIND_ANY        1
#define TYPE_FUNC       0x0400

typedef int proc_sym_f(void *, const GElf_Sym *, const char *);
typedef int proc_map_f(void *, uint64_t, const char *);

extern uint64_t proc_addr2map(struct proc_handle *, uintptr_t);
extern uint64_t proc_name2map(struct proc_handle *, const char *);
extern char *proc_objname(struct proc_handle *, uintptr_t, char *, size_t);
extern int proc_iter_objs(struct proc_handle *, proc_map_f *, void *);
extern int proc_iter_symbyaddr(struct proc_handle *, const char *, int,
                               int, proc_sym_f *, void *);
extern int proc_addr2sym(struct proc_handle *, uintptr_t, char *, size_t, GElf_Sym *);
extern int proc_attach(pid_t pid, int flags, struct proc_handle **pphdl);
extern int proc_clearflags(struct proc_handle *, int);
extern int proc_create(const char *, char * const *, char * const *,
                       proc_child_func *, void *, struct proc_handle **);
extern int proc_detach(struct proc_handle *, int);
extern int proc_getflags(struct proc_handle *);
extern int proc_name2sym(struct proc_handle *, const char *, const char *,
                         GElf_Sym *, prsyminfo_t *);
extern int proc_setflags(struct proc_handle *, int);
extern void proc_free(struct proc_handle *);
extern pid_t proc_getpid(struct proc_handle *);
extern int proc_continue(struct proc_handle *);
extern HANDLE proc_gethandle(struct proc_handle *);

#define Pxlookup_by_name(p, l, s1, s2, sym, a) proc_name2sym(p, s1, s2, sym, a)
#define Paddr_to_map proc_addr2map
#define Pcreate_error strerror
#define Pgrab_error strerror
#define Plmid_to_map(p, l, o) proc_name2map(p, o)
#define Plookup_by_addr proc_addr2sym
#define Pname_to_map proc_name2map
#define Pobject_iter proc_iter_objs
#define Pobjname proc_objname
#define Prelease proc_detach
#define Psetflags proc_setflags
#define Pstate proc_state
#define Psymbol_iter_by_addr proc_iter_symbyaddr
#define Punsetflags proc_clearflags


