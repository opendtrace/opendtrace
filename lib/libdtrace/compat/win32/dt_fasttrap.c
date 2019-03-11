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

    dt_fasttrap.c

Abstract:

    This file implements DTrace interface to the fasttrap driver
    for DTrace/NT compatibility layer.

--*/

#include <ntcompat.h>

#include <dt_impl.h>
#include <dt_pid.h>

#include "dt_fgraph.h"

int
dt_pid_create_entry_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
                          fasttrap_probe_spec_t *ftp, const GElf_Sym *symp)
{
    ftp->ftps_handle = (ULONG_PTR)proc_gethandle(P);
    ftp->ftps_type = DTFTP_ENTRY;
    ftp->ftps_pc = symp->st_value;
    ftp->ftps_size = symp->st_size;
    ftp->ftps_noffs = 1;
    ftp->ftps_offs[0] = 0;

    if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
        dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
                   strerror(errno));
        return (dt_set_errno(dtp, errno));
    }

    return (1);
}

static dt_disasm_walk_graph_f dt_pid_create_return_probe_walker;
static int dt_pid_create_return_probe_walker(void* context, uint32_t offset,
    enum dt_disasm_instr_type instr_type, uint8_t instr_size, const uint8_t* instr)
{
    fasttrap_probe_spec_t *ftp = (fasttrap_probe_spec_t *)context;
    if (dt_disasm_instr_type_return == instr_type) {
        ftp->ftps_offs[ftp->ftps_noffs++] = offset;
    }

    return 0;
}

int
dt_pid_create_return_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, uint64_t *stret)
{
    struct dt_disasm_graph* graph;
    int err;

    ftp->ftps_handle = (ULONG_PTR)proc_gethandle(P);
    ftp->ftps_type = DTFTP_RETURN;
    ftp->ftps_pc = (uintptr_t)symp->st_value;
    ftp->ftps_size = (size_t)symp->st_size;
    ftp->ftps_noffs = 0;

    err = dt_disasm_build_graph(proc_gethandle(P), dtp->dt_ftfd,
                                (uintptr_t)symp->st_value, 0,
                                (uintptr_t)symp->st_value, (uint32_t)symp->st_size,
                                &graph);
    if (0 != err) {
        dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                   proc_getpid(P), strerror(err));

        return (dt_set_errno(dtp, err));
    }

    err = dt_disasm_walk_graph(graph, 0, dt_pid_create_return_probe_walker, ftp);
    dt_disasm_free_graph(graph);
    if (0 != err) {
        dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                   proc_getpid(P), strerror(err));

        return (dt_set_errno(dtp, err));
    }

    if (ftp->ftps_noffs > 0) {
        if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
            dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
                       strerror(errno));
            return (dt_set_errno(dtp, errno));
        }
    }

    return ftp->ftps_noffs;
}

static dt_disasm_walk_graph_f dt_pid_create_offset_probe_walker;
static int dt_pid_create_offset_probe_walker(void* context,
    uint32_t offset, enum dt_disasm_instr_type instr_type, uint8_t instr_size,
    const uint8_t* instr)

{
    fasttrap_probe_spec_t *ftp = (fasttrap_probe_spec_t *)context;
    ftp->ftps_offs[0] = offset;
    return 1;
}

int
dt_pid_create_offset_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, ulong_t off)
{
    struct dt_disasm_graph* graph;
    int err;

    ftp->ftps_handle = (ULONG_PTR)proc_gethandle(P);
    ftp->ftps_type = DTFTP_OFFSETS;
    ftp->ftps_pc = (uintptr_t)symp->st_value;
    ftp->ftps_size = (size_t)symp->st_size;
    ftp->ftps_noffs = 1;

    if (strcmp("-", ftp->ftps_func) == 0) {
        ftp->ftps_offs[0] = off;
    } else {
        err = dt_disasm_build_graph(proc_gethandle(P), dtp->dt_ftfd,
                                    (uintptr_t)symp->st_value, 0,
                                    (uintptr_t)symp->st_value, (uint32_t)symp->st_size,
                                    &graph);
        if (0 != err) {
            dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                       proc_getpid(P), strerror(err));

            return (dt_set_errno(dtp, err));
        }

        err = dt_disasm_walk_graph(graph, off, dt_pid_create_offset_probe_walker, ftp);
        dt_disasm_free_graph(graph);
        if (0 != err) {
            dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                       proc_getpid(P), strerror(err));

            return (dt_set_errno(dtp, err));
        }
    }

    if (ftp->ftps_noffs > 0) {
        if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
            dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
                       strerror(errno));
            return (dt_set_errno(dtp, errno));
        }
    }

    return ftp->ftps_noffs;
}

struct dt_pid_create_glob_offset_probe_walker_context {
    fasttrap_probe_spec_t *ftp;
    int matchall;
    const char* pattern;
};

static dt_disasm_walk_graph_f dt_pid_create_glob_offset_probe_walker;
static int dt_pid_create_glob_offset_probe_walker(void* context,
    uint32_t offset, enum dt_disasm_instr_type instr_type, uint8_t instr_size,
    const uint8_t* instr)

{
    struct dt_pid_create_glob_offset_probe_walker_context *ctx =
        (struct dt_pid_create_glob_offset_probe_walker_context*)context;
    fasttrap_probe_spec_t *ftp = ctx->ftp;

    if (ctx->matchall) {
        ftp->ftps_offs[ftp->ftps_noffs++] = offset;
    } else {
        char name[33];
        (void) snprintf(name, sizeof (name), "%I64x", (uint64_t)offset);
        if (gmatch(name, ctx->pattern)) {
            ftp->ftps_offs[ftp->ftps_noffs++] = offset;
        }
    }

    return 0;
}

int
dt_pid_create_glob_offset_probes(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, const char *pattern)
{
    struct dt_pid_create_glob_offset_probe_walker_context ctx;
    struct dt_disasm_graph* graph;
    int err;

    ftp->ftps_handle = (ULONG_PTR)proc_gethandle(P);
    ftp->ftps_type = DTFTP_OFFSETS;
    ftp->ftps_pc = (uintptr_t)symp->st_value;
    ftp->ftps_size = (size_t)symp->st_size;
    ftp->ftps_noffs = 0;

    ctx.matchall = (0 == strcmp("*", pattern));
    ctx.pattern = pattern;
    ctx.ftp = ftp;

    err = dt_disasm_build_graph(proc_gethandle(P), dtp->dt_ftfd,
                                (uintptr_t)symp->st_value, 0,
                                (uintptr_t)symp->st_value, (uint32_t)symp->st_size,
                                &graph);
    if (0 != err) {
        dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                   proc_getpid(P), strerror(err));

        return (dt_set_errno(dtp, err));
    }
    err = dt_disasm_walk_graph(graph, 0, dt_pid_create_glob_offset_probe_walker, &ctx);
    dt_disasm_free_graph(graph);
    if (0 != err) {
        dt_dprintf("fasttrap probe creation failed to disassemble pid %d, %s\n",
                   proc_getpid(P), strerror(err));

        return (dt_set_errno(dtp, err));
    }

    if (ftp->ftps_noffs > 0) {
        if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
            dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
                       strerror(errno));
            return (dt_set_errno(dtp, errno));
        }
    }

    return ftp->ftps_noffs;
}

