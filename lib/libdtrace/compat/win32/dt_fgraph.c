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

    dt_fgraph.c

Abstract:

    This file implements DTrace/NT function graph builder.

--*/

#include <ntcompat.h>
#include "sys/fasttrap.h"
#include "dt_fgraph.h"
#include "dt_disasm.h"

struct dt_disasm_instr {
    uint8_t size :  4;        // 15b max.
    uint8_t type:   4;        // 'enum dt_disasm_instr_type' - 0..15
};

struct dt_disasm_block {
    struct dt_disasm_block* next;
    uint32_t rva;
    uint32_t size;
};

struct dt_disasm_graph {
    HANDLE hprocess;
    int ftfd;
    uint64_t base;                     // Image base
    uint32_t rva;                      // RVA of the function start
    uint32_t size;                     // Function byte size.
    struct dt_disasm_block block;
    uint8_t* code;
    // struct dt_disasm_instr instr_array[size];
    // uint8_t text[size];
};

static void dt_disasm_free_blocks(
    struct dt_disasm_block* block)
{
    while (NULL != block) {
        struct dt_disasm_block* next_block = block->next;
        free(block);
        block = next_block;
    }
}

static int dt_disasm_analyze(
    struct dt_disasm_graph* graph)
{
    const size_t minisize = dt_disasm_instr_min_size();
    struct dt_disasm_block* block = &graph->block;
    uint32_t offset = block->rva;

    while (offset < graph->size) {
        struct dt_disasm_instr_descr idesc = {0};
        uint32_t isize = dt_disasm_instr_analyze(graph, offset, &idesc);
        if (0 == isize) {
            return 0;
        }

        if ((isize > graph->size) || (offset > (graph->size - isize))) {
            return 0;
        }

        struct dt_disasm_instr* instr =
            (struct dt_disasm_instr*)(graph + 1) + offset / minisize;

        if (idesc.InvOp) {
            instr->type = dt_disasm_instr_type_invop;
        } else if (idesc.IsReturn) {
            instr->type = dt_disasm_instr_type_return;
        } else if (idesc.IsBranch) {
            if (idesc.DynamicBranchTarget) {
                instr->type = dt_disasm_instr_type_branch_dyn;
            } else {
                uint64_t funcaddr = graph->base + graph->rva;
                uint64_t target = idesc.BranchAddress;
                if (idesc.RelativeBranchTarget) {
                    target += funcaddr + offset + isize;
                }

                if ((target < funcaddr) ||
                    (target >= (funcaddr + graph->size))) {
                    instr->type = dt_disasm_instr_type_branch_out;
                } else {
                    instr->type = dt_disasm_instr_type_branch_int;
                    uint32_t inrva = (uint32_t)(target - funcaddr);
                    struct dt_disasm_block* b;
                    struct dt_disasm_block* prev = NULL;
                    for (b = &graph->block; NULL != b; prev = b, b = b->next) {
                        if (b->rva > inrva)  {
                            break;
                        }
                    }

                    if (((prev->rva + prev->size) <= inrva) &&
                        ((0 != prev->size) || (prev->rva != inrva))) {
                        b = malloc(sizeof(struct dt_disasm_block));
                        if (NULL == b) {
                            return 0;
                        }

                        memset(b, 0, sizeof(struct dt_disasm_block));
                        b->next = prev->next;
                        b->rva = inrva;
                        prev->next = b;
                    }
                }

            }
        } else {
            instr->type = dt_disasm_instr_type_other;
        }

        instr->size = (uint8_t)isize;

        offset += isize;
        block->size += isize;

        if (idesc.NoFallThrouth) {
            for (block = &graph->block; NULL != block; block = block->next) {
                if (0 == block->size) {
                    break;
                }
            }

            if (NULL == block) {
                break;
            }

            offset = block->rva;
        }
    }

    return 1;
}

uint32_t dt_disasm_instr_fetch(
    void* context,
    uint32_t pos,
    uint32_t size,
    void* val)
{
    struct dt_disasm_graph* graph = (struct dt_disasm_graph*)context;

    if ((pos + size) > graph->size) {
        return 0;
    }

    memcpy(val, &graph->code[pos], size);

    if ((0 != graph->ftfd) && dt_disasm_instr_is_tracepoint(val, size)) {
        fasttrap_instr_query_t instr;
        instr.ftiq_handle = (uintptr_t)graph->hprocess;
        instr.ftiq_pc = graph->base + graph->rva + pos;
        if (0 == ioctl(graph->ftfd, FASTTRAPIOC_GETINSTR, &instr)) {
            memcpy(val, &instr.ftiq_instr, dt_disasm_instr_min_size());
        }
    }

    return size;
}

void* dt_disasm_malloc(size_t bytes)
{
    return malloc(bytes);
}

void dt_disasm_free(void* p)
{
    free(p);
}

int dt_disasm_build_graph(
    HANDLE hprocess,
    int ftfd,
    uint64_t module_base,
    uint32_t code_rva,
    uint64_t code_base,
    uint32_t code_size,
    struct dt_disasm_graph** graph)
{
    struct dt_disasm_graph* pgraph;
    BOOL islocal = (NULL == hprocess) || (GetCurrentProcess() == hprocess);
    size_t graph_size;
    size_t idesc_size;
    int err;

    idesc_size = (code_size / dt_disasm_instr_min_size()) *
        sizeof(struct dt_disasm_instr);
    graph_size = sizeof(struct dt_disasm_graph) + idesc_size;

    if (!islocal) {
        graph_size += code_size;
    }

    pgraph = malloc(graph_size);
    if (NULL == pgraph) {
        err = errno;
        goto error;
    }

    memset(pgraph, 0, graph_size);
    pgraph->hprocess = hprocess;
    pgraph->ftfd = ftfd;
    pgraph->base = module_base;
    pgraph->rva = code_rva;
    pgraph->size = code_size;

    if (islocal) {
        pgraph->code = (uint8_t*)(uintptr_t)code_base;
    } else {
        pgraph->code = (uint8_t*)(pgraph + 1) + idesc_size;
    }

    if (!islocal) {
        SIZE_T done;
        if (!ReadProcessMemory(hprocess, (const void*)(uintptr_t)code_base,
                               pgraph->code, code_size, &done) ||
            (code_size != done)) {

            err = EACCES;
            goto error;
        }
    }

    if (!dt_disasm_analyze(pgraph)) {
        err = -1;
        goto error;
    }

    *graph = pgraph;
    return 0;

error:
    dt_disasm_free_graph(pgraph);
    return err;
}

void dt_disasm_free_graph(
    struct dt_disasm_graph* graph)
{
    dt_disasm_free_blocks(graph->block.next);
    free(graph);
}

int dt_disasm_walk_graph(
    struct dt_disasm_graph* graph,
    uint32_t offset,
    dt_disasm_walk_graph_f* f,
    void* context)
{
    const size_t minisize = dt_disasm_instr_min_size();

    if (offset >= graph->size) {
        return -1;
    }

    if (0 != (offset % minisize)) {
        return -1;
    }

    struct dt_disasm_block* block;
    for (block = &graph->block; NULL != block; block = block->next) {
        if ((offset >= block->rva) && (offset < (block->rva + block->size))) {
            break;
        }
    }

    if (NULL == block) {
        return -1;
    }

    for (;;) {
        struct dt_disasm_instr* instra =
            (struct dt_disasm_instr*)(graph + 1) + (offset / minisize);
        uint8_t isize = instra->size;
        if (isize < minisize) {
            return -1;
        }

        int err = (f)(context,
                      offset,
                      (enum dt_disasm_instr_type)instra->type,
                      isize,
                      graph->code + offset);

        if (err < 0) {
            return err;
        } else if (err > 0) {
            return 0;
        }

        offset += isize;

        if (offset >= (block->size + block->rva)) {
            block = block->next;
            if (NULL == block) {
                return 0;
            }

            offset = block->rva;
        }
    }
}

