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

    dt_fgraph.h

Abstract:

    This file defines DTrace/NT disassembler helpers.

--*/


//
// External interface to the graph builder.
//

struct dt_disasm_graph;

enum dt_disasm_instr_type {
    dt_disasm_instr_type_invop = 0,   // not an instruction.
    dt_disasm_instr_type_other,       // a generic instruction.
    dt_disasm_instr_type_return,      // a variation of 'ret'.
    dt_disasm_instr_type_branch_out,  // branch outside of this function.
    dt_disasm_instr_type_branch_int,  // branch inside of this function.
    dt_disasm_instr_type_branch_dyn,  // branch to unknown destination.
};

typedef int dt_disasm_walk_graph_f(
    void* context,
    uint32_t offset,
    enum dt_disasm_instr_type instr_type,
    uint8_t instr_size,
    const uint8_t* instr);

extern int dt_disasm_build_graph(
    HANDLE hprocess,
    int ftfd,
    uint64_t module_base,
    uint32_t code_rva,
    uint64_t code_base,
    uint32_t code_size,
    struct dt_disasm_graph** graph);


extern void dt_disasm_free_graph(
    struct dt_disasm_graph* graph);

extern int dt_disasm_walk_graph(
    struct dt_disasm_graph* graph,
    uint32_t offset,
    dt_disasm_walk_graph_f* f,
    void* context);



