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

    dt_disasm.h

Abstract:

    This file defines DTrace/NT disassembler helpers.

--*/

//
// Internal interface between the graph builder and disassembly engine.
//

struct dt_disasm_instr_descr {
    uint8_t InvOp;
    uint8_t NoFallThrouth;
    uint8_t IsReturn;
    uint8_t IsBranch;
    uint8_t DynamicBranchTarget;
    uint8_t RelativeBranchTarget;
    int64_t BranchAddress;
};

extern uint32_t dt_disasm_instr_analyze(
    void* context,
    uint32_t pos,
    struct dt_disasm_instr_descr* idesc);

extern int dt_disasm_instr_is_tracepoint(const void* val, uint32_t size);

extern size_t dt_disasm_instr_min_size(void);

//
// Graph builder provides the following helper to access an instruction stream:
//

extern uint32_t dt_disasm_instr_fetch(
    void* context,
    uint32_t pos,
    uint32_t size,
    void* val);

