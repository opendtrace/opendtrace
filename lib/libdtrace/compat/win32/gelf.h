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

    gelf.h

Abstract:

    This file defines types for the symbol information support in the
    DTrace/NT compatibility layer.

--*/

#pragma once

typedef uint64_t GElf_Addr;   // Image address.
typedef uint64_t GElf_Xword;  // Image offsets

typedef struct GElf_Sym {
    GElf_Addr st_value;       // Symbol address
    const char* st_namep;     // A pointer to the symbol name in a
                              // process-wide cache.
    size_t st_size;           // Symbol size.
    uint32_t st_tag;          // enum SymTagEnum (see SYMBOL_INFO for details)
    uint32_t st_type_idx;     // Type index (see SYMBOL_INFO for details)
} GElf_Sym;


