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

    dt_disasm.c

Abstract:

    This file implements DTrace/NT disassembler helpers.

    The disassembly engine is strictly limited to satisfy the
    needs of building a function graph to find its exit points and
    validate instruction boundaries, and do it as fast as possible.

--*/

#include <stdlib.h>
#include <stdint.h>

#include "dt_disasm.h"

#pragma warning(disable:4100) // '...': unreferenced formal parameter
#pragma warning(disable:4115) // '...': named type definition in parentheses

#if defined(_M_AMD64) || defined(_M_IX86)

#if defined(_M_AMD64)
#define DT_DISASM_TARGET_64 1
#else
#define DT_DISASM_TARGET_64 0
#endif

enum dt_disasm_instr_branch_base {
    dt_disasm_instr_branch_type_None = 0,
};

struct dt_disasm_instr_state {
    uint8_t OperandOverride;
    uint8_t AddressOverride;
    uint8_t RexOverride;
};

typedef uint32_t (dt_disasm_instr_f)(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc
    );

static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeBytes;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeBytesJump;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeBytesPrefix;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeBytesRex;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeBytesVex;
static dt_disasm_instr_f dt_disasm_instr_f_Analyze0F;
static dt_disasm_instr_f dt_disasm_instr_f_Analyze66;
static dt_disasm_instr_f dt_disasm_instr_f_Analyze67;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeF6;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeF7;
static dt_disasm_instr_f dt_disasm_instr_f_AnalyzeFF;
static dt_disasm_instr_f dt_disasm_instr_f_Analyze0F38;
static dt_disasm_instr_f dt_disasm_instr_f_Analyze0F3A;
static dt_disasm_instr_f dt_disasm_instr_f_Invalid;

#define ENTRY_HandleBytes1            1, 1, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes1Ret         1, 1, 0, 0, 0, NOTHROUGH|RET, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes2            2, 2, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes2Jump        2, 2, 0, 1, 0, 0, dt_disasm_instr_f_AnalyzeBytesJump
#define ENTRY_HandleBytes2JumpNoThrouth  2, 2, 0, 1, 0, NOTHROUGH, dt_disasm_instr_f_AnalyzeBytesJump
#define ENTRY_HandleBytes2Dynamic     2, 2, 0, 0, 0, DYNAMIC, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3            3, 3, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Ret         3, 3, 0, 0, 0, NOTHROUGH|RET, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Dynamic     3, 3, 0, 0, 0, DYNAMIC, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Or5         5, 3, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Or5Rex      5, 3, 0, 0, 0, REX, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Or5Target   5, 3, 0, 1, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Or5NoThroughTarget   5, 3, 0, 1, 0, NOTHROUGH, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes5Or7         7, 5, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes5Or7Dynamic  7, 5, 0, 0, 0, DYNAMIC, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes5Or7NoThroughDynamic  7, 5, 0, 0, 0, NOTHROUGH|DYNAMIC, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Or5Address  5, 3, 0, 0, 0, ADDRESS, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes4            4, 4, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes5            5, 5, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes7            7, 7, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes2Mod         2, 2, 1, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes2Mod1        3, 3, 1, 0, 1, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes2ModOperand  6, 4, 1, 0, 4, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytes3Mod         3, 3, 2, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytes
#define ENTRY_HandleBytesPrefix       1, 1, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytesPrefix
#define ENTRY_HandleBytesRex          1, 1, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytesRex
#define ENTRY_HandleBytesVex          1, 1, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeBytesVex
#define ENTRY_Handle0F                1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Analyze0F
#define ENTRY_Handle66                1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Analyze66
#define ENTRY_Handle67                1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Analyze67
#define ENTRY_HandleF6                0, 0, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeF6
#define ENTRY_HandleF7                0, 0, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeF7
#define ENTRY_HandleFF                0, 0, 0, 0, 0, 0, dt_disasm_instr_f_AnalyzeFF
#define ENTRY_Handle0F38              1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Analyze0F38
#define ENTRY_Handle0F3A              1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Analyze0F3A
#define ENTRY_Invalid                 1, 1, 0, 0, 0, 0, dt_disasm_instr_f_Invalid

enum dt_disasm_instr_flags {
    DYNAMIC     = 0x01u,
    ADDRESS     = 0x02u,
    NOTHROUGH   = 0x04u,
    REX         = 0x08u,
    RET         = 0x10u,
};

enum dt_disasm_instr_modrm_flags {
    SIB         = 0x10u,
    RIP         = 0x20u,
    NOTSIB      = 0x0fu,
};

struct dt_disasm_instr_desc {
    uint32_t       Opcode         : 8;    // Opcode
    uint32_t       FixedSize      : 4;    // Fixed size of opcode
    uint32_t       FixedSize16    : 4;    // Fixed size when 16 bit operand
    uint32_t       ModOffset      : 3;    // Offset to mod/rm byte (0=none)
    uint32_t       RelOffset      : 1;    // Offset to relative target.
    uint32_t       TargetBack     : 4;    // Offset back to absolute or rip target
    uint32_t       FlagBits       : 5;    // Flags for DYNAMIC, etc.
    dt_disasm_instr_f* Func;              // Function pointer.
};

static const uint8_t dt_disasm_instr_modrm[256] = {
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 0x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 1x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 2x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 3x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 4x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 5x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 6x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 7x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 8x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 9x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Ax
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Bx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Cx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Dx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Ex
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  // Fx
};

static const struct dt_disasm_instr_desc dt_disasm_instr_table[257] = {
    { 0x00, ENTRY_HandleBytes2Mod },                      // ADD /r
    { 0x01, ENTRY_HandleBytes2Mod },                      // ADD /r
    { 0x02, ENTRY_HandleBytes2Mod },                      // ADD /r
    { 0x03, ENTRY_HandleBytes2Mod },                      // ADD /r
    { 0x04, ENTRY_HandleBytes2 },                         // ADD ib
    { 0x05, ENTRY_HandleBytes3Or5 },                      // ADD iw
    { 0x06, ENTRY_HandleBytes1 },                         // PUSH
    { 0x07, ENTRY_HandleBytes1 },                         // POP
    { 0x08, ENTRY_HandleBytes2Mod },                      // OR /r
    { 0x09, ENTRY_HandleBytes2Mod },                      // OR /r
    { 0x0A, ENTRY_HandleBytes2Mod },                      // OR /r
    { 0x0B, ENTRY_HandleBytes2Mod },                      // OR /r
    { 0x0C, ENTRY_HandleBytes2 },                         // OR ib
    { 0x0D, ENTRY_HandleBytes3Or5 },                      // OR iw
    { 0x0E, ENTRY_HandleBytes1 },                         // PUSH
    { 0x0F, ENTRY_Handle0F },                             // Extension Ops
    { 0x10, ENTRY_HandleBytes2Mod },                      // ADC /r
    { 0x11, ENTRY_HandleBytes2Mod },                      // ADC /r
    { 0x12, ENTRY_HandleBytes2Mod },                      // ADC /r
    { 0x13, ENTRY_HandleBytes2Mod },                      // ADC /r
    { 0x14, ENTRY_HandleBytes2 },                         // ADC ib
    { 0x15, ENTRY_HandleBytes3Or5 },                      // ADC id
    { 0x16, ENTRY_HandleBytes1 },                         // PUSH
    { 0x17, ENTRY_HandleBytes1 },                         // POP
    { 0x18, ENTRY_HandleBytes2Mod },                      // SBB /r
    { 0x19, ENTRY_HandleBytes2Mod },                      // SBB /r
    { 0x1A, ENTRY_HandleBytes2Mod },                      // SBB /r
    { 0x1B, ENTRY_HandleBytes2Mod },                      // SBB /r
    { 0x1C, ENTRY_HandleBytes2 },                         // SBB ib
    { 0x1D, ENTRY_HandleBytes3Or5 },                      // SBB id
    { 0x1E, ENTRY_HandleBytes1 },                         // PUSH
    { 0x1F, ENTRY_HandleBytes1 },                         // POP
    { 0x20, ENTRY_HandleBytes2Mod },                      // AND /r
    { 0x21, ENTRY_HandleBytes2Mod },                      // AND /r
    { 0x22, ENTRY_HandleBytes2Mod },                      // AND /r
    { 0x23, ENTRY_HandleBytes2Mod },                      // AND /r
    { 0x24, ENTRY_HandleBytes2 },                         // AND ib
    { 0x25, ENTRY_HandleBytes3Or5 },                      // AND id
    { 0x26, ENTRY_HandleBytesPrefix },                    // ES prefix
    { 0x27, ENTRY_HandleBytes1 },                         // DAA
    { 0x28, ENTRY_HandleBytes2Mod },                      // SUB /r
    { 0x29, ENTRY_HandleBytes2Mod },                      // SUB /r
    { 0x2A, ENTRY_HandleBytes2Mod },                      // SUB /r
    { 0x2B, ENTRY_HandleBytes2Mod },                      // SUB /r
    { 0x2C, ENTRY_HandleBytes2 },                         // SUB ib
    { 0x2D, ENTRY_HandleBytes3Or5 },                      // SUB id
    { 0x2E, ENTRY_HandleBytesPrefix },                    // CS prefix
    { 0x2F, ENTRY_HandleBytes1 },                         // DAS
    { 0x30, ENTRY_HandleBytes2Mod },                      // XOR /r
    { 0x31, ENTRY_HandleBytes2Mod },                      // XOR /r
    { 0x32, ENTRY_HandleBytes2Mod },                      // XOR /r
    { 0x33, ENTRY_HandleBytes2Mod },                      // XOR /r
    { 0x34, ENTRY_HandleBytes2 },                         // XOR ib
    { 0x35, ENTRY_HandleBytes3Or5 },                      // XOR id
    { 0x36, ENTRY_HandleBytesPrefix },                    // SS prefix
    { 0x37, ENTRY_HandleBytes1 },                         // AAA
    { 0x38, ENTRY_HandleBytes2Mod },                      // CMP /r
    { 0x39, ENTRY_HandleBytes2Mod },                      // CMP /r
    { 0x3A, ENTRY_HandleBytes2Mod },                      // CMP /r
    { 0x3B, ENTRY_HandleBytes2Mod },                      // CMP /r
    { 0x3C, ENTRY_HandleBytes2 },                         // CMP ib
    { 0x3D, ENTRY_HandleBytes3Or5 },                      // CMP id
    { 0x3E, ENTRY_HandleBytesPrefix },                    // DS prefix
    { 0x3F, ENTRY_HandleBytes1 },                         // AAS
#if DT_DISASM_TARGET_64 // For Rex Prefix
    { 0x40, ENTRY_HandleBytesRex },                       // Rex
    { 0x41, ENTRY_HandleBytesRex },                       // Rex
    { 0x42, ENTRY_HandleBytesRex },                       // Rex
    { 0x43, ENTRY_HandleBytesRex },                       // Rex
    { 0x44, ENTRY_HandleBytesRex },                       // Rex
    { 0x45, ENTRY_HandleBytesRex },                       // Rex
    { 0x46, ENTRY_HandleBytesRex },                       // Rex
    { 0x47, ENTRY_HandleBytesRex },                       // Rex
    { 0x48, ENTRY_HandleBytesRex },                       // Rex
    { 0x49, ENTRY_HandleBytesRex },                       // Rex
    { 0x4A, ENTRY_HandleBytesRex },                       // Rex
    { 0x4B, ENTRY_HandleBytesRex },                       // Rex
    { 0x4C, ENTRY_HandleBytesRex },                       // Rex
    { 0x4D, ENTRY_HandleBytesRex },                       // Rex
    { 0x4E, ENTRY_HandleBytesRex },                       // Rex
    { 0x4F, ENTRY_HandleBytesRex },                       // Rex
#else
    { 0x40, ENTRY_HandleBytes1 },                         // INC
    { 0x41, ENTRY_HandleBytes1 },                         // INC
    { 0x42, ENTRY_HandleBytes1 },                         // INC
    { 0x43, ENTRY_HandleBytes1 },                         // INC
    { 0x44, ENTRY_HandleBytes1 },                         // INC
    { 0x45, ENTRY_HandleBytes1 },                         // INC
    { 0x46, ENTRY_HandleBytes1 },                         // INC
    { 0x47, ENTRY_HandleBytes1 },                         // INC
    { 0x48, ENTRY_HandleBytes1 },                         // DEC
    { 0x49, ENTRY_HandleBytes1 },                         // DEC
    { 0x4A, ENTRY_HandleBytes1 },                         // DEC
    { 0x4B, ENTRY_HandleBytes1 },                         // DEC
    { 0x4C, ENTRY_HandleBytes1 },                         // DEC
    { 0x4D, ENTRY_HandleBytes1 },                         // DEC
    { 0x4E, ENTRY_HandleBytes1 },                         // DEC
    { 0x4F, ENTRY_HandleBytes1 },                         // DEC
#endif
    { 0x50, ENTRY_HandleBytes1 },                         // PUSH
    { 0x51, ENTRY_HandleBytes1 },                         // PUSH
    { 0x52, ENTRY_HandleBytes1 },                         // PUSH
    { 0x53, ENTRY_HandleBytes1 },                         // PUSH
    { 0x54, ENTRY_HandleBytes1 },                         // PUSH
    { 0x55, ENTRY_HandleBytes1 },                         // PUSH
    { 0x56, ENTRY_HandleBytes1 },                         // PUSH
    { 0x57, ENTRY_HandleBytes1 },                         // PUSH
    { 0x58, ENTRY_HandleBytes1 },                         // POP
    { 0x59, ENTRY_HandleBytes1 },                         // POP
    { 0x5A, ENTRY_HandleBytes1 },                         // POP
    { 0x5B, ENTRY_HandleBytes1 },                         // POP
    { 0x5C, ENTRY_HandleBytes1 },                         // POP
    { 0x5D, ENTRY_HandleBytes1 },                         // POP
    { 0x5E, ENTRY_HandleBytes1 },                         // POP
    { 0x5F, ENTRY_HandleBytes1 },                         // POP
    { 0x60, ENTRY_HandleBytes1 },                         // PUSHAD
    { 0x61, ENTRY_HandleBytes1 },                         // POPAD
    { 0x62, ENTRY_HandleBytes2Mod },                      // BOUND /r
    { 0x63, ENTRY_HandleBytes2Mod },                      // ARPL /r
    { 0x64, ENTRY_HandleBytesPrefix },                    // FS prefix
    { 0x65, ENTRY_HandleBytesPrefix },                    // GS prefix
    { 0x66, ENTRY_Handle66 },                             // Operand Prefix
    { 0x67, ENTRY_Handle67 },                             // Address Prefix
    { 0x68, ENTRY_HandleBytes3Or5 },                      // PUSH
    { 0x69, ENTRY_HandleBytes2ModOperand },               //
    { 0x6A, ENTRY_HandleBytes2 },                         // PUSH
    { 0x6B, ENTRY_HandleBytes2Mod1 },                     // IMUL /r ib
    { 0x6C, ENTRY_HandleBytes1 },                         // INS
    { 0x6D, ENTRY_HandleBytes1 },                         // INS
    { 0x6E, ENTRY_HandleBytes1 },                         // OUTS/OUTSB
    { 0x6F, ENTRY_HandleBytes1 },                         // OUTS/OUTSW
    { 0x70, ENTRY_HandleBytes2Jump },                     // JO           // 0f80
    { 0x71, ENTRY_HandleBytes2Jump },                     // JNO          // 0f81
    { 0x72, ENTRY_HandleBytes2Jump },                     // JB/JC/JNAE   // 0f82
    { 0x73, ENTRY_HandleBytes2Jump },                     // JAE/JNB/JNC  // 0f83
    { 0x74, ENTRY_HandleBytes2Jump },                     // JE/JZ        // 0f84
    { 0x75, ENTRY_HandleBytes2Jump },                     // JNE/JNZ      // 0f85
    { 0x76, ENTRY_HandleBytes2Jump },                     // JBE/JNA      // 0f86
    { 0x77, ENTRY_HandleBytes2Jump },                     // JA/JNBE      // 0f87
    { 0x78, ENTRY_HandleBytes2Jump },                     // JS           // 0f88
    { 0x79, ENTRY_HandleBytes2Jump },                     // JNS          // 0f89
    { 0x7A, ENTRY_HandleBytes2Jump },                     // JP/JPE       // 0f8a
    { 0x7B, ENTRY_HandleBytes2Jump },                     // JNP/JPO      // 0f8b
    { 0x7C, ENTRY_HandleBytes2Jump },                     // JL/JNGE      // 0f8c
    { 0x7D, ENTRY_HandleBytes2Jump },                     // JGE/JNL      // 0f8d
    { 0x7E, ENTRY_HandleBytes2Jump },                     // JLE/JNG      // 0f8e
    { 0x7F, ENTRY_HandleBytes2Jump },                     // JG/JNLE      // 0f8f
    { 0x80, ENTRY_HandleBytes2Mod1 },                     // ADC/2 ib, etc.s
    { 0x81, ENTRY_HandleBytes2ModOperand },               //
    { 0x82, ENTRY_HandleBytes2 },                         // MOV al,x
    { 0x83, ENTRY_HandleBytes2Mod1 },                     // ADC/2 ib, etc.
    { 0x84, ENTRY_HandleBytes2Mod },                      // TEST /r
    { 0x85, ENTRY_HandleBytes2Mod },                      // TEST /r
    { 0x86, ENTRY_HandleBytes2Mod },                      // XCHG /r
    { 0x87, ENTRY_HandleBytes2Mod },                      // XCHG /r
    { 0x88, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x89, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x8A, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x8B, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x8C, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x8D, ENTRY_HandleBytes2Mod },                      // LEA /r
    { 0x8E, ENTRY_HandleBytes2Mod },                      // MOV /r
    { 0x8F, ENTRY_HandleBytes2Mod },                      // POP /0
    { 0x90, ENTRY_HandleBytes1 },                         // NOP
    { 0x91, ENTRY_HandleBytes1 },                         // XCHG
    { 0x92, ENTRY_HandleBytes1 },                         // XCHG
    { 0x93, ENTRY_HandleBytes1 },                         // XCHG
    { 0x94, ENTRY_HandleBytes1 },                         // XCHG
    { 0x95, ENTRY_HandleBytes1 },                         // XCHG
    { 0x96, ENTRY_HandleBytes1 },                         // XCHG
    { 0x97, ENTRY_HandleBytes1 },                         // XCHG
    { 0x98, ENTRY_HandleBytes1 },                         // CWDE
    { 0x99, ENTRY_HandleBytes1 },                         // CDQ
    { 0x9A, ENTRY_HandleBytes5Or7Dynamic },               // CALL cp
    { 0x9B, ENTRY_HandleBytes1 },                         // WAIT/FWAIT
    { 0x9C, ENTRY_HandleBytes1 },                         // PUSHFD
    { 0x9D, ENTRY_HandleBytes1 },                         // POPFD
    { 0x9E, ENTRY_HandleBytes1 },                         // SAHF
    { 0x9F, ENTRY_HandleBytes1 },                         // LAHF
    { 0xA0, ENTRY_HandleBytes3Or5Address },               // MOV
    { 0xA1, ENTRY_HandleBytes3Or5Address },               // MOV
    { 0xA2, ENTRY_HandleBytes3Or5Address },               // MOV
    { 0xA3, ENTRY_HandleBytes3Or5Address },               // MOV
    { 0xA4, ENTRY_HandleBytes1 },                         // MOVS
    { 0xA5, ENTRY_HandleBytes1 },                         // MOVS/MOVSD
    { 0xA6, ENTRY_HandleBytes1 },                         // CMPS/CMPSB
    { 0xA7, ENTRY_HandleBytes1 },                         // CMPS/CMPSW
    { 0xA8, ENTRY_HandleBytes2 },                         // TEST
    { 0xA9, ENTRY_HandleBytes3Or5 },                      // TEST
    { 0xAA, ENTRY_HandleBytes1 },                         // STOS/STOSB
    { 0xAB, ENTRY_HandleBytes1 },                         // STOS/STOSW
    { 0xAC, ENTRY_HandleBytes1 },                         // LODS/LODSB
    { 0xAD, ENTRY_HandleBytes1 },                         // LODS/LODSW
    { 0xAE, ENTRY_HandleBytes1 },                         // SCAS/SCASB
    { 0xAF, ENTRY_HandleBytes1 },                         // SCAS/SCASD
    { 0xB0, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB1, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB2, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB3, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB4, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB5, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB6, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB7, ENTRY_HandleBytes2 },                         // MOV B0+rb
    { 0xB8, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xB9, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBA, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBB, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBC, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBD, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBE, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xBF, ENTRY_HandleBytes3Or5Rex },                   // MOV B8+rb
    { 0xC0, ENTRY_HandleBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC1, ENTRY_HandleBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC2, ENTRY_HandleBytes3Ret },                      // RET n
    { 0xC3, ENTRY_HandleBytes1Ret },                      // RET
#if DT_DISASM_TARGET_64 // For Rex Prefix
    { 0xC4, ENTRY_HandleBytesVex },                       // VEX 3-byte prefix
    { 0xC5, ENTRY_HandleBytesVex },                       // VEX 2-byte prefix
#else
    { 0xC4, ENTRY_HandleBytes2Mod },                      // LES
    { 0xC5, ENTRY_HandleBytes2Mod },                      // LDS
#endif
    { 0xC6, ENTRY_HandleBytes2Mod1 },                     // MOV
    { 0xC7, ENTRY_HandleBytes2ModOperand },               // MOV
    { 0xC8, ENTRY_HandleBytes4 },                         // ENTER
    { 0xC9, ENTRY_HandleBytes1 },                         // LEAVE
    { 0xCA, ENTRY_HandleBytes3Ret },                      // RETFn
    { 0xCB, ENTRY_HandleBytes1Ret },                      // RETF
    { 0xCC, ENTRY_HandleBytes1 },                         // INT 3
    { 0xCD, ENTRY_HandleBytes2 },                         // INT ib
    { 0xCE, ENTRY_HandleBytes1 },                         // INTO
    { 0xCF, ENTRY_HandleBytes1Ret },                      // IRET
    { 0xD0, ENTRY_HandleBytes2Mod },                      // RCL/2, etc.
    { 0xD1, ENTRY_HandleBytes2Mod },                      // RCL/2, etc.
    { 0xD2, ENTRY_HandleBytes2Mod },                      // RCL/2, etc.
    { 0xD3, ENTRY_HandleBytes2Mod },                      // RCL/2, etc.
    { 0xD4, ENTRY_HandleBytes2 },                         // AAM
    { 0xD5, ENTRY_HandleBytes2 },                         // AAD
    { 0xD6, ENTRY_Invalid },                              //
    { 0xD7, ENTRY_HandleBytes1 },                         // XLAT/XLATB
    { 0xD8, ENTRY_HandleBytes2Mod },                      // FADD, etc.
    { 0xD9, ENTRY_HandleBytes2Mod },                      // F2XM1, etc.
    { 0xDA, ENTRY_HandleBytes2Mod },                      // FLADD, etc.
    { 0xDB, ENTRY_HandleBytes2Mod },                      // FCLEX, etc.
    { 0xDC, ENTRY_HandleBytes2Mod },                      // FADD/0, etc.
    { 0xDD, ENTRY_HandleBytes2Mod },                      // FFREE, etc.
    { 0xDE, ENTRY_HandleBytes2Mod },                      // FADDP, etc.
    { 0xDF, ENTRY_HandleBytes2Mod },                      // FBLD/4, etc.
    { 0xE0, ENTRY_HandleBytes2Jump },                     // LOOPNE cb
    { 0xE1, ENTRY_HandleBytes2Jump },                     // LOOPE cb
    { 0xE2, ENTRY_HandleBytes2Jump },                     // LOOP cb
    { 0xE3, ENTRY_HandleBytes2Jump },                     // JCXZ/JECXZ
    { 0xE4, ENTRY_HandleBytes2 },                         // IN ib
    { 0xE5, ENTRY_HandleBytes2 },                         // IN id
    { 0xE6, ENTRY_HandleBytes2 },                         // OUT ib
    { 0xE7, ENTRY_HandleBytes2 },                         // OUT ib
    { 0xE8, ENTRY_HandleBytes3Or5Target },                // CALL cd
    { 0xE9, ENTRY_HandleBytes3Or5NoThroughTarget },       // JMP cd
    { 0xEA, ENTRY_HandleBytes5Or7NoThroughDynamic },      // JMPF cp
    { 0xEB, ENTRY_HandleBytes2JumpNoThrouth },            // JMP cb
    { 0xEC, ENTRY_HandleBytes1 },                         // IN ib
    { 0xED, ENTRY_HandleBytes1 },                         // IN id
    { 0xEE, ENTRY_HandleBytes1 },                         // OUT
    { 0xEF, ENTRY_HandleBytes1 },                         // OUT
    { 0xF0, ENTRY_HandleBytesPrefix },                    // LOCK prefix
    { 0xF1, ENTRY_Invalid },                              //
    { 0xF2, ENTRY_HandleBytesPrefix },                    // REPNE prefix
    { 0xF3, ENTRY_HandleBytesPrefix },                    // REPE prefix
    { 0xF4, ENTRY_HandleBytes1 },                         // HLT
    { 0xF5, ENTRY_HandleBytes1 },                         // CMC
    { 0xF6, ENTRY_HandleF6 },                             // TEST/0, DIV/6
    { 0xF7, ENTRY_HandleF7 },                             // TEST/0, DIV/6
    { 0xF8, ENTRY_HandleBytes1 },                         // CLC
    { 0xF9, ENTRY_HandleBytes1 },                         // STC
    { 0xFA, ENTRY_HandleBytes1 },                         // CLI
    { 0xFB, ENTRY_HandleBytes1 },                         // STI
    { 0xFC, ENTRY_HandleBytes1 },                         // CLD
    { 0xFD, ENTRY_HandleBytes1 },                         // STD
    { 0xFE, ENTRY_HandleBytes2Mod },                      // DEC/1,INC/0
    { 0xFF, ENTRY_HandleFF },                             // CALL/2
};

static const struct dt_disasm_instr_desc dt_disasm_instr_table_0F[257] = {
    { 0x00, ENTRY_HandleBytes2Mod },                      // LLDT/2, etc.
    { 0x01, ENTRY_HandleBytes2Mod },                      // INVLPG/7, etc.
    { 0x02, ENTRY_HandleBytes2Mod },                      // LAR/r
    { 0x03, ENTRY_HandleBytes2Mod },                      // LSL/r
    { 0x04, ENTRY_Invalid },                              // _04
    { 0x05, ENTRY_HandleBytes1 },                         // SYSCALL
    { 0x06, ENTRY_HandleBytes1 },                         // CLTS
    { 0x07, ENTRY_HandleBytes1 },                         // SYSRETQ
    { 0x08, ENTRY_HandleBytes2 },                         // INVD
    { 0x09, ENTRY_HandleBytes1 },                         // WBINVD
    { 0x0A, ENTRY_Invalid },                              // _0A
    { 0x0B, ENTRY_HandleBytes2 },                         // UD2
    { 0x0C, ENTRY_Invalid },                              // _0C
    { 0x0D, ENTRY_HandleBytes2Mod },                      // PREFETCH
    { 0x0E, ENTRY_HandleBytes2 },                         // FEMMS
    { 0x0F, ENTRY_HandleBytes3Mod },                      // 3DNow Opcodes
    { 0x10, ENTRY_HandleBytes2Mod },                      // MOVSS MOVUPD MOVSD
    { 0x11, ENTRY_HandleBytes2Mod },                      // MOVSS MOVUPD MOVSD
    { 0x12, ENTRY_HandleBytes2Mod },                      // MOVLPD
    { 0x13, ENTRY_HandleBytes2Mod },                      // MOVLPD
    { 0x14, ENTRY_HandleBytes2Mod },                      // UNPCKLPD
    { 0x15, ENTRY_HandleBytes2Mod },                      // UNPCKHPD
    { 0x16, ENTRY_HandleBytes2Mod },                      // MOVHPD
    { 0x17, ENTRY_HandleBytes2Mod },                      // MOVHPD
    { 0x18, ENTRY_HandleBytes2Mod },                      // PREFETCHINTA...
    { 0x19, ENTRY_HandleBytes2Mod },                      // _19
    { 0x1A, ENTRY_HandleBytes2Mod },                      // _1A
    { 0x1B, ENTRY_HandleBytes2Mod },                      // _1B
    { 0x1C, ENTRY_HandleBytes2Mod },                      // _1C
    { 0x1D, ENTRY_HandleBytes2Mod },                      // _1D
    { 0x1E, ENTRY_HandleBytes2Mod },                      // rdsspq
    { 0x1F, ENTRY_HandleBytes2Mod },                      // NOP/r
    { 0x20, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x21, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x22, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x23, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x24, ENTRY_Invalid },                              // _24
    { 0x25, ENTRY_Invalid },                              // _25
    { 0x26, ENTRY_Invalid },                              // _26
    { 0x27, ENTRY_Invalid },                              // _27
    { 0x28, ENTRY_HandleBytes2Mod },                      // MOVAPS MOVAPD
    { 0x29, ENTRY_HandleBytes2Mod },                      // MOVAPS MOVAPD
    { 0x2A, ENTRY_HandleBytes2Mod },                      // CVPI2PS &
    { 0x2B, ENTRY_HandleBytes2Mod },                      // MOVNTPS MOVNTPD
    { 0x2C, ENTRY_HandleBytes2Mod },                      // CVTTPS2PI &
    { 0x2D, ENTRY_HandleBytes2Mod },                      // CVTPS2PI &
    { 0x2E, ENTRY_HandleBytes2Mod },                      // UCOMISS UCOMISD
    { 0x2F, ENTRY_HandleBytes2Mod },                      // COMISS COMISD
    { 0x30, ENTRY_HandleBytes1 },                         // WRMSR
    { 0x31, ENTRY_HandleBytes1 },                         // RDTSC
    { 0x32, ENTRY_HandleBytes1 },                         // RDMSR
    { 0x33, ENTRY_HandleBytes1 },                         // RDPMC
    { 0x34, ENTRY_HandleBytes1 },                         // SYSENTER
    { 0x35, ENTRY_HandleBytes1Ret },                      // SYSEXIT
    { 0x36, ENTRY_Invalid },                              // _36
    { 0x37, ENTRY_Invalid },                              // _37
    { 0x38, ENTRY_Handle0F38 },                           // _38
    { 0x39, ENTRY_Invalid },                              // _39
    { 0x3A, ENTRY_Handle0F3A },                           // _3A
    { 0x3B, ENTRY_Invalid },                              // _3B
    { 0x3C, ENTRY_Invalid },                              // _3C
    { 0x3D, ENTRY_Invalid },                              // _3D
    { 0x3E, ENTRY_Invalid },                              // _3E
    { 0x3F, ENTRY_Invalid },                              // _3F
    { 0x40, ENTRY_HandleBytes2Mod },                      // CMOVO (0F 40)
    { 0x41, ENTRY_HandleBytes2Mod },                      // CMOVNO (0F 41)
    { 0x42, ENTRY_HandleBytes2Mod },                      // CMOVB & CMOVNE (0F 42)
    { 0x43, ENTRY_HandleBytes2Mod },                      // CMOVAE & CMOVNB (0F 43)
    { 0x44, ENTRY_HandleBytes2Mod },                      // CMOVE & CMOVZ (0F 44)
    { 0x45, ENTRY_HandleBytes2Mod },                      // CMOVNE & CMOVNZ (0F 45)
    { 0x46, ENTRY_HandleBytes2Mod },                      // CMOVBE & CMOVNA (0F 46)
    { 0x47, ENTRY_HandleBytes2Mod },                      // CMOVA & CMOVNBE (0F 47)
    { 0x48, ENTRY_HandleBytes2Mod },                      // CMOVS (0F 48)
    { 0x49, ENTRY_HandleBytes2Mod },                      // CMOVNS (0F 49)
    { 0x4A, ENTRY_HandleBytes2Mod },                      // CMOVP & CMOVPE (0F 4A)
    { 0x4B, ENTRY_HandleBytes2Mod },                      // CMOVNP & CMOVPO (0F 4B)
    { 0x4C, ENTRY_HandleBytes2Mod },                      // CMOVL & CMOVNGE (0F 4C)
    { 0x4D, ENTRY_HandleBytes2Mod },                      // CMOVGE & CMOVNL (0F 4D)
    { 0x4E, ENTRY_HandleBytes2Mod },                      // CMOVLE & CMOVNG (0F 4E)
    { 0x4F, ENTRY_HandleBytes2Mod },                      // CMOVG & CMOVNLE (0F 4F)
    { 0x50, ENTRY_HandleBytes2Mod },                      // MOVMSKPD MOVMSKPD
    { 0x51, ENTRY_HandleBytes2Mod },                      // SQRTPS &
    { 0x52, ENTRY_HandleBytes2Mod },                      // RSQRTTS RSQRTPS
    { 0x53, ENTRY_HandleBytes2Mod },                      // RCPPS RCPSS
    { 0x54, ENTRY_HandleBytes2Mod },                      // ANDPS ANDPD
    { 0x55, ENTRY_HandleBytes2Mod },                      // ANDNPS ANDNPD
    { 0x56, ENTRY_HandleBytes2Mod },                      // ORPS ORPD
    { 0x57, ENTRY_HandleBytes2Mod },                      // XORPS XORPD
    { 0x58, ENTRY_HandleBytes2Mod },                      // ADDPS &
    { 0x59, ENTRY_HandleBytes2Mod },                      // MULPS &
    { 0x5A, ENTRY_HandleBytes2Mod },                      // CVTPS2PD &
    { 0x5B, ENTRY_HandleBytes2Mod },                      // CVTDQ2PS &
    { 0x5C, ENTRY_HandleBytes2Mod },                      // SUBPS &
    { 0x5D, ENTRY_HandleBytes2Mod },                      // MINPS &
    { 0x5E, ENTRY_HandleBytes2Mod },                      // DIVPS &
    { 0x5F, ENTRY_HandleBytes2Mod },                      // MASPS &
    { 0x60, ENTRY_HandleBytes2Mod },                      // PUNPCKLBW/r
    { 0x61, ENTRY_HandleBytes2Mod },                      // PUNPCKLWD/r
    { 0x62, ENTRY_HandleBytes2Mod },                      // PUNPCKLWD/r
    { 0x63, ENTRY_HandleBytes2Mod },                      // PACKSSWB/r
    { 0x64, ENTRY_HandleBytes2Mod },                      // PCMPGTB/r
    { 0x65, ENTRY_HandleBytes2Mod },                      // PCMPGTW/r
    { 0x66, ENTRY_HandleBytes2Mod },                      // PCMPGTD/r
    { 0x67, ENTRY_HandleBytes2Mod },                      // PACKUSWB/r
    { 0x68, ENTRY_HandleBytes2Mod },                      // PUNPCKHBW/r
    { 0x69, ENTRY_HandleBytes2Mod },                      // PUNPCKHWD/r
    { 0x6A, ENTRY_HandleBytes2Mod },                      // PUNPCKHDQ/r
    { 0x6B, ENTRY_HandleBytes2Mod },                      // PACKSSDW/r
    { 0x6C, ENTRY_HandleBytes2Mod },                      // PUNPCKLQDQ
    { 0x6D, ENTRY_HandleBytes2Mod },                      // PUNPCKHQDQ
    { 0x6E, ENTRY_HandleBytes2Mod },                      // MOVD/r
    { 0x6F, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x70, ENTRY_HandleBytes2Mod1 },                     // PSHUFW/r ib
    { 0x71, ENTRY_HandleBytes2Mod1 },                     // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
    { 0x72, ENTRY_HandleBytes2Mod1 },                     // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
    { 0x73, ENTRY_HandleBytes2Mod1 },                     // PSLLQ/6 ib,PSRLQ/2 ib
    { 0x74, ENTRY_HandleBytes2Mod },                      // PCMPEQB/r
    { 0x75, ENTRY_HandleBytes2Mod },                      // PCMPEQW/r
    { 0x76, ENTRY_HandleBytes2Mod },                      // PCMPEQD/r
    { 0x77, ENTRY_HandleBytes2 },                         // EMMS
    { 0x78, ENTRY_Invalid },                              // _78
    { 0x79, ENTRY_Invalid },                              // _79
    { 0x7A, ENTRY_Invalid },                              // _7A
    { 0x7B, ENTRY_Invalid },                              // _7B
    { 0x7C, ENTRY_Invalid },                              // _7C
    { 0x7D, ENTRY_Invalid },                              // _7D
    { 0x7E, ENTRY_HandleBytes2Mod },                      // MOVD/r
    { 0x7F, ENTRY_HandleBytes2Mod },                      // MOV/r
    { 0x80, ENTRY_HandleBytes3Or5Target },                // JO
    { 0x81, ENTRY_HandleBytes3Or5Target },                // JNO
    { 0x82, ENTRY_HandleBytes3Or5Target },                // JB,JC,JNAE
    { 0x83, ENTRY_HandleBytes3Or5Target },                // JAE,JNB,JNC
    { 0x84, ENTRY_HandleBytes3Or5Target },                // JE,JZ,JZ
    { 0x85, ENTRY_HandleBytes3Or5Target },                // JNE,JNZ
    { 0x86, ENTRY_HandleBytes3Or5Target },                // JBE,JNA
    { 0x87, ENTRY_HandleBytes3Or5Target },                // JA,JNBE
    { 0x88, ENTRY_HandleBytes3Or5Target },                // JS
    { 0x89, ENTRY_HandleBytes3Or5Target },                // JNS
    { 0x8A, ENTRY_HandleBytes3Or5Target },                // JP,JPE
    { 0x8B, ENTRY_HandleBytes3Or5Target },                // JNP,JPO
    { 0x8C, ENTRY_HandleBytes3Or5Target },                // JL,NGE
    { 0x8D, ENTRY_HandleBytes3Or5Target },                // JGE,JNL
    { 0x8E, ENTRY_HandleBytes3Or5Target },                // JLE,JNG
    { 0x8F, ENTRY_HandleBytes3Or5Target },                // JG,JNLE
    { 0x90, ENTRY_HandleBytes2Mod },                      // CMOVO (0F 40)
    { 0x91, ENTRY_HandleBytes2Mod },                      // CMOVNO (0F 41)
    { 0x92, ENTRY_HandleBytes2Mod },                      // CMOVB & CMOVC & CMOVNAE (0F 42)
    { 0x93, ENTRY_HandleBytes2Mod },                      // CMOVAE & CMOVNB & CMOVNC (0F 43)
    { 0x94, ENTRY_HandleBytes2Mod },                      // CMOVE & CMOVZ (0F 44)
    { 0x95, ENTRY_HandleBytes2Mod },                      // CMOVNE & CMOVNZ (0F 45)
    { 0x96, ENTRY_HandleBytes2Mod },                      // CMOVBE & CMOVNA (0F 46)
    { 0x97, ENTRY_HandleBytes2Mod },                      // CMOVA & CMOVNBE (0F 47)
    { 0x98, ENTRY_HandleBytes2Mod },                      // CMOVS (0F 48)
    { 0x99, ENTRY_HandleBytes2Mod },                      // CMOVNS (0F 49)
    { 0x9A, ENTRY_HandleBytes2Mod },                      // CMOVP & CMOVPE (0F 4A)
    { 0x9B, ENTRY_HandleBytes2Mod },                      // CMOVNP & CMOVPO (0F 4B)
    { 0x9C, ENTRY_HandleBytes2Mod },                      // CMOVL & CMOVNGE (0F 4C)
    { 0x9D, ENTRY_HandleBytes2Mod },                      // CMOVGE & CMOVNL (0F 4D)
    { 0x9E, ENTRY_HandleBytes2Mod },                      // CMOVLE & CMOVNG (0F 4E)
    { 0x9F, ENTRY_HandleBytes2Mod },                      // CMOVG & CMOVNLE (0F 4F)
    { 0xA0, ENTRY_HandleBytes1 },                         // PUSH FS
    { 0xA1, ENTRY_HandleBytes1 },                         // POP FS
    { 0xA2, ENTRY_HandleBytes1 },                         // CPUID
    { 0xA3, ENTRY_HandleBytes2Mod },                      // BT  (0F A3)
    { 0xA4, ENTRY_HandleBytes2Mod1 },                     // SHLD
    { 0xA5, ENTRY_HandleBytes2Mod },                      // SHLD
    { 0xA6, ENTRY_Invalid },                              // _A6
    { 0xA7, ENTRY_Invalid },                              // _A7
    { 0xA8, ENTRY_HandleBytes1 },                         // PUSH GS
    { 0xA9, ENTRY_HandleBytes1 },                         // POP GS
    { 0xAA, ENTRY_HandleBytes2 },                         // RSM
    { 0xAB, ENTRY_HandleBytes2Mod },                      // BTS (0F AB)
    { 0xAC, ENTRY_HandleBytes2Mod1 },                     // SHRD
    { 0xAD, ENTRY_HandleBytes2Mod },                      // SHRD
    { 0xAE, ENTRY_HandleBytes2Mod },                      // FXRSTOR/1,FXSAVE/0
    { 0xAF, ENTRY_HandleBytes2Mod },                      // IMUL (0F AF)
    { 0xB0, ENTRY_HandleBytes2Mod },                      // CMPXCHG (0F B0)
    { 0xB1, ENTRY_HandleBytes2Mod },                      // CMPXCHG (0F B1)
    { 0xB2, ENTRY_HandleBytes2Mod },                      // LSS/r
    { 0xB3, ENTRY_HandleBytes2Mod },                      // BTR (0F B3)
    { 0xB4, ENTRY_HandleBytes2Mod },                      // LFS/r
    { 0xB5, ENTRY_HandleBytes2Mod },                      // LGS/r
    { 0xB6, ENTRY_HandleBytes2Mod },                      // MOVZX/r
    { 0xB7, ENTRY_HandleBytes2Mod },                      // MOVZX/r
    { 0xB8, ENTRY_Invalid },                              // _B8
    { 0xB9, ENTRY_Invalid },                              // _B9
    { 0xBA, ENTRY_HandleBytes2Mod1 },                     // BT & BTC & BTR & BTS (0F BA)
    { 0xBB, ENTRY_HandleBytes2Mod },                      // BTC (0F BB)
    { 0xBC, ENTRY_HandleBytes2Mod },                      // BSF (0F BC)
    { 0xBD, ENTRY_HandleBytes2Mod },                      // BSR (0F BD)
    { 0xBE, ENTRY_HandleBytes2Mod },                      // MOVSX/r
    { 0xBF, ENTRY_HandleBytes2Mod },                      // MOVSX/r
    { 0xC0, ENTRY_HandleBytes2Mod },                      // XADD/r
    { 0xC1, ENTRY_HandleBytes2Mod },                      // XADD/r
    { 0xC2, ENTRY_HandleBytes3Mod },                      // CMPPS &
    { 0xC3, ENTRY_HandleBytes2Mod },                      // MOVNTI
    { 0xC4, ENTRY_HandleBytes2Mod1 },                     // PINSRW /r ib
    { 0xC5, ENTRY_HandleBytes2Mod1 },                     // PEXTRW /r ib
    { 0xC6, ENTRY_HandleBytes2Mod1 },                     // SHUFPS & SHUFPD
    { 0xC7, ENTRY_HandleBytes2Mod },                      // CMPXCHG8B (0F C7)
    { 0xC8, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xC9, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xCA, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xCB, ENTRY_HandleBytes1 },                         //CVTPD2PI BSWAP 0F C8 + rd
    { 0xCC, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xCD, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xCE, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xCF, ENTRY_HandleBytes1 },                         // BSWAP 0F C8 + rd
    { 0xD0, ENTRY_Invalid },                              // _D0
    { 0xD1, ENTRY_HandleBytes2Mod },                      // PSRLW/r
    { 0xD2, ENTRY_HandleBytes2Mod },                      // PSRLD/r
    { 0xD3, ENTRY_HandleBytes2Mod },                      // PSRLQ/r
    { 0xD4, ENTRY_HandleBytes2Mod },                      // PADDQ
    { 0xD5, ENTRY_HandleBytes2Mod },                      // PMULLW/r
    { 0xD6, ENTRY_HandleBytes2Mod },                      // MOVDQ2Q / MOVQ2DQ
    { 0xD7, ENTRY_HandleBytes2Mod },                      // PMOVMSKB/r
    { 0xD8, ENTRY_HandleBytes2Mod },                      // PSUBUSB/r
    { 0xD9, ENTRY_HandleBytes2Mod },                      // PSUBUSW/r
    { 0xDA, ENTRY_HandleBytes2Mod },                      // PMINUB/r
    { 0xDB, ENTRY_HandleBytes2Mod },                      // PAND/r
    { 0xDC, ENTRY_HandleBytes2Mod },                      // PADDUSB/r
    { 0xDD, ENTRY_HandleBytes2Mod },                      // PADDUSW/r
    { 0xDE, ENTRY_HandleBytes2Mod },                      // PMAXUB/r
    { 0xDF, ENTRY_HandleBytes2Mod },                      // PANDN/r
    { 0xE0, ENTRY_HandleBytes2Mod  },                     // PAVGB
    { 0xE1, ENTRY_HandleBytes2Mod },                      // PSRAW/r
    { 0xE2, ENTRY_HandleBytes2Mod },                      // PSRAD/r
    { 0xE3, ENTRY_HandleBytes2Mod },                      // PAVGW
    { 0xE4, ENTRY_HandleBytes2Mod },                      // PMULHUW/r
    { 0xE5, ENTRY_HandleBytes2Mod },                      // PMULHW/r
    { 0xE6, ENTRY_HandleBytes2Mod },                      // CTDQ2PD &
    { 0xE7, ENTRY_HandleBytes2Mod },                      // MOVNTQ
    { 0xE8, ENTRY_HandleBytes2Mod },                      // PSUBB/r
    { 0xE9, ENTRY_HandleBytes2Mod },                      // PSUBW/r
    { 0xEA, ENTRY_HandleBytes2Mod },                      // PMINSW/r
    { 0xEB, ENTRY_HandleBytes2Mod },                      // POR/r
    { 0xEC, ENTRY_HandleBytes2Mod },                      // PADDSB/r
    { 0xED, ENTRY_HandleBytes2Mod },                      // PADDSW/r
    { 0xEE, ENTRY_HandleBytes2Mod },                      // PMAXSW /r
    { 0xEF, ENTRY_HandleBytes2Mod },                      // PXOR/r
    { 0xF0, ENTRY_Invalid },                              // _F0
    { 0xF1, ENTRY_HandleBytes2Mod },                      // PSLLW/r
    { 0xF2, ENTRY_HandleBytes2Mod },                      // PSLLD/r
    { 0xF3, ENTRY_HandleBytes2Mod },                      // PSLLQ/r
    { 0xF4, ENTRY_HandleBytes2Mod },                      // PMULUDQ/r
    { 0xF5, ENTRY_HandleBytes2Mod },                      // PMADDWD/r
    { 0xF6, ENTRY_HandleBytes2Mod },                      // PSADBW/r
    { 0xF7, ENTRY_HandleBytes2Mod },                      // MASKMOVQ
    { 0xF8, ENTRY_HandleBytes2Mod },                      // PSUBB/r
    { 0xF9, ENTRY_HandleBytes2Mod },                      // PSUBW/r
    { 0xFA, ENTRY_HandleBytes2Mod },                      // PSUBD/r
    { 0xFB, ENTRY_HandleBytes2Mod },                      // FSUBQ/r
    { 0xFC, ENTRY_HandleBytes2Mod },                      // PADDB/r
    { 0xFD, ENTRY_HandleBytes2Mod },                      // PADDW/r
    { 0xFE, ENTRY_HandleBytes2Mod },                      // PADDD/r
    { 0xFF, ENTRY_Invalid },                              // _FF
};

static uint32_t dt_disasm_instr_Dispatch(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    return (desc->Func)(context, cursor, istate, idesc, desc);
}

static int64_t dt_disasm_sign_extend(int64_t val, int bits)
{
    uint64_t sign_bit = val & (1ULL << (bits - 1));
    val |= ~(sign_bit - 1);
    return val;
}

static uint32_t dt_disasm_instr_f_Invalid(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    idesc->InvOp = 1;
    idesc->NoFallThrouth = 1;
    *cursor += 1;
    return 1;
}

static uint32_t dt_disasm_instr_f_AnalyzeBytes(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
#if DT_DISASM_TARGET_64
    uint32_t BytesFixed = (desc->FlagBits & ADDRESS)
        ? (istate->AddressOverride ? 5 : 9)      // For move A0-A3
        : ((istate->OperandOverride ? desc->FixedSize16 :
            (desc->FlagBits & REX)
            ? (istate->RexOverride ? 9 : 5)      // For move B8
            : desc->FixedSize));
#else
    uint32_t BytesFixed = (desc->FlagBits & ADDRESS)
        ? (istate->AddressOverride ? desc->FixedSize16 : desc->FixedSize)
        : (istate->OperandOverride ? desc->FixedSize16 : desc->FixedSize);
#endif

    uint32_t Bytes = BytesFixed;
    uint32_t JumpTargetOffset = desc->RelOffset;
    uint32_t JumpTargetByteSize = Bytes - JumpTargetOffset;

    if (desc->ModOffset > 0) {
        uint8_t ModRm;
        if (!dt_disasm_instr_fetch(context, *cursor + desc->ModOffset, 1, &ModRm)) {
            return 0;
        }

        uint8_t Flags = dt_disasm_instr_modrm[ModRm];

        Bytes += Flags & NOTSIB;

        if (Flags & SIB) {
            uint8_t Sib;
            if (!dt_disasm_instr_fetch(context, *cursor + desc->ModOffset + 1, 1, &Sib)) {
                return 0;
            }

            if ((Sib & 0x07) == 0x05) {
                if ((ModRm & 0xc0) == 0x00) {
                    Bytes += 4;
                }
                else if ((ModRm & 0xc0) == 0x40) {
                    Bytes += 1;
                }
                else if ((ModRm & 0xc0) == 0x80) {
                    Bytes += 4;
                }
            }

            JumpTargetByteSize = Bytes - JumpTargetOffset;

        } else if (Flags & RIP) {
#if DT_DISASM_TARGET_64
            JumpTargetOffset = Bytes - (4 + desc->TargetBack);
            JumpTargetByteSize = 4;
#endif
        }
    }

    if (0 != desc->RelOffset) {
        uint64_t Address = 0;
        if (!dt_disasm_instr_fetch(context, *cursor + JumpTargetOffset, JumpTargetByteSize, &Address)) {
            return 0;
        }

        idesc->BranchAddress = dt_disasm_sign_extend(Address, JumpTargetByteSize * 8);
        idesc->IsBranch = 1;
        idesc->RelativeBranchTarget = 1;
    }

    if (desc->FlagBits & RET) {
        idesc->IsReturn = 1;
    }

    if (desc->FlagBits & NOTHROUGH) {
        idesc->NoFallThrouth = 1;
    }

    if (desc->FlagBits & DYNAMIC) {
        idesc->DynamicBranchTarget = 1;
    }

    *cursor += Bytes;
    return Bytes;
}

static uint32_t dt_disasm_instr_f_Next(
    const struct dt_disasm_instr_desc* table,
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t next;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &next)) {
        return 0;
    }

    *cursor += 1;
    desc = &table[next];
    return 1 + dt_disasm_instr_Dispatch(context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_Analyze0F(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    return dt_disasm_instr_f_Next(dt_disasm_instr_table_0F, context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_AnalyzeBytesPrefix(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    return dt_disasm_instr_f_Next(dt_disasm_instr_table, context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_AnalyzeBytesRex(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t rex;
    if (!dt_disasm_instr_fetch(context, *cursor, 1, &rex)) {
        return 0;
    }

    if (rex & 0x8) {
        istate->RexOverride = 1;
    }

    return dt_disasm_instr_f_Next(dt_disasm_instr_table, context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_AnalyzeBytesVex(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t Vex[3];
    if (!dt_disasm_instr_fetch(context, *cursor, 3, Vex)) {
        return 0;
    }

    uint8_t VexSize = (Vex[0] & 1) ? 1 : 2;

    *cursor += VexSize;
    // TODO:
    return VexSize + dt_disasm_instr_f_Invalid(context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_Analyze66(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    istate->OperandOverride = 1;
    return dt_disasm_instr_f_Next(dt_disasm_instr_table, context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_Analyze67(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    istate->AddressOverride = 1;
    return dt_disasm_instr_f_Next(dt_disasm_instr_table, context, cursor, istate, idesc, desc);
}

static uint32_t dt_disasm_instr_f_AnalyzeBytesJump(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    int8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }

    idesc->BranchAddress = b; // sign extends
    idesc->IsBranch = 1;
    idesc->RelativeBranchTarget = desc->RelOffset ? 1 : 0;

    if (desc->FlagBits & NOTHROUGH) {
        idesc->NoFallThrouth = 1;
    }

    if (desc->FlagBits & DYNAMIC) {
        idesc->DynamicBranchTarget = 1;
    }

    *cursor += 2;
    return 2;
}

static uint32_t dt_disasm_instr_f_AnalyzeF6(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }

    b = (b >> 3) & 7;
    if (0 == b) {
        // TEST BYTE /0
        const struct dt_disasm_instr_desc e = {
            0xf6, ENTRY_HandleBytes2Mod1
        };
        return dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
    } else {
        // TEST /1
        // NOT  /2
        // NEG  /3
        // MUL  /4
        // IMUL /5
        // DIV  /6
        // IDIV /7
        const struct dt_disasm_instr_desc e = {
            0xf6, ENTRY_HandleBytes2Mod
        };
        return dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
    }
}

static uint32_t dt_disasm_instr_f_AnalyzeF7(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }

    b = (b >> 3) & 7;
    if (0 == b) {
        // TEST WORD /0
        const struct dt_disasm_instr_desc e = {
            0xf7, ENTRY_HandleBytes2ModOperand
        };
        return dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
    } else {

        // TEST /1
        // NOT  /2
        // NEG  /3
        // MUL  /4
        // DIV  /6
        // IMUL /5
        // IDIV /7
        const struct dt_disasm_instr_desc e = {
            0xf7, ENTRY_HandleBytes2Mod
        };
        return dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
    }
}

static uint32_t dt_disasm_instr_f_AnalyzeFF(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }

    // INC  /0
    // DEC  /1
    // CALL /2
    // CALLF/3
    // JMP  /4
    // JMPF /5
    // PUSH /6
    // PUSH /7

    b = (b >> 3) & 7;
    switch (b) {
    case 4:
    case 5:
        idesc->NoFallThrouth = 1;
        __fallthrough;
    case 2:
    case 3:
        idesc->IsBranch = 1;
        idesc->DynamicBranchTarget = 1;
        break;
    }

    const struct dt_disasm_instr_desc e = {
        0xff, ENTRY_HandleBytes2Mod
    };
    return dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
}

static uint32_t dt_disasm_instr_f_Analyze0F38(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }
    *cursor += 1;

    const struct dt_disasm_instr_desc e = {
        0x38, ENTRY_HandleBytes2Mod
    };
    return 1 + dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
}

static uint32_t dt_disasm_instr_f_Analyze0F3A(
    void* context,
    uint32_t* cursor,
    struct dt_disasm_instr_state* istate,
    struct dt_disasm_instr_descr* idesc,
    const struct dt_disasm_instr_desc* desc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, *cursor + 1, 1, &b)) {
        return 0;
    }
    *cursor += 1;

    const struct dt_disasm_instr_desc e = {
        0x3A, ENTRY_HandleBytes2Mod1
    };
    return 1 + dt_disasm_instr_Dispatch(context, cursor, istate, idesc, &e);
}

uint32_t dt_disasm_instr_analyze(
    void* context,
    uint32_t pos,
    struct dt_disasm_instr_descr* idesc)
{
    uint8_t b;
    if (!dt_disasm_instr_fetch(context, pos, 1, &b)) {
        return 0;
    }

    const struct dt_disasm_instr_desc* desc = &dt_disasm_instr_table[b];
    struct dt_disasm_instr_state istate = {0};
    return dt_disasm_instr_Dispatch(context, &pos, &istate, idesc, desc);
}

int dt_disasm_instr_is_tracepoint(const void* val, uint32_t size)
{
    return (0xcc == *(const uint8_t*)val);
}

size_t dt_disasm_instr_min_size(void)
{
    return 1;
}

#elif defined(_M_ARM64)

static int64_t dt_disasm_sign_extend(int64_t val, int bits)
{
    uint64_t sign_bit = val & (1ULL << (bits - 1));
    val |= ~(sign_bit - 1);
    return val;
}

static void dt_disasm_instr_analyze_eret(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    idesc->IsReturn = 1;
    idesc->NoFallThrouth = 1;
    return;
}

static void dt_disasm_instr_analyze_br(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t BranchType = (instr >> 21) & 3;

    if (2 == BranchType) {
        idesc->IsReturn = 1;
        idesc->NoFallThrouth = 1;
    } else if (3 == BranchType) {
        idesc->InvOp = 1;
    } else {
        if (0 == BranchType) {
            idesc->NoFallThrouth = 1;
        }

        idesc->IsBranch = 1;
        idesc->DynamicBranchTarget = 1;
    }

    return;
}

static void dt_disasm_instr_analyze_bl(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t imm = instr & 0x03ffffff; // 0,23
    uint32_t is_link = instr & 0x80000000;
    idesc->BranchAddress = dt_disasm_sign_extend(imm * 4, 64) - 4;
    idesc->NoFallThrouth = is_link ? 0 : 1;
    idesc->IsBranch = 1;
    idesc->RelativeBranchTarget = 1;
    return;
}

static void dt_disasm_instr_analyze_bc(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t imm = (instr >> 5) & 0x0007ffff; // 5..19
    idesc->BranchAddress = dt_disasm_sign_extend(imm * 4, 64) - 4;
    idesc->IsBranch = 1;
    idesc->RelativeBranchTarget = 1;
    return;
}

static void dt_disasm_instr_analyze_cb(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t imm = (instr >> 5) & 0x0007ffff; // 5,19
    idesc->BranchAddress = dt_disasm_sign_extend(imm * 4, 64) - 4;
    idesc->IsBranch = 1;
    idesc->RelativeBranchTarget = 1;
    return;
}

static void dt_disasm_instr_analyze_tb(
    uint32_t instr,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t imm = (instr >> 5) & 0x00003fff; // 5,14
    idesc->BranchAddress = dt_disasm_sign_extend(imm * 4, 64) - 4;
    idesc->IsBranch = 1;
    idesc->RelativeBranchTarget = 1;
    return;
}

uint32_t dt_disasm_instr_analyze(
    void* context,
    uint32_t pos,
    struct dt_disasm_instr_descr* idesc)
{
    uint32_t instr;
    if (!dt_disasm_instr_fetch(context, pos, 4, &instr)) {
        return 0;
    }

    if ((instr & 0xFF9FFC1F) == 0xD61F0000) {
        dt_disasm_instr_analyze_br(instr, idesc);     // br/blr/ret
    } else if ((instr & 0x7C000000) == 0x14000000) {
        dt_disasm_instr_analyze_bl(instr, idesc);     // b/bl
    } else if ((instr & 0xFF000010) == 0x54000000) {
        dt_disasm_instr_analyze_bc(instr, idesc);     // b.cond
    } else if ((instr & 0x7E000000) == 0x34000000) {
        dt_disasm_instr_analyze_cb(instr, idesc);     // cbz/cbnz
    } else if ((instr & 0x7E000000) == 0x36000000) {
        dt_disasm_instr_analyze_tb(instr, idesc);     //
    } else if (instr == 0xD69F03E0) {
        dt_disasm_instr_analyze_eret(instr, idesc);
    }

    return 4;
}

int dt_disasm_instr_is_tracepoint(const void* val, uint32_t size)
{
    return (4 == size) && (0xD43E0000 == *(const uint32_t*)val);
}

size_t dt_disasm_instr_min_size(void)
{
    return 4;
}

#else

uint32_t dt_disasm_instr_analyze(
    void* context,
    uint32_t pos,
    struct dt_disasm_instr_descr* idesc)
{
    return 0;
}

int dt_disasm_instr_is_tracepoint(const void* val, uint32_t size)
{
    return 0;
}

size_t dt_disasm_instr_min_size(void)
{
    return 1;
}

#endif

