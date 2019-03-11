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

    nttrace.h

Abstract:

    This file defines the interface between the trace engine and the system
    trace support interface.

--*/

#pragma once

#ifdef _KERNEL

//
// Engine registration with the trace extension.
//

typedef UINT_PTR NTTRACE_PROVIDER_ID;
typedef unsigned int NTTRACE_PROBE_ID;

typedef struct _TRACE_PROVIDER_CALLBACKS {
    ULONG Size;

    VOID
    (*Provide) (
        _In_opt_ PVOID ProviderContext,
        _In_opt_ PCSZ ProviderName,
        _In_opt_ PCSZ ModuleName,
        _In_opt_ PCSZ FunctionName,
        _In_opt_ PCSZ ProbeName
        );

    VOID
    (*Destroy) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext
        );

    VOID
    (*Enable) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext
        );

    VOID
    (*Disable) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext
        );

    ULONGLONG
    (*GetArgument) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext,
        _In_ INT ArgumentIndex,
        _In_opt_ PVOID CallContext // As passed into 'probe()' routine.
        );

    INT
    (*GetArgumentType) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext,
        _In_ INT ArgumentIndex,
        _Out_writes_z_(TypeNameBufferSize) PSTR TypeName,
        _In_ size_t TypeNameBufferSize
        );

    KPROCESSOR_MODE
    (*GetContext) (
        _In_opt_ PVOID ProviderContext,
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ PVOID ProbeContext,
        _In_opt_ PVOID CallContext, // As passed into 'probe()' routine.
        _Out_opt_ struct _KTRAP_FRAME** TrapFrame,
        _Out_opt_ struct _CONTEXT** ContextRecord
        );

} TRACE_PROVIDER_CALLBACKS;
typedef const TRACE_PROVIDER_CALLBACKS* PCTRACE_PROVIDER_CALLBACKS;

typedef struct _TRACE_CONTROL_CALLBACKS {
    ULONG Size;

    NTSTATUS
    (*Create) (
        _In_opt_ PVOID Context,
        _In_ PIRP Irp,
        _In_opt_ PCUNICODE_STRING ExtraPath
        );

    VOID
    (*Close) (
        _In_opt_ PVOID Context
        );

    NTSTATUS
    (*IoControl) (
        _In_opt_ PVOID Context,
        _In_ PIRP Irp,
        _Out_ PULONG BytesDone
        );

} TRACE_CONTROL_CALLBACKS;
typedef const TRACE_CONTROL_CALLBACKS* PCTRACE_CONTROL_CALLBACKS;

typedef enum _TRACE_PROVIDER_ACCESS {
    TRACE_PROVIDER_ACCESS_None    = 0,
    TRACE_PROVIDER_ACCESS_Kernel  = 1,
    TRACE_PROVIDER_ACCESS_User    = 2,
    TRACE_PROVIDER_ACCESS_Process = 4,
} TRACE_PROVIDER_ACCESS;

typedef struct _TRACE_ENGINE {
    ULONG Size;

    //
    // Pointers to the framework functions to establish control device
    // in the dtrace namespace.
    //

    NTSTATUS
    (*RegisterControlExtension) (
        _In_opt_ PCUNICODE_STRING Name,
        _In_opt_ ULONG ContextSize,
        _In_opt_ PCTRACE_CONTROL_CALLBACKS Callbacks,
        _Out_ PULONG RegistrationId
        );

    VOID
    (*UnregisterControlExtension) (
        _In_ ULONG RegistrationId
        );

    //
    // Pointers to the dtrace API functions.
    //

    NTTRACE_PROVIDER_ID
    (*ProviderRegister) (
        _In_ PCSZ ProviderName,
        _In_opt_ PVOID ProviderContext,
        _In_ PCTRACE_PROVIDER_CALLBACKS Callbacks,
        _In_ TRACE_PROVIDER_ACCESS AccessLevel
        );

    VOID
    (*ProviderUnregister) (
        _In_ NTTRACE_PROVIDER_ID id
        );

    VOID
    (*ProviderCleanup) (
        _In_ NTTRACE_PROVIDER_ID id
        );

    NTTRACE_PROBE_ID
    (*ProbeLookup) (
        _In_ NTTRACE_PROVIDER_ID ProviderId,
        _In_opt_ PCSZ ModuleName,
        _In_opt_ PCSZ FunctionName,
        _In_opt_ PCSZ ProbeName
        );

    NTTRACE_PROBE_ID
    (*ProbeCreate) (
        _In_ NTTRACE_PROVIDER_ID ProviderId,
        _In_opt_ PCSZ ModuleName,
        _In_opt_ PCSZ FunctionName,
        _In_opt_ PCSZ ProbeName,
        _In_opt_ INT SkipFrames,
        _In_opt_ PVOID ProbeContext
        );

    VOID
    (*ModuleUnloaded) (
        _In_ PCSZ Name
        );

    VOID
    (*ProbeFire) (
        _In_ NTTRACE_PROBE_ID ProbeId,
        _In_opt_ UINT_PTR Arg0,
        _In_opt_ UINT_PTR Arg1,
        _In_opt_ UINT_PTR Arg2,
        _In_opt_ UINT_PTR Arg3,
        _In_opt_ PVOID Context
        );

} TRACE_ENGINE;
typedef const TRACE_ENGINE* PCTRACE_ENGINE;

typedef struct _TRACE_ENGINE_HELPERS {
    ULONG Size;

    //
    // Utility helpers for use by the tracing engine.
    //

    PULONG_PTR
    (*GetCurrentThreadTracePrivate) (
        _In_ ULONG Index
        );

    BOOLEAN
    (*AccessMemory) (
        _In_ PVOID SystemAddress,
        _In_ ULONG_PTR UntrustedAddress,
        _In_ SIZE_T NumberOfBytes,
        _In_ SIZE_T ChunkSize,
        _In_ BOOLEAN ReadOperation
        );

    ULONG
    (*WalkUserStack) (
        _In_ ULONG Limit,
        _Out_writes_(Limit) PVOID* Stack
        );

    VOID
    (*FilterAccess) (
        _In_ KPROCESSOR_MODE PreviousMode,
        _Inout_ PBOOLEAN KernelMemory,
        _Inout_ PBOOLEAN UserMemory
        );

} TRACE_ENGINE_HELPERS;
typedef const TRACE_ENGINE_HELPERS* PCTRACE_ENGINE_HELPERS;

NTSTATUS
NTAPI
TraceRegisterEngine (
    _In_opt_ PCTRACE_ENGINE Api,
    _Out_opt_ PCTRACE_ENGINE_HELPERS* HelpersPtr
    );

#endif _KERNEL

//
// Interface to the user-mode symbol server.
//

#define TRACE_SYM_QUEUE_PACKET \
    CTL_CODE(FILE_DEVICE_NULL, 123, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _TRACE_SYM_REQUEST {
    ULONG Index;             // Symbol index to start from.
    struct {
        ULONG DbgInfoPresent    :  1;  // 1 when PDB GUID and Age fields present.
        ULONG ReturnSingleEntry :  1;  // 1 to fill no more than one entry.
        ULONG Reserved          : 30;
    } Flags;
    ULONGLONG ModuleBase;    // Base of the target module.
    // GUID PdbGuid;         // When DbgInfoPresent == 1
    // ULONG PdbAge;         // When DbgInfoPresent == 1
    // CHAR SymbolMask[];    // Empty to match all.
} TRACE_SYM_REQUEST, *PTRACE_SYM_REQUEST;

typedef struct _TRACE_SYM_REPLY {
    ULONG Index;              // Index of the found symbol. -1 of end of list.
    USHORT NextEntryOffset;   // Next entry offset from the start of thus one.
    struct {
        USHORT VaArgs   :  1; // vararg function.
        USHORT Reserved : 15;
    } Flags;
    ULONG Rva;               // Symbol RVA.
    ULONG Size;              // Size of the symbol, 0 when unknown.
    // CHAR Names[];         // NULNUL-terminated list of symbol names.
    // CHAR Parameters[];    // NULNUL-terminated list of parameter types.
} TRACE_SYM_REPLY, *PTRACE_SYM_REPLY;


