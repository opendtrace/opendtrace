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

    dllmain.cpp


Abstract:

    This file implements the entry point for the dtrace.dll

--*/

#include <windows.h>
#include <dbghelp.h>

void _dtrace_init(void);
void dt_dprintf(const char *format, ...);

static BOOL CALLBACK
SymbolCallbackFunction (
    _In_ HANDLE ProcessSymHandle,
    _In_ ULONG ActionCode,
    _In_opt_ ULONG64 CallbackData,
    _In_opt_ ULONG64 UserContext
    )

{

    UNREFERENCED_PARAMETER(ProcessSymHandle);
    UNREFERENCED_PARAMETER(UserContext);

    if (ActionCode == CBA_DEBUG_INFO) {
        dt_dprintf("%s", (PCSTR)(ULONG_PTR)CallbackData);
        return TRUE;
    }

    return FALSE;
}

BOOL
APIENTRY
DllMain (
    _In_ HMODULE hModule,
    _In_ DWORD dwReason,
    _In_ LPVOID lpReserved
    )

{

    UNREFERENCED_PARAMETER(lpReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        _dtrace_init();

        SymInitialize(GetCurrentProcess(), NULL, FALSE);

        if (SymRegisterCallback64(GetCurrentProcess(), &SymbolCallbackFunction, 0)) {
            SymSetOptions(SymGetOptions() | SYMOPT_DEBUG);
        }

        break;

    case DLL_PROCESS_DETACH:
        SymCleanup(GetCurrentProcess());
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}



