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

    dt_symsrv.c

Abstract:

    This file implements the symbol server to support fbt provider name
    resolution.

    N.B. Though this symbol server starts a separate thread to handle FBT name
         resolution, calls are only expected to happen when main thread is
         blocked on IO control to the driver creating probes, so single-threded
         design of the dbghelp.dll is not an issue for this implementation.

--*/

#include <ntcompat.h>
#include <ntdtrace.h>
#include <cvconst.h>
#include <dt_impl.h>
#include <dt_string.h>
#include "dt_disasm.h"

struct dt_symsvr {
    HANDLE Thread;
    HANDLE Device;
    volatile BOOL Exiting;
};

struct dt_symsvr_function_name {
    struct dt_symsvr_function_name* Next;
    //char Value[0]; // NUL-terminated buffer at the tail.
};

struct dt_symsvr_function_parameter {
    struct dt_symsvr_function_parameter* Next;
    //char Value[0]; // NUL-terminated buffer at the tail.
};

struct dt_symsvr_function_flags {
    ULONG VaArgs   :  1; // vararg function.
    ULONG Reserved : 31;
};

struct dt_symsvr_function {
    struct dt_symsvr_function* Next;
    struct dt_symsvr_function* Prev;
    ULONG Rva;
    ULONG Size;
    struct dt_symsvr_function_flags Flags;
    struct dt_symsvr_function_parameter* Parameters;
    struct dt_symsvr_function_name Name;
    // char[]; Tail of rhe first name string.
};

struct dt_symsvr_function_enum_ctx {
    struct dt_symsvr_function* list;
    struct dt_symsvr_function* hint;
    PCSTR ModuleName;
};

static void dt_symsvr_free_paramlist(struct dt_symsvr_function_parameter* p)
{
    while (NULL != p) {
        struct dt_symsvr_function_parameter* nextp = p->Next;
        free(p);
        p = nextp;
    }
}

static void dt_symsvr_free_namelist(struct dt_symsvr_function_name* n)
{
    while (NULL != n) {
        struct dt_symsvr_function_name* nextn = n->Next;
        free(n);
        n = nextn;
    }
}

static void dt_symsvr_free_funclist(struct dt_symsvr_function* f)
{
    while (NULL != f) {
        struct dt_symsvr_function* nextf = f->Next;
        dt_symsvr_free_namelist(f->Name.Next);
        dt_symsvr_free_paramlist(f->Parameters);
        free(f);
        f = nextf;
    }
}

static PWSTR dt_symsrv_typestr_Contact(PWSTR Instr,
    PCWSTR Pfx, PCWSTR PfxDlm, PCWSTR Sfx, PCWSTR SfxDlm)
{
    size_t Len = 1;
    if (NULL != Pfx) {
        Len += wcslen(Pfx);
    }
    if (NULL != PfxDlm) {
        Len += wcslen(PfxDlm);
    }
    if (NULL != Instr) {
        Len += wcslen(Instr);
    }
    if (NULL != SfxDlm) {
        Len += wcslen(SfxDlm);
    }
    if (NULL != Sfx) {
        Len += wcslen(Sfx);
    }

    PWSTR s = (PWSTR)LocalAlloc(LPTR, Len * sizeof(WCHAR));
    if (NULL != s) {
        *s = 0;
        if (NULL != Pfx) {
            wcscat(s, Pfx);
        }
        if (NULL != PfxDlm) {
            wcscat(s, PfxDlm);
        }
        if (NULL != Instr) {
            wcscat(s, Instr);
        }
        if (NULL != SfxDlm) {
            wcscat(s, SfxDlm);
        }
        if (NULL != Sfx) {
            wcscat(s, Sfx);
        }
    }

    if (NULL != Instr) {
        LocalFree(Instr);
    }

    return s;
}

static PWSTR dt_symsrv_typestr(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId);

static PWSTR dt_symsrv_typestr_function(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    WCHAR functype[] = L"void*";
    PWSTR s = (PWSTR)LocalAlloc(LPTR, sizeof(functype));
    if (NULL != s) {
        wcscpy(s, functype);
    }
    return s;
}

static PWSTR dt_symsrv_typestr_enum(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    PWSTR TypeName = NULL;
    SymGetTypeInfo(Process, DebugBase, TypeId,
                   TI_GET_SYMNAME, &TypeName);

    return dt_symsrv_typestr_Contact(TypeName, L"`", NULL, NULL, NULL);
}

static PWSTR dt_symsrv_typestr_pointer(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    PWSTR BaseTypeName = NULL;
    ULONG baseType;
    if (SymGetTypeInfo(Process, DebugBase, TypeId,
                       TI_GET_TYPEID, &baseType)) {
        BaseTypeName = dt_symsrv_typestr(Process, DebugBase, baseType);
    }

    return dt_symsrv_typestr_Contact(BaseTypeName, NULL, NULL, L"*", NULL);
}

static PWSTR dt_symsrv_typestr_array(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    PWSTR ElementTypeName = NULL;
    ULONG typeIdElement;
    if (SymGetTypeInfo(Process, DebugBase, TypeId,
                       TI_GET_TYPEID, &typeIdElement)) {
        ElementTypeName = dt_symsrv_typestr(Process, DebugBase, typeIdElement);
    }

    ULONGLONG Length = 0;
    WCHAR ArrayStr[100];
    if (SymGetTypeInfo(Process, DebugBase, TypeId,
                        TI_GET_LENGTH, &Length)) {

        swprintf(ArrayStr, L"[%I64d]", Length);

    } else {
        wcscpy(ArrayStr, L"[]");
    }

    return dt_symsrv_typestr_Contact(ElementTypeName, NULL, NULL, ArrayStr, NULL);
}

static PWSTR dt_symsrv_typestr_udt(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    PWSTR TypeName = NULL;
    SymGetTypeInfo(Process, DebugBase, TypeId,
                   TI_GET_SYMNAME, &TypeName);

    return dt_symsrv_typestr_Contact(TypeName, L"`", NULL, NULL, NULL);
}

static PWSTR dt_symsrv_typestr_basetype(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    ULONG baseType;
    ULONG64 length;
    if (!SymGetTypeInfo(Process, DebugBase, TypeId,
                        TI_GET_BASETYPE, &baseType)) {
        return NULL;
    }

    if (!SymGetTypeInfo(Process, DebugBase, TypeId,
                        TI_GET_LENGTH, &length)) {
        return NULL;
    }

    WCHAR NameBuffer[512];
    NameBuffer[0] = 0;

    switch (baseType) {
    case btWChar:
    case btChar:
        switch (length) {
        case 1: wcscat(NameBuffer, L"char"); break;
        case 2: wcscat(NameBuffer, L"wchar_t"); break;
        }

        break;

    case btUInt:
    case btULong:
        wcscat(NameBuffer, L"unsigned ");
        __fallthrough;
    case btVoid:
    case btInt:
    case btLong:
        switch (length) {
        case 0: wcscat(NameBuffer, L"void"); break;
        case 1: wcscat(NameBuffer, L"char"); break;
        case 2: wcscat(NameBuffer, L"short"); break;
        case 4: wcscat(NameBuffer, L"long"); break;
        case 8: wcscat(NameBuffer, L"long long"); break;
        }

        break;

    case btFloat :
        switch (length) {
        case 4: wcscat(NameBuffer, L"float"); break;
        case 8: wcscat(NameBuffer, L"double"); break;
        }

        break;

    case btBool:
        switch (length) {
        case 1: wcscat(NameBuffer, L"bool"); break;
        case 4: wcscat(NameBuffer, L"`BOOL"); break;
        }

        break;

    case btHresult:
        wcscat(NameBuffer, L"`HRESULT"); break;
    }

    PWSTR Name = (PWSTR)LocalAlloc(LPTR, (wcslen(NameBuffer) + 1) * 2);
    if (NULL != Name) {
        wcscpy(Name, NameBuffer);
    }
    return Name;
}

PWSTR dt_symsrv_typestr(HANDLE Process, ULONGLONG DebugBase, ULONG TypeId)
{
    PWSTR TypeName = NULL;

    ULONG SymTag;
    if (!SymGetTypeInfo(Process, DebugBase, TypeId, TI_GET_SYMTAG, &SymTag)) {
        goto exit;
    }

    switch (SymTag) {
    case SymTagBaseType:
        TypeName = dt_symsrv_typestr_basetype(Process, DebugBase, TypeId);
        break;

    case SymTagUDT:
        TypeName = dt_symsrv_typestr_udt(Process, DebugBase, TypeId);
        break;

    case SymTagPointerType:
        TypeName = dt_symsrv_typestr_pointer(Process, DebugBase, TypeId);
        break;

    case SymTagFunctionType:
        TypeName = dt_symsrv_typestr_function(Process, DebugBase, TypeId);
        break;

    case SymTagArrayType:
        TypeName = dt_symsrv_typestr_array(Process, DebugBase, TypeId);
        break;

    case SymTagEnum:
        TypeName = dt_symsrv_typestr_enum(Process, DebugBase, TypeId);
        break;
    }

exit:
    return TypeName;
}

static struct dt_symsvr_function_parameter* dt_symsrv_name2paramtype(
    PCSTR ModuleName, PWSTR TypeName)
{
    if (NULL == TypeName) {
        return NULL;
    }

    size_t len = wcslen(TypeName) + 1;
    if ('`' == *TypeName) {
        if (NULL != ModuleName) {
            len += strlen(ModuleName);
        } else {
            len -= 1;
        }
    }

    struct dt_symsvr_function_parameter* p =
        malloc(sizeof(struct dt_symsvr_function_parameter) + len);

    if (NULL != p) {
        p->Next = NULL;

        size_t i = 0;
        char* pc = (char*)(p + 1);
        WCHAR* pw = TypeName;

        if ('`' == *pw) {
            if (NULL != ModuleName) {
                const char* pmc = ModuleName;
                while (*pmc) {
                    *(pc++) = *(pmc++);
                }
            } else {
                pw += 1;
            }
        }

        while (*pw) {
            *(pc++) = (char)*(pw++);
        }

        *pc = 0;
    }

    LocalFree(TypeName);
    return p;
}

static struct dt_symsvr_function_parameter* dt_symsrv_load_paramtypes(
    PCSTR ModuleName, ULONGLONG Base, ULONG TypeIndex,
    struct dt_symsvr_function_flags* Flags)
{
    if (0 == TypeIndex) {
        return NULL;
    }

    ULONG SymTag;
    if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex,
                        TI_GET_SYMTAG, &SymTag)) {
        return NULL;
    }

    if (SymTagFunctionType != SymTag) {
        return NULL;
    }

    ULONG ReturnType;
    if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex,
                        TI_GET_TYPEID, &ReturnType)) {
        return NULL;
    }

    struct dt_symsvr_function_parameter* Head =
        dt_symsrv_name2paramtype(ModuleName,
                                 dt_symsrv_typestr(GetCurrentProcess(),
                                                   Base,
                                                   ReturnType));

    if (NULL == Head) {
        return NULL;
    }

    ULONG ParamsCount = 0;
    if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex,
                        TI_GET_CHILDRENCOUNT, &ParamsCount)) {
        goto error;
    }

    if (0 == ParamsCount) {
        return Head;
    }

    TI_FINDCHILDREN_PARAMS* Params = (TI_FINDCHILDREN_PARAMS*)
        _alloca(sizeof(TI_FINDCHILDREN_PARAMS) + ParamsCount * sizeof(ULONG));

    Params->Count = ParamsCount;
    Params->Start = 0;
    if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex,
                        TI_FINDCHILDREN, Params)) {
        goto error;
    }

    struct dt_symsvr_function_parameter* Prev = Head;
    for (ULONG i = 0; i < ParamsCount; i++) {
        ULONG ParamType;
        if (!SymGetTypeInfo(GetCurrentProcess(), Base, Params->ChildId[i],
                            TI_GET_TYPEID, &ParamType)) {
            goto error;
        }

        ULONG baseType;
        if (((i + 1) == ParamsCount) &&
            SymGetTypeInfo(GetCurrentProcess(), Base, ParamType,
                           TI_GET_BASETYPE, &baseType) &&
            (btNoType == baseType)) {

            Flags->VaArgs = 1;
            break;
        }

        struct dt_symsvr_function_parameter* p =
            dt_symsrv_name2paramtype(ModuleName,
                                     dt_symsrv_typestr(GetCurrentProcess(),
                                                       Base,
                                                       ParamType));
        if (NULL == p) {
            goto error;
        }

        Prev->Next = p;
        Prev = p;
    }

    return Head;

error:
    dt_symsvr_free_paramlist(Head);
    return NULL;
}

static BOOL dt_symsvr_is_function(PSYMBOL_INFO SymInfo)
{
    if (SymTagFunction == SymInfo->Tag) {
        return TRUE;
    }

    if ((SymTagPublicSymbol == SymInfo->Tag) &&
        (0 != (SymInfo->Flags & (SYMFLAG_EXPORT |
                                 SYMFLAG_FUNCTION |
                                 SYMFLAG_PUBLIC_CODE)))) {

        return TRUE;
    }

    return FALSE;
}

static struct dt_symsvr_function* dt_symsvr_locate_entry(
    struct dt_symsvr_function_enum_ctx* ctx, ULONG Rva)
{
    if (NULL == ctx->list) {
        return NULL;
    }

    struct dt_symsvr_function* f = ctx->hint;
    if (NULL == f) {
        f = ctx->list;
    }

    for (;;) {
        if (Rva == f->Rva) {
            return f;
        }

        if (Rva > f->Rva) {
            if ((NULL == f->Next) || (Rva < f->Next->Rva)) {
                return f;
            }

            f = f->Next;
            continue;
        }

        if (Rva < f->Rva) {
            if ((NULL == f->Prev) || (Rva > f->Prev->Rva)) {
                return f;
            }

            f = f->Prev;
            continue;
        }
    }
}

static void dt_symsvr_add_function(struct dt_symsvr_function_enum_ctx* ctx,
    ULONG Rva, ULONG Size, PSTR Name, ULONG TypeIndex, ULONGLONG ModBase)
{
    struct dt_symsvr_function* f =
        dt_symsvr_locate_entry(ctx, Rva);

    size_t NameSize = strlen(Name) + 1;

    if ((NULL == f) || (f->Rva != Rva)) {
        struct dt_symsvr_function* newf =
            malloc(sizeof(struct dt_symsvr_function) + NameSize);

        if (NULL == newf) {
            return; // Ignore.
        }

        ZeroMemory(newf, sizeof(struct dt_symsvr_function));
        newf->Rva = Rva;
        newf->Size = Size;
        CopyMemory((PSTR)(newf + 1), Name, NameSize);
        newf->Parameters =
            dt_symsrv_load_paramtypes(ctx->ModuleName, ModBase, TypeIndex, &newf->Flags);

        if (NULL == f) {
            ;

        } else if (f->Rva < Rva) {
            newf->Prev = f;
            newf->Next = f->Next;
            f->Next = newf;
            if (NULL != newf->Next) {
                newf->Next->Prev = newf;
            }

        } else {
            newf->Next = f;
            newf->Prev = f->Prev;
            f->Prev = newf;
            if (NULL != newf->Prev) {
                newf->Prev->Next = newf;
            }
        }

        if (NULL == newf->Prev) {
            ctx->list = newf;
        }

        f = newf;

    } else {
        struct dt_symsvr_function_name* n =
            malloc(sizeof(struct dt_symsvr_function_name) + NameSize);

        if (NULL == n) {
            return; // Ignore.
        }

        ZeroMemory(n, sizeof(struct dt_symsvr_function_name));
        CopyMemory((PSTR)(n + 1), Name, NameSize);

        n->Next = f->Name.Next;
        f->Name.Next = n;
    }

    ctx->hint = f;
    return;
}

static BOOL CALLBACK dt_symsvr_EnumSymProc(PSYMBOL_INFO SymInfo,
    ULONG SymbolSize, PVOID UserContext)
{
    if (dt_symsvr_is_function(SymInfo)) {
        dt_symsvr_add_function((struct dt_symsvr_function_enum_ctx*)UserContext,
                               (ULONG)(SymInfo->Address - SymInfo->ModBase),
                               SymInfo->Size,
                               SymInfo->Name,
                               SymInfo->TypeIndex, SymInfo->ModBase);
    }

    return TRUE;
}

static PSTR dt_symsvr_module_name(ULONGLONG ModuleBase)
{
    char DriverPath[MAXPATHLEN];
    if (!GetDeviceDriverFileNameA((PVOID)(ULONG_PTR)ModuleBase, DriverPath, sizeof(DriverPath))) {
        return NULL;
    }

    if (DriverPath[0] == '\\' && DriverPath[1] == '?' &&
        DriverPath[2] == '?' && DriverPath[3] == '\\') {

        DriverPath[1] = '\\';

    } else {
        const char SystemRootPrefix[] = "\\SystemRoot\\";

        if (!_strnicmp(DriverPath, SystemRootPrefix, sizeof(SystemRootPrefix) - 1)) {
            CHAR Buf[MAXPATHLEN];
            int Len = GetEnvironmentVariableA("SYSTEMROOT", Buf, sizeof(Buf));

            if ((Len > 0) &&
                ((sizeof(DriverPath) - Len) >
                 ((strlen(DriverPath) + 1) - (sizeof(SystemRootPrefix) - 3)))) {

                strcat(Buf, DriverPath + (sizeof(SystemRootPrefix) - 2));
                strcpy(DriverPath, Buf);
            }
        }
    }

    return strdup(DriverPath);
}

static struct dt_symsvr_function* dt_symsvr_load_functions(
    ULONGLONG ModuleBase, PMODLOAD_DATA ModuleData, PCHAR ImageFileName)
{
    PVOID OldRedirectionDisabled;
    BOOL RedirectionDisabled =
        Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);

    ULONGLONG Base =
        SymLoadModuleEx(GetCurrentProcess(), NULL, ImageFileName, NULL,
                        ModuleBase, 0, ModuleData, 0);

    if (0 == Base) {
        dt_dprintf("Failed symbol server failed to load image at %p, %08lx\n",
                   ModuleBase, GetLastError());
    }

    if (RedirectionDisabled) {
        Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
    }

    if (0 == Base) {
        return NULL;
    }

    struct dt_symsvr_function_enum_ctx ctx = {0};

    IMAGEHLP_MODULE64 ModuleInfo = {0};
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);
    if (SymGetModuleInfo64(GetCurrentProcess(), Base, &ModuleInfo)) {
        ctx.ModuleName = ModuleInfo.ModuleName;
        if (0 == strcmp(ctx.ModuleName, "ntoskrnl")) {
            ctx.ModuleName = "nt";
        }
    }

    if (!SymEnumSymbols(GetCurrentProcess(), Base, "*", dt_symsvr_EnumSymProc,
                        &ctx)) {
        dt_dprintf("Failed symbol server failed to enum symbols for load image at %p, %08lx\n",
                   ModuleBase, GetLastError());
    }

    SymUnloadModule64(GetCurrentProcess(), Base);

    return ctx.list;
}

static PVOID dt_symsvr_map(PCSTR FileName)
{
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    HANDLE SectionHandle = NULL;
    PVOID View = NULL;
    BOOL RedirectionDisabled;
    PVOID OldRedirectionDisabled;

    RedirectionDisabled = Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);
    FileHandle = CreateFileA(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);

    if (RedirectionDisabled) {
        Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
    }

    if (INVALID_HANDLE_VALUE == FileHandle) {
        goto exit;
    }

    SectionHandle = CreateFileMappingW(FileHandle,
                                       NULL,
                                       PAGE_READONLY,
                                       0, 0, // Max size is zero = map entire file.
                                       NULL);

    if (NULL == SectionHandle) {
        goto exit;
    }

    View = MapViewOfFile(SectionHandle,
                         FILE_MAP_READ,
                         0, 0, // At zero offset.
                         0);   // Map entire section.

exit:
    if (NULL != SectionHandle) {
        CloseHandle(SectionHandle);
    }

    if (INVALID_HANDLE_VALUE != FileHandle) {
        CloseHandle(FileHandle);
    }

    return View;
}

static DWORD CALLBACK dt_symsvr_thread(PVOID param)
{
    struct dt_symsvr* s = (struct dt_symsvr*)param;
    UCHAR buf[4096] = {0};
    ULONG bytesdone;
    ULONGLONG LoadedImageBase = 0;
    struct dt_symsvr_function* f = NULL;
    struct dt_symsvr_function* c = NULL;
    PSTR UsedNameFilter = NULL;

    //
    // Start the API loop.
    // It will be broken when stopping the symbol server by
    // canceling an outstanding IO.
    //

retry:
    while (!s->Exiting &&
           DeviceIoControl(s->Device,
                           TRACE_SYM_QUEUE_PACKET,
                           buf, sizeof(buf),
                           buf, sizeof(buf),
                           &bytesdone,
                           NULL)) {

        PTRACE_SYM_REQUEST Request = (PTRACE_SYM_REQUEST)&buf[0];
        PTRACE_SYM_REPLY Reply = (PTRACE_SYM_REPLY)&buf[0];
        ULONG Index = Request->Index;

        if ((ULONG)-1 == Index) {
            continue;
        }

        //
        // Remap the module if different from one already mapped,
        // and load all functions from it.
        //

        if (LoadedImageBase != Request->ModuleBase) {
            MODLOAD_DATA Modload = {0};
            PMODLOAD_DATA ModuleData = NULL;
            PCHAR ImageFileName = NULL;
            struct dt_symsvr_function* newf;

            if (0 != Request->Flags.DbgInfoPresent) {
                Modload.ssize = sizeof(MODLOAD_DATA);
                Modload.ssig = DBHHEADER_PDBGUID;
                Modload.data = Request + 1;
                Modload.size = sizeof(MODLOAD_PDBGUID_PDBAGE);
                ModuleData = &Modload;
            }

            ImageFileName = dt_symsvr_module_name(Request->ModuleBase);
            newf = dt_symsvr_load_functions(Request->ModuleBase,
                                            ModuleData,
                                            ImageFileName);

            if (NULL != ImageFileName) {
                free(ImageFileName);
            }

            if (NULL == newf) {
                goto no_more;
            }

            dt_symsvr_free_funclist(f);
            f = newf;
            c = NULL;
            LoadedImageBase = Request->ModuleBase;
        }

        //
        // Reference the name filter.
        // This code will return all entries if glob or no filter.
        //

        PCSTR NameFilter = (PCSTR)(Request + 1);
        if (Request->Flags.DbgInfoPresent) {
            NameFilter += sizeof(MODLOAD_PDBGUID_PDBAGE);
        }

        if ((0 == *NameFilter) || strisglob(NameFilter)) {
            NameFilter = NULL;
        }

        if (NULL == NameFilter) {
            if (NULL != UsedNameFilter) {
                free(UsedNameFilter);
                UsedNameFilter = NULL;
            }
        } else {
            if ((NULL != UsedNameFilter) &&
                (0 != strcmp(NameFilter, UsedNameFilter))) {

                free(UsedNameFilter);
                UsedNameFilter = NULL;
            }

            if (NULL == UsedNameFilter) {
                UsedNameFilter = strdup(NameFilter);
            }
        }

        //
        // Check if resetting the walker.
        //

        if (0 == Index) {
            c = f;
        }

    skip_symbol:
        if (NULL == c) {
            goto no_more;
        }

        //
        // Copy string list of names as many as space allows.
        // If matching is required, the entry will be skipped if none of
        // names match.
        //

        BOOL Matched = FALSE;
        PSTR Names = (PSTR)(Reply + 1);
        PSTR Limit = ((PSTR)&buf[0] + (sizeof(buf) - 1));
        struct dt_symsvr_function_name* n;

        for (n = &c->Name; NULL != n; n = n->Next) {
            PCSTR Name = (PCSTR)(n + 1);

            if (!Matched &&
                ((NULL == UsedNameFilter) ||
                 (0 == strcmp(Name, UsedNameFilter)))) {

                Matched = TRUE;
            }

            SIZE_T NameSize = strlen(Name) + 1;
            if ((Names + NameSize) < Limit) {
                RtlCopyMemory(Names, Name, NameSize);
                Names += NameSize;
            }
        }

        if (!Matched) {
            c = c->Next;
            goto skip_symbol;
        }

        //
        // Write location information for those matching the requested
        // filter.
        //

        Reply->Rva = c->Rva;
        Reply->Size = c->Size;
        Reply->Flags.VaArgs = c->Flags.VaArgs;

        if (Names <= Limit) {
            *Names = '\0'; // Double-terminate.
        }

        //
        // Fill in parameter types multistring.
        //

        PSTR Parameters = Names + 1;
        struct dt_symsvr_function_parameter* pm;
        for (pm = c->Parameters; NULL != pm; pm = pm->Next) {
            PCSTR Param = (PCSTR)(pm + 1);
            SIZE_T ParamSize = strlen(Param) + 1;
            if ((Parameters + ParamSize) < Limit) {
                RtlCopyMemory(Parameters, Param, ParamSize);
                Parameters += ParamSize;
            }
        }

        if (Parameters <= Limit) {
            *Parameters = '\0'; // Double-terminate.
        }

        //
        // Prepare for the next iteration.
        //

        Reply->Index = Index + 1;
        Reply->NextEntryOffset = 0; // TODO: single entry for now.
        c = c->Next;
        continue;


    no_more:
        Reply->Index = (ULONG)-1;
    }


    if (!s->Exiting) {
        Sleep(100); // Rely on MM ensuring a forward progress in OOM condition.
        goto retry;
    }

    if (NULL != UsedNameFilter) {
        free(UsedNameFilter);
    }

    dt_symsvr_free_funclist(f);
    return 0;
}

struct dt_symsvr* dt_symsvr_start(void)
{
    DWORD Tid;
    struct dt_symsvr* s;

    s = malloc(sizeof(struct dt_symsvr));
    if (NULL == s) {
        goto error;
    }

    ZeroMemory(s, sizeof(struct dt_symsvr));

    s->Device = CreateFileW(L"\\\\.\\dtrace\\symsrv",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);

    if (INVALID_HANDLE_VALUE == s->Device) {
        dt_dprintf("symbol server failed to open control device, %08lx\n",
                   GetLastError());
        s->Device = NULL;
        goto error;
    }

    s->Thread = CreateThread(NULL, 0, dt_symsvr_thread, s, 0, &Tid);
    if (NULL == s->Thread) {
        goto error;
    }

    return s;

error:
    if (NULL != s) {
        dt_symsvr_stop(s);
    }

    return NULL;
}

void dt_symsvr_stop(struct dt_symsvr* svr)
{
    if (NULL != svr->Thread) {
        svr->Exiting = TRUE;
        while (WAIT_TIMEOUT ==
               WaitForSingleObject(svr->Thread,
                                   (CancelIoEx(svr->Device, NULL)
                                    ? INFINITE
                                    : 100))) {
            ;
        }
        CloseHandle(svr->Thread);
    }

    if (NULL != svr->Device) {
        CloseHandle(svr->Device);
    }

    free(svr);
    return;
}

