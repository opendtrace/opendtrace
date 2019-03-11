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

    pr_win32.c

Abstract:

    This file implements libproc compatibility layer for DTrace/NT.

--*/

#include <ntcompat.h>
#include <libproc.h>
#include <cvconst.h>


struct proc_handle {
    pid_t pid;
    int flags;
    BOOL readonly;
    BOOL exited;
    HANDLE hproc;
    HANDLE hdbg;
    HANDLE hdbgready;
    HANDLE hdbgcontinue;
};

static int pw32_maperr(DWORD err)
{
    switch (err) {
    case NO_ERROR:                return 0;
    case ERROR_ACCESS_DENIED:     return EACCES;
    case ERROR_INVALID_PARAMETER: return EINVAL;
    case ERROR_NOT_ENOUGH_MEMORY: return ENOMEM;
    case ERROR_NOT_ENOUGH_QUOTA:  return ENOMEM;
    case ERROR_FILE_NOT_FOUND:    return ENOENT;
    case ERROR_PATH_NOT_FOUND:    return ENOENT;
    case ERROR_INVALID_HANDLE:    return EBADF;
    default:                      return EINVAL;
    }
}

static void pw32_adjustkillonexit(void)
{
    /*
     * Though DebugSetProcessKillOnExit is not a part of the onecore,
     * it should still be adjusted on larger SKUs.
     */

    HMODULE hk32;
    BOOL (WINAPI* pDebugSetProcessKillOnExit)(BOOL);

    hk32 = GetModuleHandleA("kernel32.dll");
    if (NULL == hk32) {
        return;
    }

    *(PULONG_PTR)&pDebugSetProcessKillOnExit = (ULONG_PTR)
        GetProcAddress(hk32, "DebugSetProcessKillOnExit");

    if (NULL == pDebugSetProcessKillOnExit) {
        return;
    }

    (*pDebugSetProcessKillOnExit)(FALSE);
    return;
}

struct pw32_dbgthread_context {
    struct proc_handle* ph;
    const char* cmdline;
    const char* envp;
};

static DWORD CALLBACK pw32_dbgthread(PVOID param)
{
    struct pw32_dbgthread_context* ctx = (struct pw32_dbgthread_context*)param;
    struct proc_handle* ph = ctx->ph;
    DEBUG_EVENT dbge;
    DWORD dbgstatus;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD err = NO_ERROR;
    BOOL initialbp = FALSE;

    if (NULL != ctx->cmdline) {
        ZeroMemory(&pi, sizeof(pi));
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        if (!CreateProcessA(NULL,
                            (char*)ctx->cmdline,
                            NULL,
                            NULL,
                            FALSE,
                            DEBUG_ONLY_THIS_PROCESS,
                            (char*)ctx->envp,
                            NULL,
                            &si,
                            &pi)) {

            err = GetLastError();
            goto exit;
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ph->pid = pi.dwProcessId;

    } else {
        if (!DebugActiveProcess(ph->pid)) {
            err = GetLastError();
            goto exit;
        }
    }

    pw32_adjustkillonexit();

    for (;;) {
        if (ph->exited) {
            break;
        }

        if (!WaitForDebugEvent(&dbge, 100)) {
            err = GetLastError();
            if (ERROR_SEM_TIMEOUT == err) {
                continue;
            }

            break;
        }

        dbgstatus = DBG_CONTINUE;

        switch (dbge.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT:
            CloseHandle(dbge.u.CreateProcessInfo.hFile);
            if (!DuplicateHandle(GetCurrentProcess(),
                                 dbge.u.CreateProcessInfo.hProcess,
                                 GetCurrentProcess(),
                                 &ph->hproc,
                                 0,
                                 FALSE,
                                 DUPLICATE_SAME_ACCESS)) {
                ph->hproc = NULL;
                ph->exited = TRUE;
                break;
            }

            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            ph->exited = TRUE;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            break;

        case LOAD_DLL_DEBUG_EVENT:
            CloseHandle(dbge.u.LoadDll.hFile);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            break;

        case EXCEPTION_DEBUG_EVENT:
            switch(dbge.u.Exception.ExceptionRecord.ExceptionCode) {
            case EXCEPTION_BREAKPOINT:
                if (!initialbp) {
                    initialbp = TRUE;
                    SetEvent(ph->hdbgready);
                    WaitForSingleObject(ph->hdbgcontinue, INFINITE);
                }
                break;
            default:
                dbgstatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }
            break;
        default:
            break;
        }

        ContinueDebugEvent(dbge.dwProcessId, dbge.dwThreadId, dbgstatus);
    }

    DebugActiveProcessStop(ph->pid);

exit:
    return err;
}

void proc_free(struct proc_handle *phdl)
{
    if (NULL != phdl->hdbg) {
        phdl->exited = TRUE;
        proc_continue(phdl);
        WaitForSingleObject(phdl->hdbg, INFINITE);
        CloseHandle(phdl->hdbg);
    }

    if (NULL != phdl->hproc) {
        SymCleanup(phdl->hproc);
        CloseHandle(phdl->hproc);
    }

    if (NULL != phdl->hdbgready) {
        CloseHandle(phdl->hdbgready);
    }

    if (NULL != phdl->hdbgcontinue) {
        CloseHandle(phdl->hdbgcontinue);
    }

    free(phdl);
    return;
}

static PSTR pw32_sympath(void)
{
    DWORD len = 64*1024;
    PSTR p = (PSTR)malloc(len);
    if (NULL == p) {
        return NULL;
    }

    if (!SymGetSearchPath(GetCurrentProcess(), p, len)) {
        free(p);
        return NULL;
    }

    return p;
}

static int pw32_attach(pid_t pid, int flags, const char* cmdline,
                       const char* envp, struct proc_handle **pphdl)
{
    struct proc_handle *ph = NULL;
    DWORD err;
    DWORD tid;
    HANDLE h[2];
    struct pw32_dbgthread_context ctx;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    PSTR sympath = NULL;
    BOOL killoncleanup;
    BOOL RedirectionDisabled = FALSE;
    PVOID OldRedirectionDisabled = NULL;

    if (NULL == cmdline) {
        if (0 == pid) {
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }

        if ((GetCurrentProcessId() == pid) && (0 == (flags & PGRAB_RDONLY))) {
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }

        killoncleanup = FALSE;

    } else {
        if ((0 != flags) || (0 != pid)) {
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }

        killoncleanup = TRUE;
    }

    ph = (struct proc_handle*)malloc(sizeof(struct proc_handle));
    if (NULL == ph) {
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    ZeroMemory(ph, sizeof(*ph));
    ph->pid = pid;
    ph->readonly = 0 != (flags & PGRAB_RDONLY);

    if (ph->readonly) {
        if (NULL != cmdline) {
            ZeroMemory(&pi, sizeof(pi));
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            if (!CreateProcessA(NULL,
                                (char*)cmdline,
                                NULL,
                                NULL,
                                FALSE,
                                0,
                                (char*)envp,
                                NULL,
                                &si,
                                &pi)) {

                err = GetLastError();
                goto exit;
            }

            CloseHandle(pi.hThread);
            ph->pid = pi.dwProcessId;
            ph->hproc = pi.hProcess;

        } else {
            ph->hproc = OpenProcess((STANDARD_RIGHTS_REQUIRED |
                                     SYNCHRONIZE |
                                     PROCESS_QUERY_LIMITED_INFORMATION |
                                     PROCESS_VM_READ |
                                     PROCESS_VM_WRITE),
                                    FALSE,
                                    pid);

            if (NULL == ph->hproc) {
                err = GetLastError();
                goto exit;
            }
        }

    } else {
        ph->hdbgready = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (NULL == ph->hdbgready) {
            err = GetLastError();
            goto exit;
        }

        ph->hdbgcontinue = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (NULL == ph->hdbgcontinue) {
            err = GetLastError();
            goto exit;
        }

        ctx.ph = ph;
        ctx.cmdline = cmdline;
        ctx.envp = envp;

        ph->hdbg = CreateThread(NULL, 0, pw32_dbgthread, &ctx, 0, &tid);
        if (NULL == ph->hdbg) {
            err = GetLastError();
            goto exit;
        }

        h[0] = ph->hdbgready;
        h[1] = ph->hdbg;
        err = WaitForMultipleObjects(2, &h[0], FALSE, INFINITE);
        if (WAIT_OBJECT_0 != err) {
            if (WAIT_FAILED == err) {
                err = GetLastError();
            } else if (((WAIT_OBJECT_0 + 1) != err) || !GetExitCodeThread(ph->hdbg, &err)) {
                err = ERROR_NOT_ENOUGH_MEMORY;
            }

            goto exit;
        }
    }

    RedirectionDisabled = Wow64DisableWow64FsRedirection(&OldRedirectionDisabled);

    sympath = pw32_sympath();
    if (!SymInitialize(ph->hproc, sympath, TRUE)) {
        err = GetLastError();
        goto exit;
    }

    *pphdl = ph;
    ph = NULL;
    err = NO_ERROR;

exit:
    if (RedirectionDisabled) {
        Wow64RevertWow64FsRedirection(OldRedirectionDisabled);
    }

    if (NULL != sympath) {
        free(sympath);
    }

    if (NULL != ph) {
        proc_detach(ph, killoncleanup ? PRELEASE_KILL : 0);
    }

    return pw32_maperr(err);
}

static char* pw32_string_array_to_string(char *const *arr, char sep, char quote)
{
    char* s;
    char *const *p;
    char *d;
    size_t len;
    size_t buflen;

    buflen = 1;
    for (p = arr; NULL != *p; p += 1) {
        buflen += 1 + strlen(*p) + 1 + 1;
    }

    s = (char*)malloc(buflen);
    if (NULL == s) {
        return NULL;
    }

#define check_dest_buffer(_len_)                      \
    _Analysis_assume_(buflen >= ((d + (_len_)) - s)); \
    assert(buflen >= ((d + (_len_)) - s));

    d = s;
    for (p = arr; NULL != *p; p += 1) {
        if (p != arr) {
            check_dest_buffer(1); *(d++) = sep;
        }

        if (0 != quote) {
            check_dest_buffer(1); *(d++) = quote;
        }

        len  = strlen(*p);
        check_dest_buffer(len); memcpy(d, *p, len);
        d += len;
        if (0 != quote) {
            check_dest_buffer(1); *(d++) = quote;
        }

    }

    check_dest_buffer(1); *(d++) = '\0';
    check_dest_buffer(1); *(d++) = '\0';

    return s;
}

int proc_create(const char *file, char *const *argv, char *const *envp,
                proc_child_func *child_func, void *child_arg,
                struct proc_handle **pphdl)
{
    int err;
    char* cmd = NULL;
    char* env = NULL;

    if (NULL != child_func) {
        err = EINVAL;
        goto exit;;
    }

    if (0 != strcmp(file, argv[0])) {
        err = EINVAL;
        goto exit;;
    }

    cmd = pw32_string_array_to_string(argv, ' ', '"');
    if (NULL == cmd) {
        err = ENOMEM;
        goto exit;;
    }

    if (NULL != envp) {
        env = pw32_string_array_to_string(envp, '\0', '\0');
        if (NULL == env) {
            err = ENOMEM;
            goto exit;;
        }
    }

    err = pw32_attach(0, 0, cmd, env, pphdl);

exit:
    if (NULL != cmd) {
        free(cmd);
    }

    if (NULL != env) {
        free(env);
    }

    return err;
}

int proc_attach(pid_t pid, int flags, struct proc_handle **pphdl)
{
    return pw32_attach(pid, flags, NULL, NULL, pphdl);
}

int proc_detach(struct proc_handle *phdl, int reason)
{
    if (reason == PRELEASE_KILL) {
        TerminateProcess(phdl->hproc, -1);
    }

    proc_free(phdl);
    return 0;
}

int proc_continue(struct proc_handle *phdl)
{
    if (NULL == phdl->hdbgcontinue) {
        return -1;
    }

    SetEvent(phdl->hdbgcontinue);
    return 0;
}

int proc_getflags(struct proc_handle *phdl)
{
    return phdl->flags;
}

int proc_setflags(struct proc_handle *phdl, int flags)
{
    phdl->flags |= flags;
    return 0;
}

int proc_clearflags(struct proc_handle *phdl, int flags)
{
    phdl->flags &= ~flags;
    return 0;
}

pid_t proc_getpid(struct proc_handle *phdl)
{
    return phdl->pid;
}

HANDLE proc_gethandle(struct proc_handle *phdl)
{
    return phdl->hproc;
}

struct pw32_iter_objs_context {
    proc_map_f *func;
    void *cd;
};

static BOOL CALLBACK pw32_iter_objs_EnumModulesCallback(PCSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
    struct pw32_iter_objs_context* ctx = (struct pw32_iter_objs_context*)UserContext;
    return 0 == ctx->func(ctx->cd, BaseOfDll, ModuleName);
}

int proc_iter_objs(struct proc_handle *phdl, proc_map_f *func, void *cd)
{
    struct pw32_iter_objs_context ctx;
    ctx.func = func;
    ctx.cd = cd;
    if (!SymEnumerateModules64(phdl->hproc, pw32_iter_objs_EnumModulesCallback, &ctx)) {
        return pw32_maperr(GetLastError());
    }

    return 0;
}

uint64_t proc_addr2map(struct proc_handle *phdl, uintptr_t addr)
{
    return SymGetModuleBase64(phdl->hproc, addr);
}

static enum SymTagEnum pw32_symtag(PSYMBOL_INFO SymInfo)
{
    //
    // Translate 'SymTagPublicSymbol' to function to handle the case
    // when symbolic info is not available.
    //

    if (SymTagPublicSymbol == SymInfo->Tag) {
        if (0 != (SymInfo->Flags & (SYMFLAG_EXPORT |
                                    SYMFLAG_FUNCTION |
                                    SYMFLAG_PUBLIC_CODE))) {
            return SymTagFunction;
        }
    }

    return SymInfo->Tag;
}

struct pw32_iter_symbyaddr_context {
    struct proc_handle *phdl;
    const char* object_name;
    int which; int mask;
    proc_sym_f *func;
    void *cd;
};

static BOOL CALLBACK pw32_iter_symbyaddr_SymEnumSymbolsProc(PSYMBOL_INFO pSymInfo, DWORD SymbolSize, PVOID UserContext)
{
    struct pw32_iter_symbyaddr_context* ctx = (struct pw32_iter_symbyaddr_context*)UserContext;
    GElf_Sym sym;
    enum SymTagEnum Tag = pw32_symtag(pSymInfo);

    switch (Tag) {
    case SymTagFunction:
        if (0 == (TYPE_FUNC & ctx->mask)) {
            return TRUE;
        }
        break;

    default:
        return TRUE;
    }

    sym.st_value = pSymInfo->Address;
    sym.st_namep = pSymInfo->Name;
    sym.st_size = pSymInfo->Size;
    sym.st_tag = Tag;
    sym.st_type_idx = pSymInfo->TypeIndex;

    return 0 == ctx->func(ctx->cd, &sym, pSymInfo->Name);
}

static int pw32_iter_symbyaddr_f(void *cd, uint64_t vaddr, const char *object_name)
{
    struct pw32_iter_symbyaddr_context* ctx = (struct pw32_iter_symbyaddr_context*)cd;
    if (SymMatchFileName(object_name, ctx->object_name, NULL, NULL)) {
        if (!SymEnumSymbols(ctx->phdl->hproc, vaddr, NULL, pw32_iter_symbyaddr_SymEnumSymbolsProc, ctx)) {
            return pw32_maperr(GetLastError());
        }
    }

    return 0;
}

int proc_iter_symbyaddr(struct proc_handle *phdl,
    const char *object_name, int which, int mask, proc_sym_f *func, void *cd)
{
    struct pw32_iter_symbyaddr_context ctx;
    if (PR_SYMTAB != which) {
        return 0;
    }

    ctx.phdl = phdl;
    ctx.object_name = object_name;
    ctx.which = which;
    ctx.mask = mask;
    ctx.func = func;
    ctx.cd = cd;
    return proc_iter_objs(phdl, pw32_iter_symbyaddr_f, &ctx);
}

char *proc_objname(struct proc_handle *phdl, uintptr_t addr, char *buffer,
                   size_t bufsize)
{
    IMAGEHLP_MODULE64 info;
    assert(bufsize > 0);
    bufsize -= 1;
    ZeroMemory(&info, sizeof(info));
    info.SizeOfStruct = sizeof(info);
    if (!SymGetModuleInfo64(phdl->hproc, addr, &info)) {
        buffer[0] = '\0';
        return NULL;
    }

    buffer[bufsize] = '\0';
    return strncpy(buffer, info.ModuleName, bufsize);
}


struct pw32_name2map_context {
    const char* object_name;
    uint64_t base;
};

static BOOL CALLBACK pw32_name2map_EnumModulesCallback(PCSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
    struct pw32_name2map_context* ctx = (struct pw32_name2map_context*)UserContext;
    if (SymMatchFileName(ModuleName, ctx->object_name, NULL, NULL)) {
        ctx->base = BaseOfDll;
        return FALSE;
    }

    return TRUE;
}

uint64_t proc_name2map(struct proc_handle *phdl, const char *name)
{
    struct pw32_name2map_context ctx;
    ctx.object_name = name;
    ctx.base = 0;
    if (!SymEnumerateModules64(phdl->hproc, pw32_name2map_EnumModulesCallback, &ctx)) {
        return 0;
    }

    return ctx.base;
}

int proc_name2sym(struct proc_handle *phdl, const char *oname,
                  const char *sname, GElf_Sym *symp, prsyminfo_t *sip)
{
    int err;
    PSTR Name = NULL;
    struct {
        SYMBOL_INFO Info;
        CHAR NameBuffer[MAX_SYM_NAME];
    } Sym;

    if (NULL != oname) {
        Name = (PSTR)malloc(strlen(oname) + 1 + strlen(sname) + 1);
        if (NULL == Name) {
            err = ENOMEM;
            goto exit;
        }

        strcpy(Name, oname);
        strcat(Name, "!");
        strcat(Name, sname);
        sname = Name;
    }

    Sym.Info.SizeOfStruct = sizeof(SYMBOL_INFO);
    Sym.Info.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(phdl->hproc, sname, &Sym.Info)) {
        err = pw32_maperr(GetLastError());
        goto exit;
    }

    symp->st_value = Sym.Info.Address;
    symp->st_namep = NULL;
    symp->st_size = Sym.Info.Size;
    symp->st_tag = pw32_symtag(&Sym.Info);
    symp->st_type_idx = Sym.Info.TypeIndex;

    if (NULL != sip) {
        sip->prs_id = 0;
    }

    err = 0;

exit:
    if (NULL != Name) {
        free(Name);
    }
    return err;
}

int proc_addr2sym(struct proc_handle *phdl, uintptr_t addr, char *buf,
                  size_t size, GElf_Sym *symp)
{
    int err;
    DWORD64 Displacement;
    struct {
        SYMBOL_INFO Info;
        CHAR NameBuffer[MAX_SYM_NAME];
    } Sym;

    Sym.Info.SizeOfStruct = sizeof(SYMBOL_INFO);
    Sym.Info.MaxNameLen = MAX_SYM_NAME;

    if (!SymFromAddr(phdl->hproc, addr, &Displacement, &Sym.Info)) {
        err = pw32_maperr(GetLastError());
        goto exit;
    }

    symp->st_value = Sym.Info.Address;
    symp->st_namep = NULL;
    symp->st_size = Sym.Info.Size;
    symp->st_tag = pw32_symtag(&Sym.Info);
    symp->st_type_idx = Sym.Info.TypeIndex;

    if (0 != size) {
        size -= 1;
        if (size < Sym.Info.NameLen) {
            size = Sym.Info.NameLen;
        }

        CopyMemory(buf, &Sym.Info.Name[0], size);
        buf[size] = '\0';
    }

    err = 0;

exit:
    return err;
}

