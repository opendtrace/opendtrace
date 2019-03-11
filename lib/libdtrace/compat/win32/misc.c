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

    misc.c

Abstract:

    This file implements misc routines for DTrace/NT compatibility layer.

--*/

#include <ntcompat.h>

static long _GetMaximumProcessorCount(void)
{
    long Count;
    PPROCESSOR_GROUP_INFO GroupInfo;
    DWORD Index;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Information = NULL;
    DWORD Size = 0;

    Count = 1; // At least one is here.

    for (;;) {
        if (NULL != Information) {
            free(Information);
            Information = NULL;
        }

        if (0 != Size) {
            Information = malloc(Size);
            if (NULL == Information) {
                goto exit;
            }
        }

        if (GetLogicalProcessorInformationEx(RelationGroup, Information, &Size)) {
            break;
        }

        if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
            goto exit;
        }
    }

    Count = 0;
    for (Index = 0; Index < Information->Group.ActiveGroupCount; Index += 1) {
        GroupInfo = &Information->Group.GroupInfo[Index];
        Count += GroupInfo->MaximumProcessorCount;
    }

exit:
    if (NULL != Information) {
        free(Information);
    }

    return Count;
}

long sysconf(int name)
{
    assert((_SC_CPUID_MAX == name) ||
           (_SC_NPROCESSORS_MAX == name));

    switch (name) {
    case _SC_CPUID_MAX:
        return _GetMaximumProcessorCount() - 1;

    case _SC_NPROCESSORS_MAX:
        return _GetMaximumProcessorCount();

    default:
        return -1;
    }
}

int p_online(processorid_t processorid, int flag)
{
    return P_ONLINE;
}

int ftruncate(int fd, off_t length)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    SetFilePointer(h, length, 0, 0);
    SetEndOfFile(h);
    return 0;
}

char *ctime_r(const time_t *time, char *buf)
{
    return ctime_s(buf, 26, time) ? NULL : buf;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return localtime_s(result, timep) ? NULL : result;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    assert(-1 == fd);
    assert(0 == offset);
    assert((MAP_PRIVATE | MAP_ANON) == flags);
    assert((PROT_READ | PROT_WRITE) == prot);
    return VirtualAlloc(addr, length, MEM_COMMIT, PAGE_READWRITE);
}

int munmap(void *addr, size_t length)
{
    VirtualFree(addr, 0, MEM_RELEASE);
    return 0;
}

int mprotect(void *addr, size_t len, int prot)
{
    DWORD oldprotect;
    assert(PROT_READ == prot);
    if (VirtualProtect(addr, len, PAGE_READONLY, &oldprotect)) {
        return 0;
    } else {
        return -1;
    }
}

