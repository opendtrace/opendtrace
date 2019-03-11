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

    ioctl.c

Abstract:

    This file implements the ioctl() routine for DTrace/NT compatibility layer.
    It is expected to be called with METHOD_NEITHER control codes only, so
    it will be up to the driver to probe and capture buffer contents.

--*/

#include <windows.h>
#include <devioctl.h>
#include <io.h>
#include <assert.h>

static int get_last_error()
{
    switch (GetLastError()) {
    case NO_ERROR:
        return 0;

    case ERROR_INVALID_PARAMETER:
        return EINVAL;

    case ERROR_NOACCESS:
        return EFAULT;

    case ERROR_BAD_COMMAND:
        return EBUSY;

    case ERROR_NOT_FOUND:
        return ENOENT;

    case ERROR_NO_MATCH:
        return ESRCH;

    case ERROR_INVALID_FUNCTION:
        return ENOTTY;

    case ERROR_ACCESS_DENIED:
        return EACCES;

    default:
        return EINVAL;
    }
}

int ioctl(int fd, unsigned long request, void* buf)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    ULONG done;

    assert(METHOD_NEITHER == METHOD_FROM_CTL_CODE(request));

    if (!DeviceIoControl(h, request, buf, 0, NULL, 0, &done, NULL)) {
        errno = get_last_error();
        return -1;
    }

    return 0;
}

