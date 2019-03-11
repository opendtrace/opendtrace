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

    string.c

Abstract:

    This file implements string utilities for the Dtrace/NT compatibility layer.

--*/

#include <ntcompat.h>

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;

    if (n != 0 && --n != 0) {
        do {
            if ((*d++ = *s++) == 0) {
                break;
            }
        } while (--n != 0);
    }

    if (n == 0) {
        if (siz != 0) {
            *d = '\0';
        }

        while (*s++) {
            ;
        }
    }

    return s - src - 1;
}

char *strndup(const char *s, size_t n)
{
    size_t len;
    char *dest;

    len = strlen(s);
    if (len > n) {
        len = n;
    }

    dest = malloc(len + 1);
    if (NULL != dest) {
        memcpy(dest, s, len);
        dest[len] = '\0';
    }

    return dest;
}

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    int cb;

    cb = _vscprintf(fmt, ap);
    if (cb < 0) {
        return cb;
    }

    *strp = (char*)malloc(cb + 1);
    if (NULL == *strp) {
        return -1;
    }

    return vsnprintf(*strp, cb + 1, fmt, ap);
}

int asprintf(char **strp, const char *fmt, ...)
{
    int cb;
    va_list ap;
    va_start(ap, fmt);
    cb = vasprintf(strp, fmt, ap);
    va_end(ap);
    return cb;
}

char* basename(char *path)
{
    static char fname[_MAX_FNAME+1];
    _splitpath(path, NULL, NULL, fname, NULL);
    return fname;
}

