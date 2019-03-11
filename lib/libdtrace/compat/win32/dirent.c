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

    dirent.c

Abstract:

    This file implements opendir/readdir/closedir for DTrace/NT compatibility
    layer.

--*/

#include <ntcompat.h>
#include "dirent.h"

struct DIR_internal {
    intptr_t handle;
    struct _finddata_t finddata;
    int first_try;
    struct dirent dirent;
};

DIR* opendir(const char* name)
{
    struct DIR_internal* dir = malloc(sizeof(struct DIR_internal));
    size_t len = strlen(name);
    char* pattern;

    if (!dir) {
        return (DIR*)0;
    }

    pattern = _alloca(len + 3);
    strcpy(pattern, name);
    strcat(pattern, "\\*");

    dir->handle = _findfirst(pattern, &dir->finddata);
    if (-1 == dir->handle) {
        free(dir);
        return (DIR*)0;
    }

    dir->first_try = 1;
    dir->dirent.d_name = &dir->finddata.name[0];
    return (DIR*)dir;
}

struct dirent* readdir(DIR* dir)
{
    struct DIR_internal* dir_int =  (struct DIR_internal*)dir;

    if (!dir_int->first_try) {
        if (0 != _findnext(dir_int->handle, &dir_int->finddata)) {
            return (struct dirent*)0;
        }
    } else {
        dir_int->first_try = 0;
    }

    return &dir_int->dirent;
}

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    entry;
    *result = readdir(dirp);
    return 0;
}

int closedir(DIR* dir)
{
    struct DIR_internal* dir_int =  (struct DIR_internal*)dir;
    int rv = _findclose(dir_int->handle);
    free(dir_int);
    return rv;
}




