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

    pthread.h

Abstract:

    This file implements the essentials of the pthread package for the
    DTrace/NT compatibility layer.

--*/

#pragma once

typedef SRWLOCK pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef SRWLOCK pthread_rwlock_t;
typedef HANDLE pthread_t;
typedef struct pthread_condattr {int dummy;} pthread_condattr_t;
typedef struct pthread_mutexattr {int dummy;} pthread_mutexattr_t;

#define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT

__inline int pthread_mutex_init(pthread_mutex_t *mutex,
                                const pthread_mutexattr_t *attr)
{
    assert(NULL == attr);
    InitializeSRWLock(mutex);
    return 0;
}

__inline int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    AcquireSRWLockExclusive(mutex);
    return 0;
}

__inline int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    return !TryAcquireSRWLockExclusive(mutex);
}

__inline int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    ReleaseSRWLockExclusive(mutex);
    return 0;
}

__inline int pthread_cond_init(pthread_cond_t *cond,
                               const pthread_condattr_t *attr)
{
    assert(NULL == attr);
    InitializeConditionVariable(cond);
    return 0;
}

__inline int pthread_cond_reltimedwait_np(pthread_cond_t *cond,
                                          pthread_mutex_t *mutex,
                                          const struct timespec *reltime)
{
    DWORD ms = (DWORD)(reltime->tv_sec * 1000 + reltime->tv_nsec / 1000000);
    return !SleepConditionVariableSRW(cond, mutex, ms, 0);
}

__inline int pthread_cond_wait(pthread_cond_t *cond,
                               pthread_mutex_t *mutex)
{
    return !SleepConditionVariableSRW(cond, mutex, INFINITE, 0);
}

__inline int pthread_cond_broadcast(pthread_cond_t *cond)
{
    WakeAllConditionVariable(cond);
    return 0;
}

