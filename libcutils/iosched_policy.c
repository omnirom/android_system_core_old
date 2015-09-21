/*
** Copyright 2007-2014, The Android Open Source Project
** Copyright 2015, The CyanogenMod Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <cutils/iosched_policy.h>
#define LOG_TAG "iosched_policy"
#include <cutils/log.h>

#define __android_unused __attribute__((__unused__))

#if defined(__ANDROID__)
#define IOPRIO_WHO_PROCESS (1)
#define IOPRIO_CLASS_SHIFT (13)
#include <sys/syscall.h>
#include <sys/stat.h>

static int __rtio_cgroup_supported = -1;
static pthread_once_t __rtio_init_once = PTHREAD_ONCE_INIT;

int android_set_ioprio(int pid __android_unused, IoSchedClass clazz __android_unused, int ioprio __android_unused) {
    if (syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid, ioprio | (clazz << IOPRIO_CLASS_SHIFT))) {
        return -1;
    }
    return 0;
}

int android_get_ioprio(int pid __android_unused, IoSchedClass *clazz, int *ioprio) {
    int rc;

    if ((rc = syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, pid)) < 0) {
        return -1;
    }

    *clazz = (rc >> IOPRIO_CLASS_SHIFT);
    *ioprio = (rc & 0xff);
    return 0;
}

static void __initialize_rtio(void) {
    if (!access("/sys/fs/cgroup/bfqio/tasks", W_OK) ||
        !access("/sys/fs/cgroup/bfqio/rt-display/tasks", W_OK)) {
        __rtio_cgroup_supported = 1;
    } else {
        __rtio_cgroup_supported = 0;
    }
}

int android_set_rt_ioprio(int tid, int rt) {
    int fd = -1, rc = -1;

    pthread_once(&__rtio_init_once, __initialize_rtio);
    if (__rtio_cgroup_supported != 1) {
        return -1;
    }

    if (rt) {
        fd = open("/sys/fs/cgroup/bfqio/rt-display/tasks", O_WRONLY | O_CLOEXEC);
    } else {
        fd = open("/sys/fs/cgroup/bfqio/tasks", O_WRONLY | O_CLOEXEC);
    }

    if (fd < 0) {
        return -1;
    }

#ifdef HAVE_GETTID
    if (tid == 0) {
        tid = gettid();
    }
#endif

    // specialized itoa -- works for tid > 0
    char text[22];
    char *end = text + sizeof(text) - 1;
    char *ptr = end;
    *ptr = '\0';
    while (tid > 0) {
        *--ptr = '0' + (tid % 10);
        tid = tid / 10;
    }

    rc = write(fd, ptr, end - ptr);
    if (rc < 0) {
        /*
         * If the thread is in the process of exiting,
         * don't flag an error
         */
        if (errno == ESRCH) {
            rc = 0;
        } else {
            SLOGV("android_set_rt_ioprio failed to write '%s' (%s); fd=%d\n",
                  ptr, strerror(errno), fd);
        }
    }

    close(fd);
    return rc;
}

#else
int android_set_ioprio(int pid __android_unused, IoSchedClass clazz __android_unused, int ioprio __android_unused) {
    return 0;
}

int android_get_ioprio(int pid __android_unused, IoSchedClass *clazz, int *ioprio) {
    *clazz = IoSchedClass_NONE;
    *ioprio = 0;
    return 0;
}

int android_set_rt_ioprio(int tid __android_unused, int rt __android_unused)
{
    return 0;
}
#endif
