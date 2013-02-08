/*
 * Copyright 2012, Samsung Telecommunications of America
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Written by William Roberts <w.roberts@sta.samsung.com>
 */

#define LOG_TAG "auditd"

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cutils/log.h>
#include <cutils/klog.h>

#include <cutils/log.h>
#include <private/android_filesystem_config.h>

#include <linux/capability.h>
#include <linux/prctl.h>

#include "libaudit.h"
#include "audit_log.h"

/*
 * TODO:
 *   Just Ideas:
 *   1. Add a socket interface for sending events
 */

#ifndef AUDITD_MAX_LOG_FILE_SIZEKB
#error "AUDITD_MAX_LOG_FILE_SIZEKB not defined by makefile!"
#endif

#define AUDITD_LOG_DIR "/data/misc/audit"
#define AUDITD_LOG_FILE AUDITD_LOG_DIR "/audit.log"
#define AUDITD_OLD_LOG_FILE AUDITD_LOG_DIR "/audit.old"

#define AUDITD_MAX_LOG_FILE_SIZE (1024 * AUDITD_MAX_LOG_FILE_SIZEKB)

static volatile int quit = 0;

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        quit = 1;
        break;
    }
    return;
}

static void usage(char *cmd)
{
    printf("%s - log audit events from the kernel\n"
            "OPTIONS\n"
            "-k - search dmesg on startup for audit events\n"
            "\n", cmd);
}

#define RAISE(ary, c) ary[CAP_TO_INDEX(c)].permitted |= CAP_TO_MASK(c);

static void drop_privileges_or_die(void)
{

    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];

    if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
        SLOGE("Failed on prctl KEEPCAPS: %s", strerror(errno));
        exit(1);
    }

    if (setgid(AID_AUDIT) < 0) {
        SLOGE("Failed on setgid: %s", strerror(errno));
        exit(1);
    }

    if (setuid(AID_AUDIT) < 0) {
        SLOGE("Failed on setuid: %s", strerror(errno));
        exit(1);
    }

    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    RAISE(capdata, CAP_AUDIT_CONTROL);
    RAISE(capdata, CAP_SYSLOG);

    capdata[0].effective = capdata[0].permitted;
    capdata[1].effective = capdata[1].permitted;
    capdata[0].inheritable = 0;
    capdata[1].inheritable = 0;

    if (capset(&capheader, &capdata[0]) < 0) {
        SLOGE("Failed on capset: %s", strerror(errno));
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int c;
    int rc;
    int audit_fd = -1;
    int check_kernel_log = 0;

    struct pollfd pfds;
    struct audit_reply rep;
    struct sigaction action;
    audit_log *l = NULL;

    SLOGI("Starting up");

    drop_privileges_or_die();

    /* register the signal handler */
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    rc = sigaction(SIGINT, &action, NULL);
    if (rc < 0) {
        rc = errno;
        SLOGE("Failed on set signal handler: %s", strerror(errno));
        goto err;
    }

    while ((c = getopt(argc, argv, "k")) != -1) {
        switch (c) {
        case 'k':
            check_kernel_log = 1;
            break;
        default:
            usage(argv[0]);
            goto err;
        }
    }

    /* Open the netlink socket for audit events */
    audit_fd = audit_open();
    if (audit_fd < 0) {
        rc = errno;
        SLOGE("Failed on audit_set_pid with error: %s", strerror(errno));
        goto err;
    }

    l = audit_log_open(AUDITD_LOG_FILE, AUDITD_OLD_LOG_FILE, AUDITD_MAX_LOG_FILE_SIZE);
    if (!l) {
        SLOGE("Failed on audit_log_open");
        goto err;
    }

    if (audit_set_pid(audit_fd, getpid(), WAIT_YES) < 0) {
        rc = errno;
        SLOGE("Failed on audit_set_pid with error: %s", strerror(errno));
        goto err;
    }

    pfds.fd = audit_fd;
    pfds.events = POLLIN;

    if (check_kernel_log) {
        audit_log_put_kmsg(l);
    }

    while (!quit) {

        /* Start reading for events */
        rc = poll(&pfds, 1, -1);
        if (rc == 0) {
            continue;
        } else if (rc < 0) {
            if (errno != EINTR) {
                SLOGE("Failed to poll audit log socket: %d : %s", errno, strerror(errno));
            }
            continue;
        }

        if (audit_get_reply(audit_fd, &rep, GET_REPLY_BLOCKING, 0) < 0) {
            SLOGE("Failed on audit_get_reply with error: %s", strerror(errno));
            continue;
        }

        audit_log_write(l, "type=%d msg=%.*s\n", rep.type, rep.len, rep.msg.data);
        /* Keep reading for events */
    }

err:
    SLOGI("Exiting");
    if (audit_fd >= 0) {
        audit_set_pid(audit_fd, 0, WAIT_NO);
        audit_close(audit_fd);
    }
    audit_log_close(l);
    return rc;
}
