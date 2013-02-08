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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <alloca.h>
#include <sys/klog.h>
#include <sys/types.h>
#include <sys/stat.h>

#define LOG_TAG "audit_log"
#include <cutils/log.h>

#include "libaudit.h"
#include "audit_log.h"

/*
 * Note that the flags passed to fcntl and the flags used
 * by fopen must be compatible. For instance, specifying
 * write only on one and read only on the other will yield
 * strange behavior.
 */
/* Mode for fopen */
#define AUDIT_LOG_FMODE "w+"
/* mode for fchmod*/
#define AUDIT_LOG_MODE  (S_IRUSR | S_IWUSR | S_IRGRP)
/* flags for fcntl */
#define AUDIT_LOG_FLAGS (O_RDWR | O_CREAT | O_SYNC)

#define AUDIT_TYPE    "type="
#define AUDIT_MSG     "msg="
#define AUDIT_KEYWORD "audit("

struct audit_log
{
    FILE *file;
    size_t total_bytes;
    size_t threshold;
    char *rotatefile;
    char *logfile;
};

/**
 * Wraps open with a fchmod to prevent umask issues from arising in
 * permission setting as well as a fcntl to set the underlying
 * fds mode. However, the rest of the library relies on stdio file
 * access, so a FILE pointer is returned.
 *
 * You must make sure your mode and fmode are compatible
 *
 * @param file
 *  File stream output
 * @param path
 *  The path of the log file
 * @param flags
 *  The flags passed to fcntl
 * @param fmode
 *  The mode passed to fopen
 * @param mode
 *  The mode passed to open and fchmod
 * @return
 *  0 on success with *file set, or -errno on error
 */
static int open_log(FILE **file, const char *path, int flags, const char *fmode, mode_t mode)
{
    int fd;
    int rc;

    if(!file) {
        return -EINVAL;
    }

    *file = fopen(path, fmode);
    if(!*file) {
        rc = -errno;
        SLOGE("Could not open audit log file %s : %s", path, strerror(errno));
        return rc;
    }

    rc = setvbuf(*file, NULL, _IONBF, 0);
    if (rc != 0) {
        rc = -errno;
        SLOGE("Could not setvbuf the log file");
        goto err;
    }

    fd = fileno(*file);
    rc = fchmod(fd, mode);
    if (rc < 0) {
        rc = -errno;
        SLOGE("Could not fchmod the log file");
        goto err;
    }

    rc = fcntl(fd, F_SETFD, flags);
    if (rc < 0) {
        rc = -errno;
        SLOGE("Could not fcntl the log file");
        goto err;
    }

    return 0;

err:
    fclose(*file);
    return rc;
}

audit_log *audit_log_open(const char *logfile, const char *rotatefile, size_t threshold)
{
    int rc;
    audit_log *l = NULL;
    struct stat log_file_stats;

    rc = stat(logfile, &log_file_stats);
    if (rc < 0) {
        if(errno != ENOENT) {
            SLOGE("Could not stat audit logfile %s: %s", logfile, strerror(errno));
            return NULL;
        }
        else {
            SLOGI("Previous audit logfile not detected");
        }
    }

    /* The existing log had data */
    if (rc == 0 && log_file_stats.st_size >= 0) {
        rc = rename(logfile, rotatefile);
        if (rc < 0) {
            SLOGE("Could not rename %s to %s: %s", logfile, rotatefile, strerror(errno));
            return NULL;
        }
        SLOGI("Previous audit logfile detected, rotating\n");
    }

    l = calloc(sizeof(struct audit_log), 1);
    if (!l) {
        SLOGE("Out of memory while allocating audit log");
        return NULL;
    }

    /* Open the output logfile */
    rc = open_log(&(l->file), logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_FMODE, AUDIT_LOG_MODE);
    if (rc < 0) {
        /* Error message handled by open_log() */
        return NULL;
    }

    l->rotatefile = strdup(rotatefile);
    if (!l->rotatefile) {
        SLOGE("Out of memory while duplicating rotatefile string");
        goto err;
    }

    l->logfile = strdup(logfile);
    if (!l->logfile) {
        SLOGE("Out of memory while duplicating logfile string");
        goto err;
    }

    l->threshold = threshold;

    return l;

err:
    audit_log_close(l);
    return NULL;
}

int audit_log_write(audit_log *l, const char *fmt, ...)
{
    int rc;
    va_list args;

    if (l == NULL || fmt == NULL) {
        return -EINVAL;
    }

    va_start(args, fmt);
    rc = vfprintf(l->file, fmt, args);
    va_end(args);

    if(rc < 0) {
        SLOGE("Error writing to log file");
        clearerr(l->file);
        rc = -EINVAL;
        goto out;
    }

    l->total_bytes += rc;

out:
    if(l->total_bytes > l->threshold) {
        /* audit_log_rotate() handles error message */
        rc = audit_log_rotate(l);
    }

    return rc;
}

int audit_log_rotate(audit_log *l)
{
    FILE *file;
    int rc = 0;

    if (!l) {
        return -EINVAL;
    }

    rc = rename(l->logfile, l->rotatefile);
    if (rc < 0) {
        rc = -errno;
        SLOGE("Could not rename audit log file \"%s\" to \"%s\", error: %s",
                l->logfile, l->rotatefile, strerror(errno));
        return rc;
    }

    rc = open_log(&file, l->logfile, AUDIT_LOG_FLAGS, AUDIT_LOG_FMODE, AUDIT_LOG_MODE);
    if (rc < 0) {
        /* Error message handled by open_log() */
        return rc;
    }

    fclose(l->file);
    l->total_bytes = 0;
    l->file = file;

    return 0;
}

void audit_log_close(audit_log *l)
{
    if (!l) {
        return;
    }

    free(l->logfile);
    free(l->rotatefile);
    if (l->file) {
        fclose(l->file);
    }
    free(l);
    return;
}

int audit_log_put_kmsg(audit_log *l)
{
    char *tok;
    char *audit;
    char *type;
    int rc = 0;
    char *buf = NULL;
    int len = klogctl(KLOG_SIZE_BUFFER, NULL, 0);

    /* No data to read */
    if (len == 0) {
        SLOGI("Empty kmsg");
        return 0;
    }

    /* Error */
    if (len < 0) {
        rc = -errno;
        SLOGE("Could not read kernel log length: %s", strerror(errno));
        return rc;
    }

    /* Data to read */
    len++;
    buf = malloc(len * sizeof(*buf));
    if (!buf) {
        SLOGE("Out of memory wile allocating kmsg buffer");
        return -ENOMEM;
    }

    rc = klogctl(KLOG_READ_ALL, buf, len);
    if (rc < 0) {
        rc = -errno;
        SLOGE("Could not read kernel log data: %s", strerror(errno));
        goto err;
    }

    buf[len - 1] = '\0';
    tok = buf;

    while ((tok = strtok(tok, "\r\n"))) {

        /* Only print audit messages The SPACE is important!! as we want the
         * audit pointer pointing to a space and not the beginning of the message.
         * This helps ensure that we don't erroneously going down the wrong path when
         * parsing this data.
         * XXX Should we include the space in the AUDIT_KEYWORD macro?
         */
        audit = strstr(tok, " "AUDIT_KEYWORD);
        if (audit) {

            /* Place a null terminator at the space, and advance the pointer past it */
            *audit++ = '\0';

            /* If it has type field, print that than msg=<rest> */
            type = strstr(tok, AUDIT_TYPE);
            if (type) {

                /*
                 * The type should be the the left of the space we replaced with a
                 * null terminator
                 *
                 * type is pointing to type=1400\0 and audit is pointing to audit(....\0
                 */
                rc = audit_log_write(l, "%s msg=%s\n", type, audit);
                if(rc < 0) {
                    /* audit_log_write handles error message */
                    goto err;
                }
            }
            /* It contined the AUDIT_KEWORD but was not formatted as expected, just dump it */
            else {
                SLOGW("Improperly formatted kernel audit message, dumping as is");
                rc = audit_log_write(l, "%s\n", audit);
                if(rc < 0) {
                    /* audit_log_write handles error message */
                    goto err;
                }
            }
        }
        tok = NULL;
    }

err:
    free(buf);
    return rc;
}
