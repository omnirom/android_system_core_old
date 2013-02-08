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

#ifndef _AUDIT_LOG_H_
#define _AUDIT_LOG_H_

#include <unistd.h>
#include "libaudit.h"

typedef struct audit_log audit_log;

/**
 * Opens an audit logfile for writing
 * @param logfile
 *  The logfile name to use
 * @param rotatefile
 *  The logfile to rotate to when threshold is encountered
 * @param threshold
 *  The threshold, in bytes, the log file should grow to
 *  until rotation.
 * @return
 *  A valid handle to the audit_log or NULL on failure.
 */
extern audit_log *audit_log_open(const char *logfile, const char *rotatefile, size_t threshold);

/**
 * Writes a formatted message to the audit log
 * @param l
 *  The log to write too
 * @param fmt
 *  The fmt specifier as passed to fprintf/printf family of functions
 * @return
 *  0 on success or -errno on error
 *
 */
extern int audit_log_write(audit_log *l, const char *fmt, ...);

/**
 * Forces a rotation of the audit log.
 * @param l
 *  The log file to use
 * @return
 *  0 on success, -errno on failure.
 */
extern int audit_log_rotate(audit_log *l);

/**
 * Closes the audit log file.
 * @param l
 *  The log file to close.
 */
extern void audit_log_close(audit_log *l);

/**
 * Searches once through kmsg for type=1400
 * kernel messages and logs them to the audit log
 * @param l
 *  The log to append too
 * @return
 *  0 on success, -errno on failure.
 */
extern int audit_log_put_kmsg(audit_log *l);

#endif
