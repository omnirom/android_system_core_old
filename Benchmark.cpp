/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Benchmark.h"
#include "BenchmarkGen.h"
#include "VolumeManager.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <cutils/iosched_policy.h>
#include <hardware_legacy/power.h>
#include <private/android_filesystem_config.h>

#include <thread>

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#define ENABLE_DROP_CACHES 1

using android::base::ReadFileToString;
using android::base::WriteStringToFile;

namespace android {
namespace vold {

static const char* kWakeLock = "Benchmark";

static status_t benchmarkInternal(const std::string& rootPath,
        android::os::PersistableBundle* extras) {
    auto path = rootPath;
    path += "/misc";
    if (android::vold::PrepareDir(path, 01771, AID_SYSTEM, AID_MISC)) {
        return -1;
    }
    path += "/vold";
    if (android::vold::PrepareDir(path, 0700, AID_ROOT, AID_ROOT)) {
        return -1;
    }
    path += "/bench";
    if (android::vold::PrepareDir(path, 0700, AID_ROOT, AID_ROOT)) {
        return -1;
    }

    errno = 0;
    int orig_prio = getpriority(PRIO_PROCESS, 0);
    if (errno != 0) {
        PLOG(ERROR) << "Failed to getpriority";
        return -1;
    }
    if (setpriority(PRIO_PROCESS, 0, -10) != 0) {
        PLOG(ERROR) << "Failed to setpriority";
        return -1;
    }

    IoSchedClass orig_clazz = IoSchedClass_NONE;
    int orig_ioprio = 0;
    if (android_get_ioprio(0, &orig_clazz, &orig_ioprio)) {
        PLOG(ERROR) << "Failed to android_get_ioprio";
        return -1;
    }
    if (android_set_ioprio(0, IoSchedClass_RT, 0)) {
        PLOG(ERROR) << "Failed to android_set_ioprio";
        return -1;
    }

    char orig_cwd[PATH_MAX];
    if (getcwd(orig_cwd, PATH_MAX) == NULL) {
        PLOG(ERROR) << "Failed getcwd";
        return -1;
    }
    if (chdir(path.c_str()) != 0) {
        PLOG(ERROR) << "Failed chdir";
        return -1;
    }

    sync();

    LOG(INFO) << "Benchmarking " << path;
    nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkCreate();
    sync();
    nsecs_t create = systemTime(SYSTEM_TIME_BOOTTIME);

#if ENABLE_DROP_CACHES
    LOG(VERBOSE) << "Before drop_caches";
    if (!WriteStringToFile("3", "/proc/sys/vm/drop_caches")) {
        PLOG(ERROR) << "Failed to drop_caches";
    }
    LOG(VERBOSE) << "After drop_caches";
#endif
    nsecs_t drop = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkRun();
    sync();
    nsecs_t run = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkDestroy();
    sync();
    nsecs_t destroy = systemTime(SYSTEM_TIME_BOOTTIME);

    if (chdir(orig_cwd) != 0) {
        PLOG(ERROR) << "Failed to chdir";
    }
    if (android_set_ioprio(0, orig_clazz, orig_ioprio)) {
        PLOG(ERROR) << "Failed to android_set_ioprio";
    }
    if (setpriority(PRIO_PROCESS, 0, orig_prio) != 0) {
        PLOG(ERROR) << "Failed to setpriority";
    }

    nsecs_t create_d = create - start;
    nsecs_t drop_d = drop - create;
    nsecs_t run_d = run - drop;
    nsecs_t destroy_d = destroy - run;

    LOG(INFO) << "create took " << nanoseconds_to_milliseconds(create_d) << "ms";
    LOG(INFO) << "drop took " << nanoseconds_to_milliseconds(drop_d) << "ms";
    LOG(INFO) << "run took " << nanoseconds_to_milliseconds(run_d) << "ms";
    LOG(INFO) << "destroy took " << nanoseconds_to_milliseconds(destroy_d) << "ms";

    extras->putString(String16("path"), String16(path.c_str()));
    extras->putString(String16("ident"), String16(BenchmarkIdent().c_str()));
    extras->putLong(String16("create"), create_d);
    extras->putLong(String16("drop"), drop_d);
    extras->putLong(String16("run"), run_d);
    extras->putLong(String16("destroy"), destroy_d);

    return 0;
}

void Benchmark(const std::string& path,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    android::os::PersistableBundle extras;
    status_t res = benchmarkInternal(path, &extras);
    if (listener) {
        listener->onFinished(res, extras);
    }

    release_wake_lock(kWakeLock);
}

}  // namespace vold
}  // namespace android
