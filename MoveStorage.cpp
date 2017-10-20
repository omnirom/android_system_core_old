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

#include "MoveStorage.h"
#include "Utils.h"
#include "VolumeManager.h"

#include <android-base/stringprintf.h>
#include <android-base/logging.h>
#include <private/android_filesystem_config.h>
#include <hardware_legacy/power.h>

#include <thread>

#include <dirent.h>
#include <sys/wait.h>

#define CONSTRAIN(amount, low, high) ((amount) < (low) ? (low) : ((amount) > (high) ? (high) : (amount)))

#define EXEC_BLOCKING 0

using android::base::StringPrintf;

namespace android {
namespace vold {

// TODO: keep in sync with PackageManager
static const int kMoveSucceeded = -100;
static const int kMoveFailedInternalError = -6;

static const char* kCpPath = "/system/bin/cp";
static const char* kRmPath = "/system/bin/rm";

static const char* kWakeLock = "MoveTask";

static void notifyProgress(int progress,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    if (listener) {
        android::os::PersistableBundle extras;
        listener->onStatus(progress, extras);
    }
}

static status_t pushBackContents(const std::string& path, std::vector<std::string>& cmd,
        bool addWildcard) {
    DIR* dir = opendir(path.c_str());
    if (dir == NULL) {
        return -1;
    }
    bool found = false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if ((!strcmp(ent->d_name, ".")) || (!strcmp(ent->d_name, ".."))) {
            continue;
        }
        if (addWildcard) {
            cmd.push_back(StringPrintf("%s/%s/*", path.c_str(), ent->d_name));
        } else {
            cmd.push_back(StringPrintf("%s/%s", path.c_str(), ent->d_name));
        }
        found = true;
    }
    closedir(dir);
    return found ? OK : -1;
}

static status_t execRm(const std::string& path, int startProgress, int stepProgress,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    notifyProgress(startProgress, listener);

    uint64_t expectedBytes = GetTreeBytes(path);
    uint64_t startFreeBytes = GetFreeBytes(path);

    std::vector<std::string> cmd;
    cmd.push_back(kRmPath);
    cmd.push_back("-f"); /* force: remove without confirmation, no error if it doesn't exist */
    cmd.push_back("-R"); /* recursive: remove directory contents */
    if (pushBackContents(path, cmd, true) != OK) {
        LOG(WARNING) << "No contents in " << path;
        return OK;
    }

#if EXEC_BLOCKING
    return ForkExecvp(cmd);
#else
    pid_t pid = ForkExecvpAsync(cmd);
    if (pid == -1) return -1;

    int status;
    while (true) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (WIFEXITED(status)) {
                LOG(DEBUG) << "Finished rm with status " << WEXITSTATUS(status);
                return (WEXITSTATUS(status) == 0) ? OK : -1;
            } else {
                break;
            }
        }

        sleep(1);
        uint64_t deltaFreeBytes = GetFreeBytes(path) - startFreeBytes;
        notifyProgress(startProgress + CONSTRAIN((int)
                ((deltaFreeBytes * stepProgress) / expectedBytes), 0, stepProgress), listener);
    }
    return -1;
#endif
}

static status_t execCp(const std::string& fromPath, const std::string& toPath, int startProgress,
        int stepProgress, const android::sp<android::os::IVoldTaskListener>& listener) {
    notifyProgress(startProgress, listener);

    uint64_t expectedBytes = GetTreeBytes(fromPath);
    uint64_t startFreeBytes = GetFreeBytes(toPath);

    if (expectedBytes > startFreeBytes) {
        LOG(ERROR) << "Data size " << expectedBytes << " is too large to fit in free space "
                << startFreeBytes;
        return -1;
    }

    std::vector<std::string> cmd;
    cmd.push_back(kCpPath);
    cmd.push_back("-p"); /* preserve timestamps, ownership, and permissions */
    cmd.push_back("-R"); /* recurse into subdirectories (DEST must be a directory) */
    cmd.push_back("-P"); /* Do not follow symlinks [default] */
    cmd.push_back("-d"); /* don't dereference symlinks */
    if (pushBackContents(fromPath, cmd, false) != OK) {
        LOG(WARNING) << "No contents in " << fromPath;
        return OK;
    }
    cmd.push_back(toPath.c_str());

#if EXEC_BLOCKING
    return ForkExecvp(cmd);
#else
    pid_t pid = ForkExecvpAsync(cmd);
    if (pid == -1) return -1;

    int status;
    while (true) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (WIFEXITED(status)) {
                LOG(DEBUG) << "Finished cp with status " << WEXITSTATUS(status);
                return (WEXITSTATUS(status) == 0) ? OK : -1;
            } else {
                break;
            }
        }

        sleep(1);
        uint64_t deltaFreeBytes = startFreeBytes - GetFreeBytes(toPath);
        notifyProgress(startProgress + CONSTRAIN((int)
                ((deltaFreeBytes * stepProgress) / expectedBytes), 0, stepProgress), listener);
    }
    return -1;
#endif
}

static void bringOffline(const std::shared_ptr<VolumeBase>& vol) {
    vol->destroy();
    vol->setSilent(true);
    vol->create();
    vol->setMountFlags(0);
    vol->mount();
}

static void bringOnline(const std::shared_ptr<VolumeBase>& vol) {
    vol->destroy();
    vol->setSilent(false);
    vol->create();
}

static status_t moveStorageInternal(const std::shared_ptr<VolumeBase>& from,
        const std::shared_ptr<VolumeBase>& to,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    std::string fromPath;
    std::string toPath;

    // TODO: add support for public volumes
    if (from->getType() != VolumeBase::Type::kEmulated) goto fail;
    if (to->getType() != VolumeBase::Type::kEmulated) goto fail;

    // Step 1: tear down volumes and mount silently without making
    // visible to userspace apps
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOffline(from);
        bringOffline(to);
    }

    fromPath = from->getInternalPath();
    toPath = to->getInternalPath();

    // Step 2: clean up any stale data
    if (execRm(toPath, 10, 10, listener) != OK) {
        goto fail;
    }

    // Step 3: perform actual copy
    if (execCp(fromPath, toPath, 20, 60, listener) != OK) {
        goto copy_fail;
    }

    // NOTE: MountService watches for this magic value to know
    // that move was successful
    notifyProgress(82, listener);
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOnline(from);
        bringOnline(to);
    }

    // Step 4: clean up old data
    if (execRm(fromPath, 85, 15, listener) != OK) {
        goto fail;
    }

    notifyProgress(kMoveSucceeded, listener);
    return OK;

copy_fail:
    // if we failed to copy the data we should not leave it laying around
    // in target location. Do not check return value, we can not do any
    // useful anyway.
    execRm(toPath, 80, 1, listener);
fail:
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOnline(from);
        bringOnline(to);
    }
    notifyProgress(kMoveFailedInternalError, listener);
    return -1;
}

void MoveStorage(const std::shared_ptr<VolumeBase>& from, const std::shared_ptr<VolumeBase>& to,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    android::os::PersistableBundle extras;
    status_t res = moveStorageInternal(from, to, listener);
    if (listener) {
        listener->onFinished(res, extras);
    }

    release_wake_lock(kWakeLock);
}

}  // namespace vold
}  // namespace android
