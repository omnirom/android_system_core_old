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

#include "EmulatedVolume.h"

#include "AppFuseUtil.h"
#include "Utils.h"
#include "VolumeManager.h"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <cutils/fs.h>
#include <private/android_filesystem_config.h>
#include <utils/Timers.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>

using android::base::StringPrintf;

namespace android {
namespace vold {

static const char* kSdcardFsPath = "/system/bin/sdcard";

EmulatedVolume::EmulatedVolume(const std::string& rawPath, int userId)
    : VolumeBase(Type::kEmulated) {
    setId(StringPrintf("emulated;%u", userId));
    mRawPath = rawPath;
    mLabel = "emulated";
}

EmulatedVolume::EmulatedVolume(const std::string& rawPath, dev_t device, const std::string& fsUuid,
                               int userId)
    : VolumeBase(Type::kEmulated) {
    setId(StringPrintf("emulated:%u,%u;%u", major(device), minor(device), userId));
    mRawPath = rawPath;
    mLabel = fsUuid;
}

EmulatedVolume::~EmulatedVolume() {}

status_t EmulatedVolume::doMount() {
    // We could have migrated storage to an adopted private volume, so always
    // call primary storage "emulated" to avoid media rescans.
    std::string label = mLabel;
    if (getMountFlags() & MountFlags::kPrimary) {
        label = "emulated";
    }

    mSdcardFsDefault = StringPrintf("/mnt/runtime/default/%s", label.c_str());
    mSdcardFsRead = StringPrintf("/mnt/runtime/read/%s", label.c_str());
    mSdcardFsWrite = StringPrintf("/mnt/runtime/write/%s", label.c_str());
    mSdcardFsFull = StringPrintf("/mnt/runtime/full/%s", label.c_str());

    setInternalPath(mRawPath);
    setPath(StringPrintf("/storage/%s", label.c_str()));

    if (fs_prepare_dir(mSdcardFsDefault.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mSdcardFsRead.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mSdcardFsWrite.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mSdcardFsFull.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount points";
        return -errno;
    }

    dev_t before = GetDevice(mSdcardFsFull);

    bool isFuse = base::GetBoolProperty(kPropFuseSnapshot, false);

    if (isFuse) {
        LOG(INFO) << "Mounting emulated fuse volume";
        android::base::unique_fd fd;
        int user_id = getMountUserId();
        int result = MountUserFuse(user_id, getInternalPath(), label, &fd);

        if (result != 0) {
            PLOG(ERROR) << "Failed to mount emulated fuse volume";
            return -result;
        }

        auto callback = getMountCallback();
        if (callback) {
            bool is_ready = false;
            callback->onVolumeChecking(std::move(fd), getPath(), getInternalPath(), &is_ready);
            if (!is_ready) {
                return -EIO;
            }
        }

        return OK;
    } else if (getMountUserId() != 0) {
        // For sdcardfs, only mount for user 0, since user 0 will always be running
        // and the paths don't change for different users. Trying to double mount
        // will cause sepolicy to scream since sdcardfs prevents 'mounton'
        return OK;
    }

    LOG(INFO) << "Executing sdcardfs";
    int sdcardFsPid;
    if (!(sdcardFsPid = fork())) {
        // clang-format off
        if (execl(kSdcardFsPath, kSdcardFsPath,
                "-u", "1023", // AID_MEDIA_RW
                "-g", "1023", // AID_MEDIA_RW
                "-m",
                "-w",
                "-G",
                "-i",
                "-o",
                mRawPath.c_str(),
                label.c_str(),
                NULL)) {
            // clang-format on
            PLOG(ERROR) << "Failed to exec";
        }

        LOG(ERROR) << "sdcardfs exiting";
        _exit(1);
    }

    if (sdcardFsPid == -1) {
        PLOG(ERROR) << getId() << " failed to fork";
        return -errno;
    }

    nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);
    while (before == GetDevice(mSdcardFsFull)) {
        LOG(DEBUG) << "Waiting for sdcardfs to spin up...";
        usleep(50000);  // 50ms

        nsecs_t now = systemTime(SYSTEM_TIME_BOOTTIME);
        if (nanoseconds_to_milliseconds(now - start) > 5000) {
            LOG(WARNING) << "Timed out while waiting for sdcardfs to spin up";
            return -ETIMEDOUT;
        }
    }
    /* sdcardfs will have exited already. The filesystem will still be running */
    TEMP_FAILURE_RETRY(waitpid(sdcardFsPid, nullptr, 0));

    return OK;
}

status_t EmulatedVolume::doUnmount() {
    // Unmount the storage before we kill the FUSE process. If we kill
    // the FUSE process first, most file system operations will return
    // ENOTCONN until the unmount completes. This is an exotic and unusual
    // error code and might cause broken behaviour in applications.
    KillProcessesUsingPath(getPath());

    bool isFuse = base::GetBoolProperty(kPropFuseSnapshot, false);
    if (isFuse) {
        // We could have migrated storage to an adopted private volume, so always
        // call primary storage "emulated" to avoid media rescans.
        std::string label = mLabel;
        if (getMountFlags() & MountFlags::kPrimary) {
            label = "emulated";
        }

        std::string fuse_path(StringPrintf("/mnt/user/%d/%s", getMountUserId(), label.c_str()));
        std::string pass_through_path(
                StringPrintf("/mnt/pass_through/%d/%s", getMountUserId(), label.c_str()));
        if (UnmountUserFuse(pass_through_path, fuse_path) != OK) {
            PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
            return -errno;
        }

        rmdir(fuse_path.c_str());
        rmdir(pass_through_path.c_str());
        return OK;
    } else if (getMountUserId() != 0) {
        // For sdcardfs, only unmount for user 0, since user 0 will always be running
        // and the paths don't change for different users.
        return OK;
    }

    ForceUnmount(mSdcardFsDefault);
    ForceUnmount(mSdcardFsRead);
    ForceUnmount(mSdcardFsWrite);
    ForceUnmount(mSdcardFsFull);

    rmdir(mSdcardFsDefault.c_str());
    rmdir(mSdcardFsRead.c_str());
    rmdir(mSdcardFsWrite.c_str());
    rmdir(mSdcardFsFull.c_str());

    mSdcardFsDefault.clear();
    mSdcardFsRead.clear();
    mSdcardFsWrite.clear();
    mSdcardFsFull.clear();

    return OK;
}

}  // namespace vold
}  // namespace android
