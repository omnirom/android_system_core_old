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
    mFuseMounted = false;
}

EmulatedVolume::EmulatedVolume(const std::string& rawPath, dev_t device, const std::string& fsUuid,
                               int userId)
    : VolumeBase(Type::kEmulated) {
    setId(StringPrintf("emulated:%u,%u;%u", major(device), minor(device), userId));
    mRawPath = rawPath;
    mLabel = fsUuid;
    mFuseMounted = false;
}

EmulatedVolume::~EmulatedVolume() {}

std::string EmulatedVolume::getLabel() {
    // We could have migrated storage to an adopted private volume, so always
    // call primary storage "emulated" to avoid media rescans.
    if (getMountFlags() & MountFlags::kPrimary) {
        return "emulated";
    } else {
        return mLabel;
    }
}

static status_t mountFuseBindMounts(int userId, const std::string& label) {
    // TODO(b/134706060) we don't actually want to mount the "write" view by
    // default, since it gives write access to all OBB dirs.
    std::string androidSource(
            StringPrintf("/mnt/runtime/default/%s/%d/Android", label.c_str(), userId));
    std::string androidTarget(
            StringPrintf("/mnt/user/%d/%s/%d/Android", userId, label.c_str(), userId));

    if (access(androidSource.c_str(), F_OK) != 0) {
        // Android path may not exist yet if users has just been created; create it on
        // the lower fs.
        if (fs_prepare_dir(androidSource.c_str(), 0771, AID_ROOT, AID_ROOT) != 0) {
            PLOG(ERROR) << "Failed to create " << androidSource;
            return -errno;
        }
    }
    LOG(INFO) << "Bind mounting " << androidSource << " on " << androidTarget;
    auto status = BindMount(androidSource, androidTarget);
    if (status != OK) {
        return status;
    }
    LOG(INFO) << "Bind mounted " << androidSource << " on " << androidTarget;

    return OK;
}

static status_t unmountFuseBindMounts(int userId, const std::string& label) {
    std::string androidTarget(
            StringPrintf("/mnt/user/%d/%s/%d/Android", userId, label.c_str(), userId));

    LOG(INFO) << "Unmounting " << androidTarget;
    auto status = UnmountTree(androidTarget);
    if (status != OK) {
        return status;
    }
    LOG(INFO) << "Unmounted " << androidTarget;

    return OK;
}

status_t EmulatedVolume::doMount() {
    std::string label = getLabel();
    bool isVisible = getMountFlags() & MountFlags::kVisible;

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

    bool isFuse = base::GetBoolProperty(kPropFuse, false);

    // Mount sdcardfs regardless of FUSE, since we need it to bind-mount on top of the
    // FUSE volume for various reasons.
    if (getMountUserId() == 0) {
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
        sdcardFsPid = 0;
    }
    if (isFuse && isVisible) {
        LOG(INFO) << "Mounting emulated fuse volume";
        android::base::unique_fd fd;
        int user_id = getMountUserId();
        int result = MountUserFuse(user_id, getInternalPath(), label, &fd);

        if (result != 0) {
            PLOG(ERROR) << "Failed to mount emulated fuse volume";
            return -result;
        }

        mFuseMounted = true;
        auto callback = getMountCallback();
        if (callback) {
            bool is_ready = false;
            callback->onVolumeChecking(std::move(fd), getPath(), getInternalPath(), &is_ready);
            if (!is_ready) {
                return -EIO;
            }
        }

        // Only do the bind-mounts when we know for sure the FUSE daemon can resolve the path.
        return mountFuseBindMounts(user_id, label);
    }

    return OK;
}

status_t EmulatedVolume::doUnmount() {
    int userId = getMountUserId();

    // Kill all processes using the filesystem before we unmount it. If we
    // unmount the filesystem first, most file system operations will return
    // ENOTCONN until the unmount completes. This is an exotic and unusual
    // error code and might cause broken behaviour in applications.
    if (mFuseMounted) {
        // For FUSE specifically, we have an emulated volume per user, so only kill
        // processes using files from this particular user.
        std::string user_path(StringPrintf("%s/%d", getPath().c_str(), getMountUserId()));
        LOG(INFO) << "Killing all processes referencing " << user_path;
        KillProcessesUsingPath(user_path);
    } else {
        KillProcessesUsingPath(getPath());
    }

    if (mFuseMounted) {
        std::string label = getLabel();
        // Ignoring unmount return status because we do want to try to unmount
        // the rest cleanly.

        unmountFuseBindMounts(userId, label);
        if (UnmountUserFuse(userId, getInternalPath(), label) != OK) {
            PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
            return -errno;
        }

        mFuseMounted = false;
    }
    if (getMountUserId() != 0) {
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
