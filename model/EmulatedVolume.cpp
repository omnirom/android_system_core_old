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

static const char* kFusePath = "/system/bin/sdcard";

EmulatedVolume::EmulatedVolume(const std::string& rawPath)
    : VolumeBase(Type::kEmulated), mFusePid(0) {
    setId("emulated");
    mRawPath = rawPath;
    mLabel = "emulated";
}

EmulatedVolume::EmulatedVolume(const std::string& rawPath, dev_t device, const std::string& fsUuid)
    : VolumeBase(Type::kEmulated), mFusePid(0) {
    setId(StringPrintf("emulated:%u,%u", major(device), minor(device)));
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

    mFuseDefault = StringPrintf("/mnt/runtime/default/%s", label.c_str());
    mFuseRead = StringPrintf("/mnt/runtime/read/%s", label.c_str());
    mFuseWrite = StringPrintf("/mnt/runtime/write/%s", label.c_str());
    mFuseFull = StringPrintf("/mnt/runtime/full/%s", label.c_str());

    setInternalPath(mRawPath);
    setPath(StringPrintf("/storage/%s", label.c_str()));

    if (fs_prepare_dir(mFuseDefault.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mFuseRead.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mFuseWrite.c_str(), 0700, AID_ROOT, AID_ROOT) ||
        fs_prepare_dir(mFuseFull.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount points";
        return -errno;
    }

    dev_t before = GetDevice(mFuseFull);

    bool isFuse = base::GetBoolProperty(kPropFuseSnapshot, false);

    if (isFuse) {
        LOG(INFO) << "Mounting emulated fuse volume";
        android::base::unique_fd fd;
        int user_id = getMountUserId();
        int result = MountUserFuse(user_id, label, &fd);

        if (result != 0) {
            PLOG(ERROR) << "Failed to mount emulated fuse volume";
            return -result;
        }
        setFuseFd(std::move(fd));

        std::string pass_through_path(StringPrintf("/mnt/pass_through/%d/%s",
                                                   user_id, label.c_str()));
        return BindMount(getInternalPath(), pass_through_path);
    }

    if (!(mFusePid = fork())) {
        LOG(INFO) << "Executing sdcardfs";
        // clang-format off
        if (execl(kFusePath, kFusePath,
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

        LOG(ERROR) << "FUSE exiting";
        _exit(1);
    }

    if (mFusePid == -1) {
        PLOG(ERROR) << getId() << " failed to fork";
        return -errno;
    }

    nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);
    while (before == GetDevice(mFuseFull)) {
        LOG(DEBUG) << "Waiting for FUSE to spin up...";
        usleep(50000);  // 50ms

        nsecs_t now = systemTime(SYSTEM_TIME_BOOTTIME);
        if (nanoseconds_to_milliseconds(now - start) > 5000) {
            LOG(WARNING) << "Timed out while waiting for FUSE to spin up";
            return -ETIMEDOUT;
        }
    }
    /* sdcardfs will have exited already. FUSE will still be running */
    TEMP_FAILURE_RETRY(waitpid(mFusePid, nullptr, 0));
    mFusePid = 0;

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
        std::string path(StringPrintf("/mnt/user/%d/%s", getMountUserId(), label.c_str()));
        status_t result = ForceUnmount(path);
        if (result != OK) {
            // TODO(135341433): MNT_DETACH is needed for fuse because umount2 can fail with EBUSY.
            // Figure out why we get EBUSY and remove this special casing if possible.
            if (!umount2(path.c_str(), UMOUNT_NOFOLLOW | MNT_DETACH) || errno == EINVAL ||
                errno == ENOENT) {
                PLOG(INFO) << "ForceUnmount failed on emulated fuse volume";
            }
        }

        rmdir(path.c_str());
        setFuseFd(android::base::unique_fd());
        return OK;
    }

    ForceUnmount(mFuseDefault);
    ForceUnmount(mFuseRead);
    ForceUnmount(mFuseWrite);
    ForceUnmount(mFuseFull);

    rmdir(mFuseDefault.c_str());
    rmdir(mFuseRead.c_str());
    rmdir(mFuseWrite.c_str());
    rmdir(mFuseFull.c_str());

    mFuseDefault.clear();
    mFuseRead.clear();
    mFuseWrite.clear();
    mFuseFull.clear();

    return OK;
}

}  // namespace vold
}  // namespace android
