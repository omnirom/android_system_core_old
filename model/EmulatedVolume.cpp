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
#include <android-base/scopeguard.h>
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
    mUseSdcardFs = IsSdcardfsUsed();
    mAppDataIsolationEnabled = base::GetBoolProperty(kVoldAppDataIsolationEnabled, false);
}

EmulatedVolume::EmulatedVolume(const std::string& rawPath, dev_t device, const std::string& fsUuid,
                               int userId)
    : VolumeBase(Type::kEmulated) {
    setId(StringPrintf("emulated:%u,%u;%u", major(device), minor(device), userId));
    mRawPath = rawPath;
    mLabel = fsUuid;
    mFuseMounted = false;
    mUseSdcardFs = IsSdcardfsUsed();
    mAppDataIsolationEnabled = base::GetBoolProperty(kVoldAppDataIsolationEnabled, false);
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

// Creates a bind mount from source to target
static status_t doFuseBindMount(const std::string& source, const std::string& target,
                                std::list<std::string>& pathsToUnmount) {
    LOG(INFO) << "Bind mounting " << source << " on " << target;
    auto status = BindMount(source, target);
    if (status != OK) {
        return status;
    }
    LOG(INFO) << "Bind mounted " << source << " on " << target;
    pathsToUnmount.push_front(target);
    return OK;
}

status_t EmulatedVolume::mountFuseBindMounts() {
    std::string androidSource;
    std::string label = getLabel();
    int userId = getMountUserId();
    std::list<std::string> pathsToUnmount;

    auto unmounter = [&]() {
        LOG(INFO) << "mountFuseBindMounts() unmount scope_guard running";
        for (const auto& path : pathsToUnmount) {
            LOG(INFO) << "Unmounting " << path;
            auto status = UnmountTree(path);
            if (status != OK) {
                LOG(INFO) << "Failed to unmount " << path;
            } else {
                LOG(INFO) << "Unmounted " << path;
            }
        }
    };
    auto unmount_guard = android::base::make_scope_guard(unmounter);

    if (mUseSdcardFs) {
        androidSource = StringPrintf("/mnt/runtime/default/%s/%d/Android", label.c_str(), userId);
    } else {
        androidSource = StringPrintf("/%s/%d/Android", mRawPath.c_str(), userId);
    }

    status_t status = OK;
    // When app data isolation is enabled, obb/ will be mounted per app, otherwise we should
    // bind mount the whole Android/ to speed up reading.
    if (!mAppDataIsolationEnabled) {
        std::string androidDataSource = StringPrintf("%s/data", androidSource.c_str());
        std::string androidDataTarget(
                StringPrintf("/mnt/user/%d/%s/%d/Android/data", userId, label.c_str(), userId));
        status = doFuseBindMount(androidDataSource, androidDataTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }

        std::string androidObbSource = StringPrintf("%s/obb", androidSource.c_str());
        std::string androidObbTarget(
                StringPrintf("/mnt/user/%d/%s/%d/Android/obb", userId, label.c_str(), userId));
        status = doFuseBindMount(androidObbSource, androidObbTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }
    }

    // Installers get the same view as all other apps, with the sole exception that the
    // OBB dirs (Android/obb) are writable to them. On sdcardfs devices, this requires
    // a special bind mount, since app-private and OBB dirs share the same GID, but we
    // only want to give access to the latter.
    if (mUseSdcardFs) {
        std::string obbSource(StringPrintf("/mnt/runtime/write/%s/%d/Android/obb",
                label.c_str(), userId));
        std::string obbInstallerTarget(StringPrintf("/mnt/installer/%d/%s/%d/Android/obb",
                userId, label.c_str(), userId));

        status = doFuseBindMount(obbSource, obbInstallerTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }
    } else if (mAppDataIsolationEnabled) {
        std::string obbSource(StringPrintf("%s/obb", androidSource.c_str()));
        std::string obbInstallerTarget(StringPrintf("/mnt/installer/%d/%s/%d/Android/obb",
                userId, label.c_str(), userId));

        status = doFuseBindMount(obbSource, obbInstallerTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }
    }

    // /mnt/androidwriteable is similar to /mnt/installer, but it's for
    // MOUNT_EXTERNAL_ANDROID_WRITABLE apps and it can also access DATA (Android/data) dirs.
    if (mAppDataIsolationEnabled) {
        std::string obbSource = mUseSdcardFs ?
            StringPrintf("/mnt/runtime/write/%s/%d/Android/obb", label.c_str(), userId)
            : StringPrintf("%s/obb", androidSource.c_str());

        std::string obbAndroidWritableTarget(
                StringPrintf("/mnt/androidwritable/%d/%s/%d/Android/obb",
                userId, label.c_str(), userId));

        status = doFuseBindMount(obbSource, obbAndroidWritableTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }

        std::string dataSource = mUseSdcardFs ?
                StringPrintf("/mnt/runtime/write/%s/%d/Android/data", label.c_str(), userId)
                : StringPrintf("%s/data", androidSource.c_str());
        std::string dataTarget(StringPrintf("/mnt/androidwritable/%d/%s/%d/Android/data",
                userId, label.c_str(), userId));

        status = doFuseBindMount(dataSource, dataTarget, pathsToUnmount);
        if (status != OK) {
            return status;
        }
    }
    unmount_guard.Disable();
    return OK;
}

status_t EmulatedVolume::unmountFuseBindMounts() {
    std::string label = getLabel();
    int userId = getMountUserId();

    if (mUseSdcardFs || mAppDataIsolationEnabled) {
        std::string installerTarget(
                StringPrintf("/mnt/installer/%d/%s/%d/Android/obb", userId, label.c_str(), userId));
        LOG(INFO) << "Unmounting " << installerTarget;
        auto status = UnmountTree(installerTarget);
        if (status != OK) {
            LOG(ERROR) << "Failed to unmount " << installerTarget;
            // Intentional continue to try to unmount the other bind mount
        }
    }
    if (mAppDataIsolationEnabled) {
        std::string obbTarget( StringPrintf("/mnt/androidwritable/%d/%s/%d/Android/obb",
                userId, label.c_str(), userId));
        LOG(INFO) << "Unmounting " << obbTarget;
        auto status = UnmountTree(obbTarget);
        if (status != OK) {
            LOG(ERROR) << "Failed to unmount " << obbTarget;
            // Intentional continue to try to unmount the other bind mount
        }
        std::string dataTarget(StringPrintf("/mnt/androidwritable/%d/%s/%d/Android/data",
                userId, label.c_str(), userId));
        LOG(INFO) << "Unmounting " << dataTarget;
        status = UnmountTree(dataTarget);
        if (status != OK) {
            LOG(ERROR) << "Failed to unmount " << dataTarget;
            // Intentional continue to try to unmount the other bind mount
        }
    }

    // When app data isolation is enabled, kill all apps that obb/ is mounted, otherwise we should
    // umount the whole Android/ dir.
    if (mAppDataIsolationEnabled) {
        std::string appObbDir(StringPrintf("%s/%d/Android/obb", getPath().c_str(), userId));
        KillProcessesWithMountPrefix(appObbDir);
    } else {
        std::string androidDataTarget(
                StringPrintf("/mnt/user/%d/%s/%d/Android/data", userId, label.c_str(), userId));

        LOG(INFO) << "Unmounting " << androidDataTarget;
        auto status = UnmountTree(androidDataTarget);
        if (status != OK) {
            return status;
        }
        LOG(INFO) << "Unmounted " << androidDataTarget;

        std::string androidObbTarget(
                StringPrintf("/mnt/user/%d/%s/%d/Android/obb", userId, label.c_str(), userId));

        LOG(INFO) << "Unmounting " << androidObbTarget;
        status = UnmountTree(androidObbTarget);
        if (status != OK) {
            return status;
        }
        LOG(INFO) << "Unmounted " << androidObbTarget;
    }
    return OK;
}

status_t EmulatedVolume::unmountSdcardFs() {
    if (!mUseSdcardFs || getMountUserId() != 0) {
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
    if (mUseSdcardFs && getMountUserId() == 0) {
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
        // Make sure we unmount sdcardfs if we bail out with an error below
        auto sdcardfs_unmounter = [&]() {
            LOG(INFO) << "sdcardfs_unmounter scope_guard running";
            unmountSdcardFs();
        };
        auto sdcardfs_guard = android::base::make_scope_guard(sdcardfs_unmounter);

        LOG(INFO) << "Mounting emulated fuse volume";
        android::base::unique_fd fd;
        int user_id = getMountUserId();
        auto volumeRoot = getRootPath();

        // Make sure Android/ dirs exist for bind mounting
        status_t res = PrepareAndroidDirs(volumeRoot);
        if (res != OK) {
            LOG(ERROR) << "Failed to prepare Android/ directories";
            return res;
        }

        res = MountUserFuse(user_id, getInternalPath(), label, &fd);
        if (res != 0) {
            PLOG(ERROR) << "Failed to mount emulated fuse volume";
            return res;
        }

        mFuseMounted = true;
        auto fuse_unmounter = [&]() {
            LOG(INFO) << "fuse_unmounter scope_guard running";
            fd.reset();
            if (UnmountUserFuse(user_id, getInternalPath(), label) != OK) {
                PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
            }
            mFuseMounted = false;
        };
        auto fuse_guard = android::base::make_scope_guard(fuse_unmounter);

        auto callback = getMountCallback();
        if (callback) {
            bool is_ready = false;
            callback->onVolumeChecking(std::move(fd), getPath(), getInternalPath(), &is_ready);
            if (!is_ready) {
                return -EIO;
            }
        }

        // Only do the bind-mounts when we know for sure the FUSE daemon can resolve the path.
        res = mountFuseBindMounts();
        if (res != OK) {
            return res;
        }

        ConfigureReadAheadForFuse(GetFuseMountPathForUser(user_id, label), 256u);

        // By default, FUSE has a max_dirty ratio of 1%. This means that out of
        // all dirty pages in the system, only 1% is allowed to belong to any
        // FUSE filesystem. The reason this is in place is that FUSE
        // filesystems shouldn't be trusted by default; a FUSE filesystem could
        // take up say 100% of dirty pages, and subsequently refuse to write
        // them back to storage.  The kernel will then apply rate-limiting, and
        // block other tasks from writing.  For this particular FUSE filesystem
        // however, we trust the implementation, because it is a part of the
        // Android platform. So use the default ratio of 100%.
        //
        // The reason we're setting this is that there's a suspicion that the
        // kernel starts rate-limiting the FUSE filesystem under extreme
        // memory pressure scenarios. While the kernel will only rate limit if
        // the writeback can't keep up with the write rate, under extreme
        // memory pressure the write rate may dip as well, in which case FUSE
        // writes to a 1% max_ratio filesystem are throttled to an extreme amount.
        //
        // To prevent this, just give FUSE 40% max_ratio, meaning it can take
        // up to 40% of all dirty pages in the system.
        ConfigureMaxDirtyRatioForFuse(GetFuseMountPathForUser(user_id, label), 40u);

        // All mounts where successful, disable scope guards
        sdcardfs_guard.Disable();
        fuse_guard.Disable();
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
        unmountFuseBindMounts();

        if (UnmountUserFuse(userId, getInternalPath(), label) != OK) {
            PLOG(INFO) << "UnmountUserFuse failed on emulated fuse volume";
            return -errno;
        }

        mFuseMounted = false;
    }

    return unmountSdcardFs();
}

std::string EmulatedVolume::getRootPath() const {
    int user_id = getMountUserId();
    std::string volumeRoot = StringPrintf("%s/%d", getInternalPath().c_str(), user_id);

    return volumeRoot;
}

}  // namespace vold
}  // namespace android
