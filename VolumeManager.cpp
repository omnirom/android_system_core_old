/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_PACKAGE_MANAGER

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>

#include <linux/kdev_t.h>

#include <ApexProperties.sysprop.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <async_safe/log.h>

#include <cutils/fs.h>
#include <utils/Trace.h>

#include <selinux/android.h>

#include <sysutils/NetlinkEvent.h>

#include <private/android_filesystem_config.h>

#include <fscrypt/fscrypt.h>

#include "AppFuseUtil.h"
#include "Devmapper.h"
#include "FsCrypt.h"
#include "Loop.h"
#include "NetlinkManager.h"
#include "Process.h"
#include "Utils.h"
#include "VoldNativeService.h"
#include "VoldUtil.h"
#include "VolumeManager.h"
#include "fs/Ext4.h"
#include "fs/Vfat.h"
#include "model/EmulatedVolume.h"
#include "model/ObbVolume.h"
#include "model/PrivateVolume.h"
#include "model/StubVolume.h"

using android::OK;
using android::base::GetBoolProperty;
using android::base::StartsWith;
using android::base::StringAppendF;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::vold::BindMount;
using android::vold::CreateDir;
using android::vold::DeleteDirContents;
using android::vold::DeleteDirContentsAndDir;
using android::vold::EnsureDirExists;
using android::vold::IsFilesystemSupported;
using android::vold::IsSdcardfsUsed;
using android::vold::IsVirtioBlkDevice;
using android::vold::PrepareAndroidDirs;
using android::vold::PrepareAppDirFromRoot;
using android::vold::PrivateVolume;
using android::vold::Symlink;
using android::vold::Unlink;
using android::vold::UnmountTree;
using android::vold::VoldNativeService;
using android::vold::VolumeBase;

static const char* kPathUserMount = "/mnt/user";
static const char* kPathVirtualDisk = "/data/misc/vold/virtual_disk";

static const char* kPropVirtualDisk = "persist.sys.virtual_disk";

static const std::string kEmptyString("");

/* 512MiB is large enough for testing purposes */
static const unsigned int kSizeVirtualDisk = 536870912;

static const unsigned int kMajorBlockMmc = 179;

using ScanProcCallback = bool(*)(uid_t uid, pid_t pid, int nsFd, const char* name, void* params);

VolumeManager* VolumeManager::sInstance = NULL;

VolumeManager* VolumeManager::Instance() {
    if (!sInstance) sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mDebug = false;
    mNextObbId = 0;
    mNextStubId = 0;
    // For security reasons, assume that a secure keyguard is
    // showing until we hear otherwise
    mSecureKeyguardShowing = true;
}

VolumeManager::~VolumeManager() {}

int VolumeManager::updateVirtualDisk() {
    ATRACE_NAME("VolumeManager::updateVirtualDisk");
    if (GetBoolProperty(kPropVirtualDisk, false)) {
        if (access(kPathVirtualDisk, F_OK) != 0) {
            Loop::createImageFile(kPathVirtualDisk, kSizeVirtualDisk / 512);
        }

        if (mVirtualDisk == nullptr) {
            if (Loop::create(kPathVirtualDisk, mVirtualDiskPath) != 0) {
                LOG(ERROR) << "Failed to create virtual disk";
                return -1;
            }

            struct stat buf;
            if (stat(mVirtualDiskPath.c_str(), &buf) < 0) {
                PLOG(ERROR) << "Failed to stat " << mVirtualDiskPath;
                return -1;
            }

            auto disk = new android::vold::Disk(
                "virtual", buf.st_rdev, "virtual",
                android::vold::Disk::Flags::kAdoptable | android::vold::Disk::Flags::kSd);
            mVirtualDisk = std::shared_ptr<android::vold::Disk>(disk);
            handleDiskAdded(mVirtualDisk);
        }
    } else {
        if (mVirtualDisk != nullptr) {
            dev_t device = mVirtualDisk->getDevice();
            handleDiskRemoved(device);

            Loop::destroyByDevice(mVirtualDiskPath.c_str());
            mVirtualDisk = nullptr;
        }

        if (access(kPathVirtualDisk, F_OK) == 0) {
            unlink(kPathVirtualDisk);
        }
    }
    return 0;
}

int VolumeManager::setDebug(bool enable) {
    mDebug = enable;
    return 0;
}

int VolumeManager::start() {
    ATRACE_NAME("VolumeManager::start");

    // Always start from a clean slate by unmounting everything in
    // directories that we own, in case we crashed.
    unmountAll();

    Devmapper::destroyAll();
    Loop::destroyAll();

    // Assume that we always have an emulated volume on internal
    // storage; the framework will decide if it should be mounted.
    CHECK(mInternalEmulatedVolumes.empty());

    auto vol = std::shared_ptr<android::vold::VolumeBase>(
            new android::vold::EmulatedVolume("/data/media", 0));
    vol->setMountUserId(0);
    vol->create();
    mInternalEmulatedVolumes.push_back(vol);

    // Consider creating a virtual disk
    updateVirtualDisk();

    return 0;
}

void VolumeManager::handleBlockEvent(NetlinkEvent* evt) {
    std::lock_guard<std::mutex> lock(mLock);

    if (mDebug) {
        LOG(DEBUG) << "----------------";
        LOG(DEBUG) << "handleBlockEvent with action " << (int)evt->getAction();
        evt->dump();
    }

    std::string eventPath(evt->findParam("DEVPATH") ? evt->findParam("DEVPATH") : "");
    std::string devType(evt->findParam("DEVTYPE") ? evt->findParam("DEVTYPE") : "");

    if (devType != "disk") return;

    int major = std::stoi(evt->findParam("MAJOR"));
    int minor = std::stoi(evt->findParam("MINOR"));
    dev_t device = makedev(major, minor);

    switch (evt->getAction()) {
        case NetlinkEvent::Action::kAdd: {
            for (const auto& source : mDiskSources) {
                if (source->matches(eventPath)) {
                    // For now, assume that MMC and virtio-blk (the latter is
                    // specific to virtual platforms; see Utils.cpp for details)
                    // devices are SD, and that everything else is USB
                    int flags = source->getFlags();
                    if (major == kMajorBlockMmc || IsVirtioBlkDevice(major)) {
                        flags |= android::vold::Disk::Flags::kSd;
                    } else {
                        flags |= android::vold::Disk::Flags::kUsb;
                    }

                    auto disk =
                        new android::vold::Disk(eventPath, device, source->getNickname(), flags);
                    handleDiskAdded(std::shared_ptr<android::vold::Disk>(disk));
                    break;
                }
            }
            break;
        }
        case NetlinkEvent::Action::kChange: {
            LOG(DEBUG) << "Disk at " << major << ":" << minor << " changed";
            handleDiskChanged(device);
            break;
        }
        case NetlinkEvent::Action::kRemove: {
            handleDiskRemoved(device);
            break;
        }
        default: {
            LOG(WARNING) << "Unexpected block event action " << (int)evt->getAction();
            break;
        }
    }
}

void VolumeManager::handleDiskAdded(const std::shared_ptr<android::vold::Disk>& disk) {
    // For security reasons, if secure keyguard is showing, wait
    // until the user unlocks the device to actually touch it
    // Additionally, wait until user 0 is actually started, since we need
    // the user to be up before we can mount a FUSE daemon to handle the disk.
    bool userZeroStarted = mStartedUsers.find(0) != mStartedUsers.end();
    if (mSecureKeyguardShowing) {
        LOG(INFO) << "Found disk at " << disk->getEventPath()
                  << " but delaying scan due to secure keyguard";
        mPendingDisks.push_back(disk);
    } else if (!userZeroStarted) {
        LOG(INFO) << "Found disk at " << disk->getEventPath()
                  << " but delaying scan due to user zero not having started";
        mPendingDisks.push_back(disk);
    } else {
        disk->create();
        mDisks.push_back(disk);
    }
}

void VolumeManager::handleDiskChanged(dev_t device) {
    for (const auto& disk : mDisks) {
        if (disk->getDevice() == device) {
            disk->readMetadata();
            disk->readPartitions();
        }
    }

    // For security reasons, we ignore all pending disks, since
    // we'll scan them once the device is unlocked
}

void VolumeManager::handleDiskRemoved(dev_t device) {
    auto i = mDisks.begin();
    while (i != mDisks.end()) {
        if ((*i)->getDevice() == device) {
            (*i)->destroy();
            i = mDisks.erase(i);
        } else {
            ++i;
        }
    }
    auto j = mPendingDisks.begin();
    while (j != mPendingDisks.end()) {
        if ((*j)->getDevice() == device) {
            j = mPendingDisks.erase(j);
        } else {
            ++j;
        }
    }
}

void VolumeManager::addDiskSource(const std::shared_ptr<DiskSource>& diskSource) {
    std::lock_guard<std::mutex> lock(mLock);
    mDiskSources.push_back(diskSource);
}

std::shared_ptr<android::vold::Disk> VolumeManager::findDisk(const std::string& id) {
    for (auto disk : mDisks) {
        if (disk->getId() == id) {
            return disk;
        }
    }
    return nullptr;
}

std::shared_ptr<android::vold::VolumeBase> VolumeManager::findVolume(const std::string& id) {
    for (const auto& vol : mInternalEmulatedVolumes) {
        if (vol->getId() == id) {
            return vol;
        }
    }
    for (const auto& disk : mDisks) {
        auto vol = disk->findVolume(id);
        if (vol != nullptr) {
            return vol;
        }
    }
    for (const auto& vol : mObbVolumes) {
        if (vol->getId() == id) {
            return vol;
        }
    }
    return nullptr;
}

void VolumeManager::listVolumes(android::vold::VolumeBase::Type type,
                                std::list<std::string>& list) const {
    list.clear();
    for (const auto& disk : mDisks) {
        disk->listVolumes(type, list);
    }
}

int VolumeManager::forgetPartition(const std::string& partGuid, const std::string& fsUuid) {
    std::string normalizedGuid;
    if (android::vold::NormalizeHex(partGuid, normalizedGuid)) {
        LOG(WARNING) << "Invalid GUID " << partGuid;
        return -1;
    }

    bool success = true;
    std::string keyPath = android::vold::BuildKeyPath(normalizedGuid);
    if (unlink(keyPath.c_str()) != 0) {
        LOG(ERROR) << "Failed to unlink " << keyPath;
        success = false;
    }
    if (fscrypt_is_native()) {
        if (!fscrypt_destroy_volume_keys(fsUuid)) {
            success = false;
        }
    }
    return success ? 0 : -1;
}

void VolumeManager::destroyEmulatedVolumesForUser(userid_t userId) {
    // Destroy and remove all unstacked EmulatedVolumes for the user
    auto i = mInternalEmulatedVolumes.begin();
    while (i != mInternalEmulatedVolumes.end()) {
        auto vol = *i;
        if (vol->getMountUserId() == userId) {
            vol->destroy();
            i = mInternalEmulatedVolumes.erase(i);
        } else {
            i++;
        }
    }

    // Destroy and remove all stacked EmulatedVolumes for the user on each mounted private volume
    std::list<std::string> private_vols;
    listVolumes(VolumeBase::Type::kPrivate, private_vols);
    for (const std::string& id : private_vols) {
        PrivateVolume* pvol = static_cast<PrivateVolume*>(findVolume(id).get());
        std::list<std::shared_ptr<VolumeBase>> vols_to_remove;
        if (pvol->getState() == VolumeBase::State::kMounted) {
            for (const auto& vol : pvol->getVolumes()) {
                if (vol->getMountUserId() == userId) {
                    vols_to_remove.push_back(vol);
                }
            }
            for (const auto& vol : vols_to_remove) {
                vol->destroy();
                pvol->removeVolume(vol);
            }
        }  // else EmulatedVolumes will be destroyed on VolumeBase#unmount
    }
}

void VolumeManager::createEmulatedVolumesForUser(userid_t userId) {
    // Create unstacked EmulatedVolumes for the user
    auto vol = std::shared_ptr<android::vold::VolumeBase>(
            new android::vold::EmulatedVolume("/data/media", userId));
    vol->setMountUserId(userId);
    mInternalEmulatedVolumes.push_back(vol);
    vol->create();

    // Create stacked EmulatedVolumes for the user on each PrivateVolume
    std::list<std::string> private_vols;
    listVolumes(VolumeBase::Type::kPrivate, private_vols);
    for (const std::string& id : private_vols) {
        PrivateVolume* pvol = static_cast<PrivateVolume*>(findVolume(id).get());
        if (pvol->getState() == VolumeBase::State::kMounted) {
            auto evol =
                    std::shared_ptr<android::vold::VolumeBase>(new android::vold::EmulatedVolume(
                            pvol->getPath() + "/media", pvol->getRawDevice(), pvol->getFsUuid(),
                            userId));
            evol->setMountUserId(userId);
            pvol->addVolume(evol);
            evol->create();
        }  // else EmulatedVolumes will be created per user when on PrivateVolume#doMount
    }
}

int VolumeManager::onUserAdded(userid_t userId, int userSerialNumber) {
    LOG(INFO) << "onUserAdded: " << userId;

    mAddedUsers[userId] = userSerialNumber;
    return 0;
}

int VolumeManager::onUserRemoved(userid_t userId) {
    LOG(INFO) << "onUserRemoved: " << userId;

    onUserStopped(userId);
    mAddedUsers.erase(userId);
    return 0;
}

int VolumeManager::onUserStarted(userid_t userId) {
    LOG(INFO) << "onUserStarted: " << userId;

    if (mStartedUsers.find(userId) == mStartedUsers.end()) {
        createEmulatedVolumesForUser(userId);
    }

    mStartedUsers.insert(userId);

    createPendingDisksIfNeeded();
    return 0;
}

int VolumeManager::onUserStopped(userid_t userId) {
    LOG(VERBOSE) << "onUserStopped: " << userId;

    if (mStartedUsers.find(userId) != mStartedUsers.end()) {
        destroyEmulatedVolumesForUser(userId);
    }

    mStartedUsers.erase(userId);
    return 0;
}

void VolumeManager::createPendingDisksIfNeeded() {
    bool userZeroStarted = mStartedUsers.find(0) != mStartedUsers.end();
    if (!mSecureKeyguardShowing && userZeroStarted) {
        // Now that secure keyguard has been dismissed and user 0 has
        // started, process any pending disks
        for (const auto& disk : mPendingDisks) {
            disk->create();
            mDisks.push_back(disk);
        }
        mPendingDisks.clear();
    }
}

int VolumeManager::onSecureKeyguardStateChanged(bool isShowing) {
    mSecureKeyguardShowing = isShowing;
    createPendingDisksIfNeeded();
    return 0;
}

// This code is executed after a fork so it's very important that the set of
// methods we call here is strictly limited.
//
// TODO: Get rid of this guesswork altogether and instead exec a process
// immediately after fork to do our bindding for us.
static bool childProcess(const char* storageSource, const char* userSource, int nsFd,
                         const char* name) {
    if (setns(nsFd, CLONE_NEWNS) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to setns for %s :%s", name,
                              strerror(errno));
        return false;
    }

    // NOTE: Inlined from vold::UnmountTree here to avoid using PLOG methods and
    // to also protect against future changes that may cause issues across a
    // fork.
    if (TEMP_FAILURE_RETRY(umount2("/storage/", MNT_DETACH)) < 0 && errno != EINVAL &&
        errno != ENOENT) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to unmount /storage/ :%s",
                              strerror(errno));
        return false;
    }

    if (TEMP_FAILURE_RETRY(mount(storageSource, "/storage", NULL, MS_BIND | MS_REC, NULL)) == -1) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s for %s :%s",
                              storageSource, name, strerror(errno));
        return false;
    }

    if (TEMP_FAILURE_RETRY(mount(NULL, "/storage", NULL, MS_REC | MS_SLAVE, NULL)) == -1) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold",
                              "Failed to set MS_SLAVE to /storage for %s :%s", name,
                              strerror(errno));
        return false;
    }

    if (TEMP_FAILURE_RETRY(mount(userSource, "/storage/self", NULL, MS_BIND, NULL)) == -1) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s for %s :%s",
                              userSource, name, strerror(errno));
        return false;
    }

    return true;
}

// Fork the process and remount storage
bool forkAndRemountChild(uid_t uid, pid_t pid, int nsFd, const char* name, void* params) {
    int32_t mountMode = *static_cast<int32_t*>(params);
    std::string userSource;
    std::string storageSource;
    pid_t child;
    // Need to fix these paths to account for when sdcardfs is gone
    switch (mountMode) {
        case VoldNativeService::REMOUNT_MODE_NONE:
            return true;
        case VoldNativeService::REMOUNT_MODE_DEFAULT:
            storageSource = "/mnt/runtime/default";
            break;
        case VoldNativeService::REMOUNT_MODE_ANDROID_WRITABLE:
        case VoldNativeService::REMOUNT_MODE_INSTALLER:
            storageSource = "/mnt/runtime/write";
            break;
        case VoldNativeService::REMOUNT_MODE_PASS_THROUGH:
            return true;
        default:
            PLOG(ERROR) << "Unknown mode " << std::to_string(mountMode);
            return false;
    }
    LOG(DEBUG) << "Remounting " << uid << " as " << storageSource;

    // Fork a child to mount user-specific symlink helper into place
    userSource = StringPrintf("/mnt/user/%d", multiuser_get_user_id(uid));
    if (!(child = fork())) {
        if (childProcess(storageSource.c_str(), userSource.c_str(), nsFd, name)) {
            _exit(0);
        } else {
            _exit(1);
        }
    }

    if (child == -1) {
        PLOG(ERROR) << "Failed to fork";
        return false;
    } else {
        TEMP_FAILURE_RETRY(waitpid(child, nullptr, 0));
    }
    return true;
}

// Helper function to scan all processes in /proc and call the callback if:
// 1). pid belongs to an app process
// 2). If input uid is 0 or it matches the process uid
// 3). If userId is not -1 or userId matches the process userId
bool scanProcProcesses(uid_t uid, userid_t userId, ScanProcCallback callback, void* params) {
    DIR* dir;
    struct dirent* de;
    std::string rootName;
    std::string pidName;
    int pidFd;
    int nsFd;
    struct stat sb;

    static bool apexUpdatable = android::sysprop::ApexProperties::updatable().value_or(false);

    if (!(dir = opendir("/proc"))) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to opendir");
        return false;
    }

    // Figure out root namespace to compare against below
    if (!android::vold::Readlinkat(dirfd(dir), "1/ns/mnt", &rootName)) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to read root namespace");
        closedir(dir);
        return false;
    }

    async_safe_format_log(ANDROID_LOG_INFO, "vold", "Start scanning all processes");
    // Poke through all running PIDs look for apps running as UID
    while ((de = readdir(dir))) {
        pid_t pid;
        if (de->d_type != DT_DIR) continue;
        if (!android::base::ParseInt(de->d_name, &pid)) continue;

        pidFd = -1;
        nsFd = -1;

        pidFd = openat(dirfd(dir), de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (pidFd < 0) {
            goto next;
        }
        if (fstat(pidFd, &sb) != 0) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to stat %s", de->d_name);
            goto next;
        }
        if (uid != 0 && sb.st_uid != uid) {
            goto next;
        }
        if (userId != static_cast<userid_t>(-1) && multiuser_get_user_id(sb.st_uid) != userId) {
            goto next;
        }

        // Matches so far, but refuse to touch if in root namespace
        if (!android::vold::Readlinkat(pidFd, "ns/mnt", &pidName)) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold",
                    "Failed to read namespacefor %s", de->d_name);
            goto next;
        }
        if (rootName == pidName) {
            goto next;
        }

        if (apexUpdatable) {
            std::string exeName;
            // When ro.apex.bionic_updatable is set to true,
            // some early native processes have mount namespaces that are different
            // from that of the init. Therefore, above check can't filter them out.
            // Since the propagation type of / is 'shared', unmounting /storage
            // for the early native processes affects other processes including
            // init. Filter out such processes by skipping if a process is a
            // non-Java process whose UID is < AID_APP_START. (The UID condition
            // is required to not filter out child processes spawned by apps.)
            if (!android::vold::Readlinkat(pidFd, "exe", &exeName)) {
                goto next;
            }
            if (!StartsWith(exeName, "/system/bin/app_process") && sb.st_uid < AID_APP_START) {
                goto next;
            }
        }

        // We purposefully leave the namespace open across the fork
        // NOLINTNEXTLINE(android-cloexec-open): Deliberately not O_CLOEXEC
        nsFd = openat(pidFd, "ns/mnt", O_RDONLY);
        if (nsFd < 0) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold",
                    "Failed to open namespace for %s", de->d_name);
            goto next;
        }

        if (!callback(sb.st_uid, pid, nsFd, de->d_name, params)) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed in callback");
        }

    next:
        close(nsFd);
        close(pidFd);
    }
    closedir(dir);
    async_safe_format_log(ANDROID_LOG_INFO, "vold", "Finished scanning all processes");
    return true;
}

// In each app's namespace, unmount obb and data dirs
static bool umountStorageDirs(int nsFd, const char* android_data_dir, const char* android_obb_dir,
        int uid, const char* targets[], int size) {
    // This code is executed after a fork so it's very important that the set of
    // methods we call here is strictly limited.
    if (setns(nsFd, CLONE_NEWNS) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to setns %s", strerror(errno));
        return false;
    }

    // Unmount of Android/data/foo needs to be done before Android/data below.
    bool result = true;
    for (int i = 0; i < size; i++) {
        if (TEMP_FAILURE_RETRY(umount2(targets[i], MNT_DETACH)) < 0 && errno != EINVAL &&
                errno != ENOENT) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to umount %s: %s",
                                  targets[i], strerror(errno));
            result = false;
        }
    }

    // Mount tmpfs on Android/data and Android/obb
    if (TEMP_FAILURE_RETRY(umount2(android_data_dir, MNT_DETACH)) < 0 && errno != EINVAL &&
                errno != ENOENT) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to umount %s :%s",
                        android_data_dir, strerror(errno));
        result = false;
    }
    if (TEMP_FAILURE_RETRY(umount2(android_obb_dir, MNT_DETACH)) < 0 && errno != EINVAL &&
                errno != ENOENT) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to umount %s :%s",
                android_obb_dir, strerror(errno));
        result = false;
    }
    return result;
}

// In each app's namespace, mount tmpfs on obb and data dir, and bind mount obb and data
// package dirs.
static bool remountStorageDirs(int nsFd, const char* android_data_dir, const char* android_obb_dir,
        int uid, const char* sources[], const char* targets[], int size) {
    // This code is executed after a fork so it's very important that the set of
    // methods we call here is strictly limited.
    if (setns(nsFd, CLONE_NEWNS) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to setns %s", strerror(errno));
        return false;
    }

    // Mount tmpfs on Android/data and Android/obb
    if (TEMP_FAILURE_RETRY(mount("tmpfs", android_data_dir, "tmpfs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, "uid=0,gid=0,mode=0751")) == -1) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount tmpfs to %s :%s",
                        android_data_dir, strerror(errno));
        return false;
    }
    if (TEMP_FAILURE_RETRY(mount("tmpfs", android_obb_dir, "tmpfs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, "uid=0,gid=0,mode=0751")) == -1) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount tmpfs to %s :%s",
                android_obb_dir, strerror(errno));
        return false;
    }

    for (int i = 0; i < size; i++) {
        // Create package dir and bind mount it to the actual one.
        if (TEMP_FAILURE_RETRY(mkdir(targets[i], 0700)) == -1) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mkdir %s %s",
                    targets[i], strerror(errno));
            return false;
        }
        if (TEMP_FAILURE_RETRY(mount(sources[i], targets[i], NULL, MS_BIND | MS_REC, NULL)) == -1) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s to %s :%s",
                                  sources[i], targets[i], strerror(errno));
            return false;
        }
    }
    return true;
}

static std::string getStorageDirSrc(userid_t userId, const std::string& dirName,
        const std::string& packageName) {
    if (IsSdcardfsUsed()) {
        return StringPrintf("/mnt/runtime/default/emulated/%d/%s/%s",
                userId, dirName.c_str(), packageName.c_str());
    } else {
        return StringPrintf("/mnt/pass_through/%d/emulated/%d/%s/%s",
                userId, userId, dirName.c_str(), packageName.c_str());
    }
}

static std::string getStorageDirTarget(userid_t userId, std::string dirName,
        std::string packageName) {
    return StringPrintf("/storage/emulated/%d/%s/%s",
            userId, dirName.c_str(), packageName.c_str());
}

// Fork the process and remount / unmount app data and obb dirs
bool VolumeManager::forkAndRemountStorage(int uid, int pid, bool doUnmount,
                                          const std::vector<std::string>& packageNames) {
    userid_t userId = multiuser_get_user_id(uid);
    std::string mnt_path = StringPrintf("/proc/%d/ns/mnt", pid);
    android::base::unique_fd nsFd(
            TEMP_FAILURE_RETRY(open(mnt_path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (nsFd == -1) {
        PLOG(ERROR) << "Unable to open " << mnt_path.c_str();
        return false;
    }
    // Storing both Android/obb and Android/data paths.
    int size = packageNames.size() * 2;

    std::unique_ptr<std::string[]> sources(new std::string[size]);
    std::unique_ptr<std::string[]> targets(new std::string[size]);
    std::unique_ptr<const char*[]> sources_uptr(new const char*[size]);
    std::unique_ptr<const char*[]> targets_uptr(new const char*[size]);
    const char** sources_cstr = sources_uptr.get();
    const char** targets_cstr = targets_uptr.get();

    for (int i = 0; i < size; i += 2) {
        std::string const& packageName = packageNames[i/2];
        sources[i] = getStorageDirSrc(userId, "Android/data", packageName);
        targets[i] = getStorageDirTarget(userId, "Android/data", packageName);
        sources[i+1] = getStorageDirSrc(userId, "Android/obb", packageName);
        targets[i+1] = getStorageDirTarget(userId, "Android/obb", packageName);

        sources_cstr[i] = sources[i].c_str();
        targets_cstr[i] = targets[i].c_str();
        sources_cstr[i+1] = sources[i+1].c_str();
        targets_cstr[i+1] = targets[i+1].c_str();
    }

    for (int i = 0; i < size; i++) {
        // Make sure /storage/emulated/... paths are setup correctly
        // This needs to be done before EnsureDirExists to ensure Android/ is created.
        auto status = setupAppDir(targets_cstr[i], uid, false /* fixupExistingOnly */);
        if (status != OK) {
            PLOG(ERROR) << "Failed to create dir: " << targets_cstr[i];
            return false;
        }
        status = EnsureDirExists(sources_cstr[i], 0771, AID_MEDIA_RW, AID_MEDIA_RW);
        if (status != OK) {
            PLOG(ERROR) << "Failed to create dir: " << sources_cstr[i];
            return false;
        }
    }

    char android_data_dir[PATH_MAX];
    char android_obb_dir[PATH_MAX];
    snprintf(android_data_dir, PATH_MAX, "/storage/emulated/%d/Android/data", userId);
    snprintf(android_obb_dir, PATH_MAX, "/storage/emulated/%d/Android/obb", userId);

    pid_t child;
    // Fork a child to mount Android/obb android Android/data dirs, as we don't want it to affect
    // original vold process mount namespace.
    if (!(child = fork())) {
        if (doUnmount) {
            if (umountStorageDirs(nsFd, android_data_dir, android_obb_dir, uid,
                    targets_cstr, size)) {
                _exit(0);
            } else {
                _exit(1);
            }
        } else {
            if (remountStorageDirs(nsFd, android_data_dir, android_obb_dir, uid,
                    sources_cstr, targets_cstr, size)) {
                _exit(0);
            } else {
                _exit(1);
            }
        }
    }

    if (child == -1) {
        PLOG(ERROR) << "Failed to fork";
        return false;
    } else {
        int status;
        if (TEMP_FAILURE_RETRY(waitpid(child, &status, 0)) == -1) {
            PLOG(ERROR) << "Failed to waitpid: " << child;
            return false;
        }
        if (!WIFEXITED(status)) {
            PLOG(ERROR) << "Process did not exit normally, status: " << status;
            return false;
        }
        if (WEXITSTATUS(status)) {
            PLOG(ERROR) << "Process exited with code: " << WEXITSTATUS(status);
            return false;
        }
    }
    return true;
}

int VolumeManager::handleAppStorageDirs(int uid, int pid,
        bool doUnmount, const std::vector<std::string>& packageNames) {
    // Only run the remount if fuse is mounted for that user.
    userid_t userId = multiuser_get_user_id(uid);
    bool fuseMounted = false;
    for (auto& vol : mInternalEmulatedVolumes) {
        if (vol->getMountUserId() == userId && vol->getState() == VolumeBase::State::kMounted) {
            auto* emulatedVol = static_cast<android::vold::EmulatedVolume*>(vol.get());
            if (emulatedVol) {
                fuseMounted = emulatedVol->isFuseMounted();
            }
            break;
        }
    }
    if (fuseMounted) {
        forkAndRemountStorage(uid, pid, doUnmount, packageNames);
    }
    return 0;
}

int VolumeManager::abortFuse() {
    return android::vold::AbortFuseConnections();
}

int VolumeManager::reset() {
    // Tear down all existing disks/volumes and start from a blank slate so
    // newly connected framework hears all events.
    for (const auto& vol : mInternalEmulatedVolumes) {
        vol->destroy();
    }
    mInternalEmulatedVolumes.clear();

    for (const auto& disk : mDisks) {
        disk->destroy();
        disk->create();
    }
    updateVirtualDisk();
    mAddedUsers.clear();
    mStartedUsers.clear();
    return 0;
}

// Can be called twice (sequentially) during shutdown. should be safe for that.
int VolumeManager::shutdown() {
    if (mInternalEmulatedVolumes.empty()) {
        return 0;  // already shutdown
    }
    android::vold::sSleepOnUnmount = false;
    for (const auto& vol : mInternalEmulatedVolumes) {
        vol->destroy();
    }
    for (const auto& disk : mDisks) {
        disk->destroy();
    }

    mInternalEmulatedVolumes.clear();
    mDisks.clear();
    mPendingDisks.clear();
    android::vold::sSleepOnUnmount = true;

    return 0;
}

int VolumeManager::unmountAll() {
    std::lock_guard<std::mutex> lock(mLock);
    ATRACE_NAME("VolumeManager::unmountAll()");

    // First, try gracefully unmounting all known devices
    for (const auto& vol : mInternalEmulatedVolumes) {
        vol->unmount();
    }
    for (const auto& disk : mDisks) {
        disk->unmountAll();
    }

    // Worst case we might have some stale mounts lurking around, so
    // force unmount those just to be safe.
    FILE* fp = setmntent("/proc/mounts", "re");
    if (fp == NULL) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return -errno;
    }

    // Some volumes can be stacked on each other, so force unmount in
    // reverse order to give us the best chance of success.
    std::list<std::string> toUnmount;
    mntent* mentry;
    while ((mentry = getmntent(fp)) != NULL) {
        auto test = std::string(mentry->mnt_dir);
        if ((StartsWith(test, "/mnt/") &&
#ifdef __ANDROID_DEBUGGABLE__
             !StartsWith(test, "/mnt/scratch") &&
#endif
             !StartsWith(test, "/mnt/vendor") && !StartsWith(test, "/mnt/product") &&
             !StartsWith(test, "/mnt/installer") && !StartsWith(test, "/mnt/androidwritable")) ||
            StartsWith(test, "/storage/")) {
            toUnmount.push_front(test);
        }
    }
    endmntent(fp);

    for (const auto& path : toUnmount) {
        LOG(DEBUG) << "Tearing down stale mount " << path;
        android::vold::ForceUnmount(path);
    }

    return 0;
}

int VolumeManager::ensureAppDirsCreated(const std::vector<std::string>& paths, int32_t appUid) {
    int size = paths.size();
    for (int i = 0; i < size; i++) {
        int result = setupAppDir(paths[i], appUid, false /* fixupExistingOnly */,
                true /* skipIfDirExists */);
        if (result != OK) {
            return result;
        }
    }
    return OK;
}

int VolumeManager::setupAppDir(const std::string& path, int32_t appUid, bool fixupExistingOnly,
        bool skipIfDirExists) {
    // Only offer to create directories for paths managed by vold
    if (!StartsWith(path, "/storage/")) {
        LOG(ERROR) << "Failed to find mounted volume for " << path;
        return -EINVAL;
    }

    // Find the volume it belongs to
    auto filter_fn = [&](const VolumeBase& vol) {
        if (vol.getState() != VolumeBase::State::kMounted) {
            // The volume must be mounted
            return false;
        }
        if ((vol.getMountFlags() & VolumeBase::MountFlags::kVisible) == 0) {
            // and visible
            return false;
        }
        if (vol.getInternalPath().empty()) {
            return false;
        }
        if (vol.getMountUserId() != USER_UNKNOWN &&
            vol.getMountUserId() != multiuser_get_user_id(appUid)) {
            // The app dir must be created on a volume with the same user-id
            return false;
        }
        if (!path.empty() && StartsWith(path, vol.getPath())) {
            return true;
        }

        return false;
    };
    auto volume = findVolumeWithFilter(filter_fn);
    if (volume == nullptr) {
        LOG(ERROR) << "Failed to find mounted volume for " << path;
        return -EINVAL;
    }
    // Convert paths to lower filesystem paths to avoid making FUSE requests for these reasons:
    // 1. A FUSE request from vold puts vold at risk of hanging if the FUSE daemon is down
    // 2. The FUSE daemon prevents requests on /mnt/user/0/emulated/<userid != 0> and a request
    // on /storage/emulated/10 means /mnt/user/0/emulated/10
    const std::string lowerPath =
            volume->getInternalPath() + path.substr(volume->getPath().length());

    const std::string volumeRoot = volume->getRootPath();  // eg /data/media/0

    const int access_result = access(lowerPath.c_str(), F_OK);
    if (fixupExistingOnly && access_result != 0) {
        // Nothing to fixup
        return OK;
    }

    if (skipIfDirExists && access_result == 0) {
        // It's safe to assume it's ok as it will be used for zygote to bind mount dir only,
        // which the dir doesn't need to have correct permission for now yet.
        return OK;
    }

    if (volume->getType() == VolumeBase::Type::kPublic) {
        // On public volumes, we don't need to setup permissions, as everything goes through
        // FUSE; just create the dirs and be done with it.
        return fs_mkdirs(lowerPath.c_str(), 0700);
    }

    // Create the app paths we need from the root
    return PrepareAppDirFromRoot(lowerPath, volumeRoot, appUid, fixupExistingOnly);
}

int VolumeManager::fixupAppDir(const std::string& path, int32_t appUid) {
    if (IsSdcardfsUsed()) {
        //sdcardfs magically does this for us
        return OK;
    }
    return setupAppDir(path, appUid, true /* fixupExistingOnly */);
}

int VolumeManager::createObb(const std::string& sourcePath, const std::string& sourceKey,
                             int32_t ownerGid, std::string* outVolId) {
    int id = mNextObbId++;

    std::string lowerSourcePath;

    // Convert to lower filesystem path
    if (StartsWith(sourcePath, "/storage/")) {
        auto filter_fn = [&](const VolumeBase& vol) {
            if (vol.getState() != VolumeBase::State::kMounted) {
                // The volume must be mounted
                return false;
            }
            if ((vol.getMountFlags() & VolumeBase::MountFlags::kVisible) == 0) {
                // and visible
                return false;
            }
            if (vol.getInternalPath().empty()) {
                return false;
            }
            if (!sourcePath.empty() && StartsWith(sourcePath, vol.getPath())) {
                return true;
            }

            return false;
        };
        auto volume = findVolumeWithFilter(filter_fn);
        if (volume == nullptr) {
            LOG(ERROR) << "Failed to find mounted volume for " << sourcePath;
            return -EINVAL;
        } else {
            lowerSourcePath =
                    volume->getInternalPath() + sourcePath.substr(volume->getPath().length());
        }
    } else {
        lowerSourcePath = sourcePath;
    }

    auto vol = std::shared_ptr<android::vold::VolumeBase>(
            new android::vold::ObbVolume(id, lowerSourcePath, sourceKey, ownerGid));
    vol->create();

    mObbVolumes.push_back(vol);
    *outVolId = vol->getId();
    return android::OK;
}

int VolumeManager::destroyObb(const std::string& volId) {
    auto i = mObbVolumes.begin();
    while (i != mObbVolumes.end()) {
        if ((*i)->getId() == volId) {
            (*i)->destroy();
            i = mObbVolumes.erase(i);
        } else {
            ++i;
        }
    }
    return android::OK;
}

int VolumeManager::createStubVolume(const std::string& sourcePath, const std::string& mountPath,
                                    const std::string& fsType, const std::string& fsUuid,
                                    const std::string& fsLabel, int32_t flags,
                                    std::string* outVolId) {
    dev_t stubId = --mNextStubId;
    auto vol = std::shared_ptr<android::vold::StubVolume>(
            new android::vold::StubVolume(stubId, sourcePath, mountPath, fsType, fsUuid, fsLabel));

    int32_t passedFlags = 0;
    passedFlags |= (flags & android::vold::Disk::Flags::kUsb);
    passedFlags |= (flags & android::vold::Disk::Flags::kSd);
    if (flags & android::vold::Disk::Flags::kStubVisible) {
        passedFlags |= (flags & android::vold::Disk::Flags::kStubVisible);
    } else {
        passedFlags |= (flags & android::vold::Disk::Flags::kStubInvisible);
    }
    // StubDisk doesn't have device node corresponds to it. So, a fake device
    // number is used.
    auto disk = std::shared_ptr<android::vold::Disk>(
            new android::vold::Disk("stub", stubId, "stub", passedFlags));
    disk->initializePartition(vol);
    handleDiskAdded(disk);
    *outVolId = vol->getId();
    return android::OK;
}

int VolumeManager::destroyStubVolume(const std::string& volId) {
    auto tokens = android::base::Split(volId, ":");
    CHECK(tokens.size() == 2);
    dev_t stubId;
    CHECK(android::base::ParseUint(tokens[1], &stubId));
    handleDiskRemoved(stubId);
    return android::OK;
}

int VolumeManager::mountAppFuse(uid_t uid, int mountId, unique_fd* device_fd) {
    return android::vold::MountAppFuse(uid, mountId, device_fd);
}

int VolumeManager::unmountAppFuse(uid_t uid, int mountId) {
    return android::vold::UnmountAppFuse(uid, mountId);
}

int VolumeManager::openAppFuseFile(uid_t uid, int mountId, int fileId, int flags) {
    return android::vold::OpenAppFuseFile(uid, mountId, fileId, flags);
}
