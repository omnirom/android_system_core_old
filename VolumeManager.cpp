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
static const unsigned int kMajorBlockExperimentalMin = 240;
static const unsigned int kMajorBlockExperimentalMax = 254;

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

int VolumeManager::stop() {
    CHECK(!mInternalEmulatedVolumes.empty());
    for (const auto& vol : mInternalEmulatedVolumes) {
        vol->destroy();
    }
    mInternalEmulatedVolumes.clear();

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
                    // emulator-specific; see Disk.cpp for details) devices are SD,
                    // and that everything else is USB
                    int flags = source->getFlags();
                    if (major == kMajorBlockMmc || (android::vold::IsRunningInEmulator() &&
                                                    major >= (int)kMajorBlockExperimentalMin &&
                                                    major <= (int)kMajorBlockExperimentalMax)) {
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

int VolumeManager::linkPrimary(userid_t userId) {
    if (!GetBoolProperty(android::vold::kPropFuse, false)) {
        std::string source(mPrimary->getPath());
        if (mPrimary->isEmulated()) {
            source = StringPrintf("%s/%d", source.c_str(), userId);
            fs_prepare_dir(source.c_str(), 0755, AID_ROOT, AID_ROOT);
        }

        std::string target(StringPrintf("/mnt/user/%d/primary", userId));
        LOG(DEBUG) << "Linking " << source << " to " << target;
        Symlink(source, target);
    }
    return 0;
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

    if (!GetBoolProperty(android::vold::kPropFuse, false)) {
        // Note that sometimes the system will spin up processes from Zygote
        // before actually starting the user, so we're okay if Zygote
        // already created this directory.
        std::string path(StringPrintf("%s/%d", kPathUserMount, userId));
        fs_prepare_dir(path.c_str(), 0755, AID_ROOT, AID_ROOT);

        if (mPrimary) {
            linkPrimary(userId);
        }
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

int VolumeManager::setPrimary(const std::shared_ptr<android::vold::VolumeBase>& vol) {
    mPrimary = vol;
    for (userid_t userId : mStartedUsers) {
        linkPrimary(userId);
    }
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
        case VoldNativeService::REMOUNT_MODE_READ:
            storageSource = "/mnt/runtime/read";
            break;
        case VoldNativeService::REMOUNT_MODE_WRITE:
        case VoldNativeService::REMOUNT_MODE_LEGACY:
        case VoldNativeService::REMOUNT_MODE_INSTALLER:
            storageSource = "/mnt/runtime/write";
            break;
        case VoldNativeService::REMOUNT_MODE_FULL:
            storageSource = "/mnt/runtime/full";
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

int VolumeManager::remountUid(uid_t uid, int32_t mountMode) {
    if (GetBoolProperty(android::vold::kPropFuse, false)) {
        // TODO(135341433): Implement fuse specific logic.
        return 0;
    }
    return scanProcProcesses(uid, static_cast<userid_t>(-1),
            forkAndRemountChild, &mountMode) ? 0 : -1;
}

// Bind mount obb & data dir for an app if necessary.
// How it works:
// 1). Check if a pid is an app uid and not the FuseDaemon, if not then return.
// 2). Get the mounts for that pid.
// 3). If obb is already mounted then return, otherwise we need to mount obb for this pid.
// 4). Get all packages and uid mounted for jit profile. These packages are all packages with
// same uid or whitelisted apps.
// 5a). If there's no package, it means it's not a process running app data isolation, so
// just bind mount Android/obb & Android/data dir.
// 5b). Otherwise, for each package, create obb dir if it's not created and bind mount it.
// TODO: Should we get some reliable data from system server instead of scanning /proc ?
static bool bindMountAppDataObbDir(uid_t uid, pid_t pid, int nsFd, const char* name, void* params) {
    if (uid < AID_APP_START || uid > AID_APP_END) {
        return true;
    }
    if (android::vold::IsFuseDaemon(pid)) {
        return true;
    }
    async_safe_format_log(ANDROID_LOG_ERROR, "vold",
                          "Start mounting obb and data for uid:%d, pid:%d", uid, pid);

    userid_t userId = multiuser_get_user_id(uid);
    if (setns(nsFd, CLONE_NEWNS) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to setns %s", strerror(errno));
        return false;
    }

    std::string profiles_path(StringPrintf("/data/misc/profiles/cur/%d/", userId));
    // We search both .../obb and .../obb/$PKG paths here.
    std::string obb_path(StringPrintf("/storage/emulated/%d/Android/obb", userId));
    int profiles_path_len = profiles_path.length();
    int obb_path_len = obb_path.length();

    // TODO: Refactor the code as a util function so we can reuse the mount parsing code.
    std::string mounts_file(StringPrintf("/proc/%d/mounts", pid));
    auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(
            setmntent(mounts_file.c_str(), "r"), endmntent);
    if (!fp) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Error opening %s: %s",
                              mounts_file.c_str(), strerror(errno));
        return false;
    }

    // Check if obb directory is mounted, and get all packages of mounted app data directory.
    // We only need to check obb directory and assume if obb is mounted, data is mounted also.
    bool obb_mounted = false;
    std::vector<std::string> pkg_name_list;
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (strncmp(mentry->mnt_dir, profiles_path.c_str(), profiles_path_len) == 0) {
            pkg_name_list.push_back(std::string(mentry->mnt_dir + profiles_path_len));
        }
        if (strncmp(mentry->mnt_dir, obb_path.c_str(), obb_path_len) == 0) {
            obb_mounted = true;
        }
    }

    // Obb mounted in zygote already, so skip it
    if (obb_mounted) {
        return true;
    }

    std::string obbSource, dataSource;
    if (IsFilesystemSupported("sdcardfs")) {
        obbSource = StringPrintf("/mnt/runtime/default/emulated/%d/Android/obb", userId);
        dataSource = StringPrintf("/mnt/runtime/default/emulated/%d/Android/data", userId);
    } else {
        obbSource = StringPrintf("/mnt/pass_through/%d/emulated/%d/Android/obb", userId, userId);
        dataSource = StringPrintf("/mnt/pass_through/%d/emulated/%d/Android/data", userId, userId);
    }
    std::string obbTarget(StringPrintf("/storage/emulated/%d/Android/obb", userId));
    std::string dataTarget(StringPrintf("/storage/emulated/%d/Android/data", userId));

    // TODO: Review if these checks are still necessary
    auto status = EnsureDirExists(obbSource, 0771, AID_MEDIA_RW, AID_MEDIA_RW);
    if (status != OK) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to create dir %s %s",
                              obbSource.c_str(), strerror(-status));
        return false;
    }
    status = EnsureDirExists(dataSource, 0771, AID_MEDIA_RW, AID_MEDIA_RW);
    if (status != OK) {
        async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to create dir %s %s",
                              dataSource.c_str(), strerror(-status));
        return false;
    }

    // It means app data isolation is not applied to this, so we can just bind the whole obb
    // directory instead.
    if (pkg_name_list.empty()) {
        async_safe_format_log(ANDROID_LOG_INFO, "vold",
                              "Bind mounting whole obb and data directory for pid %d", pid);
        auto status1 = BindMount(obbSource, obbTarget);
        // Still bind mount data even obb fails, just slower to access obb dir
        auto status2 = BindMount(dataSource, dataTarget);
        if (status1 != OK) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s %s %s",
                                  obbSource.c_str(), obbTarget.c_str(), strerror(-status));
            return false;
        }
        if (status2 != OK) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s %s %s",
                                  dataSource.c_str(), dataTarget.c_str(), strerror(-status));
            return false;
        }
        return true;
    }

    // Bind mount each app's obb directory
    for (const auto& pkg_name : pkg_name_list) {
        std::string appObbSource, appDataSource;
        if (IsFilesystemSupported("sdcardfs")) {
            appObbSource = StringPrintf("/mnt/runtime/default/emulated/%d/Android/obb/%s",
                    userId, pkg_name.c_str());
            appDataSource = StringPrintf("/mnt/runtime/default/emulated/%d/Android/data/%s",
                    userId, pkg_name.c_str());
        } else {
            appObbSource = StringPrintf("/mnt/pass_through/%d/emulated/%d/Android/obb/%s",
                    userId, userId, pkg_name.c_str());
            appDataSource = StringPrintf("/mnt/pass_through/%d/emulated/%d/Android/data/%s",
                    userId, userId, pkg_name.c_str());
        }
        std::string appObbTarget(StringPrintf("/storage/emulated/%d/Android/obb/%s",
                userId, pkg_name.c_str()));
        std::string appDataTarget(StringPrintf("/storage/emulated/%d/Android/data/%s",
                userId, pkg_name.c_str()));

        status = EnsureDirExists(appObbSource, 0770, uid, AID_MEDIA_RW);
        if (status != OK) {
            async_safe_format_log(ANDROID_LOG_INFO, "vold", "Failed to ensure dir %s exists",
                                  appObbSource.c_str());
            continue;
        }
        status = EnsureDirExists(appDataSource, 0770, uid, AID_MEDIA_RW);
        if (status != OK) {
            async_safe_format_log(ANDROID_LOG_INFO, "vold", "Failed to ensure dir %s exists",
                                  appDataSource.c_str());
            continue;
        }
        async_safe_format_log(ANDROID_LOG_INFO, "vold",
                              "Bind mounting app obb and data directory(%s) for pid %d",
                              pkg_name.c_str(), pid);
        auto status1 = BindMount(appObbSource, appObbTarget);
        // Still bind mount data even obb fails, just slower to access obb dir
        auto status2 = BindMount(appDataSource, appDataTarget);
        if (status1 != OK) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s %s %s",
                                  obbSource.c_str(), obbTarget.c_str(), strerror(-status));
            continue;
        }
        if (status2 != OK) {
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Failed to mount %s %s %s",
                                  appDataSource.c_str(), appDataTarget.c_str(), strerror(-status));
            continue;
        }
    }
    return true;
}

int VolumeManager::remountAppStorageDirs(userid_t userId) {
    if (!GetBoolProperty(android::vold::kPropFuse, false)) {
        return 0;
    }
    LOG(INFO) << "Start remounting app obb and data";
    pid_t child;
    if (!(child = fork())) {
        // Child process
        if (daemon(0, 0) == -1) {
            PLOG(FATAL) << "Cannot create daemon";
        }
        // TODO(149548518): Refactor the code so minimize the work after fork to prevent deadlock.
        if (scanProcProcesses(0, userId, bindMountAppDataObbDir, nullptr)) {
            // As some forked zygote processes may not setuid and recognized as an app yet, sleep
            // 3s and try again to catch 'em all.
            usleep(3 * 1000 * 1000);  // 3s
            async_safe_format_log(ANDROID_LOG_ERROR, "vold", "Retry remounting app obb");
            scanProcProcesses(0, userId, bindMountAppDataObbDir, nullptr);
            _exit(0);
        } else {
            _exit(1);
        }
    }
    if (child == -1) {
        PLOG(ERROR) << "Failed to fork";
        return -1;
    } else if (child == 0) {
        // Parent
        int stat_loc;
        for (;;) {
            if (waitpid(child, &stat_loc, 0) != -1 || errno != EINTR) {
                break;
            }
        }
    }
    return 0;
}

bool VolumeManager::updateFuseMountedProperty() {
    if (mFuseMountedUsers.size() == 0) {
        android::base::SetProperty("vold.fuse_running_users", "");
        return true;
    }
    std::stringstream stream;
    char const * sep = "";
    for (const auto& userId : mFuseMountedUsers) {
        stream << sep;
        stream << userId;
        sep = ", ";
    }
    return android::base::SetProperty("vold.fuse_running_users", stream.str());
}

bool VolumeManager::addFuseMountedUser(userid_t userId) {
    mFuseMountedUsers.insert(userId);
    return updateFuseMountedProperty();
}

bool VolumeManager::removeFuseMountedUser(userid_t userId) {
    mFuseMountedUsers.erase(userId);
    return updateFuseMountedProperty();
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
    mFuseMountedUsers.clear();
    updateFuseMountedProperty();
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
    mFuseMountedUsers.clear();
    updateFuseMountedProperty();
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
             !StartsWith(test, "/mnt/installer")) ||
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

int VolumeManager::setupAppDir(const std::string& path, int32_t appUid, bool fixupExistingOnly) {
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

    if (fixupExistingOnly && (access(lowerPath.c_str(), F_OK) != 0)) {
        // Nothing to fixup
        return OK;
    }

    // Create the app paths we need from the root
    return PrepareAppDirFromRoot(lowerPath, volumeRoot, appUid, fixupExistingOnly);
}

int VolumeManager::fixupAppDir(const std::string& path, int32_t appUid) {
    if (IsFilesystemSupported("sdcardfs")) {
        //sdcardfs magically does this for us
        return OK;
    }
    return setupAppDir(path, appUid, true /* fixupExistingOnly */);
}

int VolumeManager::createObb(const std::string& sourcePath, const std::string& sourceKey,
                             int32_t ownerGid, std::string* outVolId) {
    int id = mNextObbId++;

    auto vol = std::shared_ptr<android::vold::VolumeBase>(
        new android::vold::ObbVolume(id, sourcePath, sourceKey, ownerGid));
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

    int32_t passedFlags = android::vold::Disk::Flags::kStub;
    passedFlags |= (flags & android::vold::Disk::Flags::kUsb);
    passedFlags |= (flags & android::vold::Disk::Flags::kSd);
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
