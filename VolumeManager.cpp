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
#include "cryptfs.h"
#include "fs/Ext4.h"
#include "fs/Vfat.h"
#include "model/EmulatedVolume.h"
#include "model/ObbVolume.h"
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
using android::vold::Symlink;
using android::vold::Unlink;
using android::vold::UnmountTree;
using android::vold::VoldNativeService;

static const char* kPathUserMount = "/mnt/user";
static const char* kPathVirtualDisk = "/data/misc/vold/virtual_disk";

static const char* kIsolatedStorage = "persist.sys.isolated_storage";
static const char* kIsolatedStorageSnapshot = "sys.isolated_storage_snapshot";
static const char* kPropVirtualDisk = "persist.sys.virtual_disk";

static const std::string kEmptyString("");

/* 512MiB is large enough for testing purposes */
static const unsigned int kSizeVirtualDisk = 536870912;

static const unsigned int kMajorBlockMmc = 179;
static const unsigned int kMajorBlockExperimentalMin = 240;
static const unsigned int kMajorBlockExperimentalMax = 254;

VolumeManager* VolumeManager::sInstance = NULL;

VolumeManager* VolumeManager::Instance() {
    if (!sInstance) sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mDebug = false;
    mNextObbId = 0;
    mNextStubVolumeId = 0;
    // For security reasons, assume that a secure keyguard is
    // showing until we hear otherwise
    mSecureKeyguardShowing = true;
}

VolumeManager::~VolumeManager() {}

static bool hasIsolatedStorage() {
    return GetBoolProperty(kIsolatedStorageSnapshot, GetBoolProperty(kIsolatedStorage, true));
}

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
    CHECK(mInternalEmulated == nullptr);
    mInternalEmulated = std::shared_ptr<android::vold::VolumeBase>(
        new android::vold::EmulatedVolume("/data/media"));
    mInternalEmulated->create();

    // Consider creating a virtual disk
    updateVirtualDisk();

    return 0;
}

int VolumeManager::stop() {
    CHECK(mInternalEmulated != nullptr);
    mInternalEmulated->destroy();
    mInternalEmulated = nullptr;
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
    if (mSecureKeyguardShowing) {
        LOG(INFO) << "Found disk at " << disk->getEventPath()
                  << " but delaying scan due to secure keyguard";
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
    // Vold could receive "mount" after "shutdown" command in the extreme case.
    // If this happens, mInternalEmulated will equal nullptr and
    // we need to deal with it in order to avoid null pointer crash.
    if (mInternalEmulated != nullptr && mInternalEmulated->getId() == id) {
        return mInternalEmulated;
    }
    for (const auto& disk : mDisks) {
        auto vol = disk->findVolume(id);
        if (vol != nullptr) {
            return vol;
        }
    }
    for (const auto& vol : mStubVolumes) {
        if (vol->getId() == id) {
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
    std::string source(mPrimary->getPath());
    if (mPrimary->isEmulated()) {
        source = StringPrintf("%s/%d", source.c_str(), userId);
        fs_prepare_dir(source.c_str(), 0755, AID_ROOT, AID_ROOT);
    }

    std::string target(StringPrintf("/mnt/user/%d/primary", userId));
    LOG(DEBUG) << "Linking " << source << " to " << target;
    Symlink(source, target);
    return 0;
}

int VolumeManager::mountPkgSpecificDir(const std::string& mntSourceRoot,
                                       const std::string& mntTargetRoot,
                                       const std::string& packageName, const char* dirName) {
    std::string mntSourceDir =
        StringPrintf("%s/Android/%s/%s", mntSourceRoot.c_str(), dirName, packageName.c_str());
    if (CreateDir(mntSourceDir, 0755) < 0) {
        return -errno;
    }
    std::string mntTargetDir =
        StringPrintf("%s/Android/%s/%s", mntTargetRoot.c_str(), dirName, packageName.c_str());
    if (CreateDir(mntTargetDir, 0755) < 0) {
        return -errno;
    }
    return BindMount(mntSourceDir, mntTargetDir);
}

int VolumeManager::mountPkgSpecificDirsForRunningProcs(
    userid_t userId, const std::vector<std::string>& packageNames,
    const std::vector<std::string>& visibleVolLabels, int remountMode) {
    std::unique_ptr<DIR, decltype(&closedir)> dirp(opendir("/proc"), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Failed to opendir /proc";
        return -1;
    }

    std::string rootName;
    // Figure out root namespace to compare against below
    if (!android::vold::Readlinkat(dirfd(dirp.get()), "1/ns/mnt", &rootName)) {
        PLOG(ERROR) << "Failed to read root namespace";
        return -1;
    }

    struct stat mntFullSb;
    struct stat mntWriteSb;
    if (TEMP_FAILURE_RETRY(stat("/mnt/runtime/full", &mntFullSb)) == -1) {
        PLOG(ERROR) << "Failed to stat /mnt/runtime/full";
        return -1;
    }
    if (TEMP_FAILURE_RETRY(stat("/mnt/runtime/write", &mntWriteSb)) == -1) {
        PLOG(ERROR) << "Failed to stat /mnt/runtime/write";
        return -1;
    }

    std::string obbMountDir = StringPrintf("/mnt/user/%d/obb_mount", userId);
    if (fs_prepare_dir(obbMountDir.c_str(), 0700, AID_ROOT, AID_ROOT) != 0) {
        PLOG(ERROR) << "Failed to fs_prepare_dir " << obbMountDir;
        return -1;
    }
    const unique_fd obbMountDirFd(
        TEMP_FAILURE_RETRY(open(obbMountDir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)));
    if (obbMountDirFd.get() < 0) {
        PLOG(ERROR) << "Failed to open " << obbMountDir;
        return -1;
    }

    std::unordered_set<appid_t> validAppIds;
    for (auto& package : packageNames) {
        validAppIds.insert(mAppIds[package]);
    }
    std::vector<std::string>& userPackages = mUserPackages[userId];

    std::vector<pid_t> childPids;

    struct dirent* de;
    // Poke through all running PIDs look for apps running in userId
    while ((de = readdir(dirp.get()))) {
        pid_t pid;
        if (de->d_type != DT_DIR) continue;
        if (!android::base::ParseInt(de->d_name, &pid)) continue;

        const unique_fd pidFd(
            openat(dirfd(dirp.get()), de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (pidFd.get() < 0) {
            PLOG(WARNING) << "Failed to open /proc/" << pid;
            continue;
        }
        struct stat sb;
        if (fstat(pidFd.get(), &sb) != 0) {
            PLOG(WARNING) << "Failed to stat " << de->d_name;
            continue;
        }
        if (multiuser_get_user_id(sb.st_uid) != userId) {
            continue;
        }

        // Matches so far, but refuse to touch if in root namespace
        LOG(VERBOSE) << "Found matching PID " << de->d_name;
        std::string pidName;
        if (!android::vold::Readlinkat(pidFd.get(), "ns/mnt", &pidName)) {
            PLOG(WARNING) << "Failed to read namespace for " << de->d_name;
            continue;
        }
        if (rootName == pidName) {
            LOG(WARNING) << "Skipping due to root namespace";
            continue;
        }

        // Only update the mount points of processes running with one of validAppIds.
        // This should skip any isolated uids.
        appid_t appId = multiuser_get_app_id(sb.st_uid);
        if (validAppIds.find(appId) == validAppIds.end()) {
            continue;
        }

        std::vector<std::string> packagesForUid;
        for (auto& package : userPackages) {
            if (mAppIds[package] == appId) {
                packagesForUid.push_back(package);
            }
        }
        if (packagesForUid.empty()) {
            continue;
        }
        const std::string& sandboxId = mSandboxIds[appId];

        // We purposefully leave the namespace open across the fork
        unique_fd nsFd(openat(pidFd.get(), "ns/mnt", O_RDONLY));  // not O_CLOEXEC
        if (nsFd.get() < 0) {
            PLOG(WARNING) << "Failed to open namespace for " << de->d_name;
            continue;
        }

        pid_t child;
        if (!(child = fork())) {
            if (setns(nsFd.get(), CLONE_NEWNS) != 0) {
                PLOG(ERROR) << "Failed to setns for " << de->d_name;
                _exit(1);
            }

            int mountMode;
            if (remountMode == -1) {
                mountMode =
                    getMountModeForRunningProc(packagesForUid, userId, mntWriteSb, mntFullSb);
                if (mountMode == -1) {
                    _exit(1);
                }
            } else {
                mountMode = remountMode;
                if (handleMountModeInstaller(mountMode, obbMountDirFd.get(), obbMountDir,
                                             sandboxId) < 0) {
                    _exit(1);
                }
            }
            if (mountMode == VoldNativeService::REMOUNT_MODE_FULL ||
                mountMode == VoldNativeService::REMOUNT_MODE_LEGACY ||
                mountMode == VoldNativeService::REMOUNT_MODE_NONE) {
                // These mount modes are not going to change dynamically, so don't bother
                // unmounting/remounting dirs.
                _exit(0);
            }

            for (auto& volumeLabel : visibleVolLabels) {
                std::string mntSource = StringPrintf("/mnt/runtime/write/%s", volumeLabel.c_str());
                std::string mntTarget = StringPrintf("/storage/%s", volumeLabel.c_str());
                if (volumeLabel == "emulated") {
                    StringAppendF(&mntSource, "/%d", userId);
                    StringAppendF(&mntTarget, "/%d", userId);
                }

                std::string sandboxSource =
                    StringPrintf("%s/Android/sandbox/%s", mntSource.c_str(), sandboxId.c_str());
                if (CreateDir(sandboxSource, 0755) < 0) {
                    continue;
                }
                if (BindMount(sandboxSource, mntTarget) < 0) {
                    continue;
                }

                std::string obbSourceDir = StringPrintf("%s/Android/obb", mntSource.c_str());
                std::string obbTargetDir = StringPrintf("%s/Android/obb", mntTarget.c_str());
                if (UnmountTree(obbTargetDir) < 0) {
                    continue;
                }
                if (!createPkgSpecificDirRoots(mntSource) || !createPkgSpecificDirRoots(mntTarget)) {
                    continue;
                }
                for (auto& package : packagesForUid) {
                    mountPkgSpecificDir(mntSource, mntTarget, package, "data");
                    mountPkgSpecificDir(mntSource, mntTarget, package, "media");
                    if (mountMode != VoldNativeService::REMOUNT_MODE_INSTALLER) {
                        mountPkgSpecificDir(mntSource, mntTarget, package, "obb");
                    }
                }
                if (mountMode == VoldNativeService::REMOUNT_MODE_INSTALLER) {
                    if (BindMount(obbSourceDir, obbTargetDir) < 0) {
                        continue;
                    }
                }
            }
            _exit(0);
        }

        if (child == -1) {
            PLOG(ERROR) << "Failed to fork";
        } else {
            childPids.push_back(child);
        }
    }
    for (auto& child : childPids) {
        TEMP_FAILURE_RETRY(waitpid(child, nullptr, 0));
    }
    return 0;
}

int VolumeManager::getMountModeForRunningProc(const std::vector<std::string>& packagesForUid,
                                              userid_t userId, struct stat& mntWriteStat,
                                              struct stat& mntFullStat) {
    struct stat storageSb;
    if (TEMP_FAILURE_RETRY(stat("/storage", &storageSb)) == -1) {
        PLOG(ERROR) << "Failed to stat /storage";
        return -1;
    }

    // Some packages have access to full external storage, identify processes belonging
    // to those packages by comparing inode no.s of /mnt/runtime/full and /storage
    if (storageSb.st_dev == mntFullStat.st_dev && storageSb.st_ino == mntFullStat.st_ino) {
        return VoldNativeService::REMOUNT_MODE_FULL;
    } else if (storageSb.st_dev == mntWriteStat.st_dev && storageSb.st_ino == mntWriteStat.st_ino) {
        return VoldNativeService::REMOUNT_MODE_LEGACY;
    }

    std::string obbMountFile =
        StringPrintf("/mnt/user/%d/obb_mount/%s", userId, packagesForUid[0].c_str());
    if (TEMP_FAILURE_RETRY(access(obbMountFile.c_str(), F_OK)) != -1) {
        return VoldNativeService::REMOUNT_MODE_INSTALLER;
    } else if (errno != ENOENT) {
        PLOG(ERROR) << "Failed to access " << obbMountFile;
        return -1;
    }

    // Some packages don't have access to external storage and processes belonging to
    // those packages don't have anything mounted at /storage. So, identify those
    // processes by comparing inode no.s of /mnt/user/%d/package
    // and /storage
    std::string sandbox = StringPrintf("/mnt/user/%d/package", userId);
    struct stat sandboxStat;
    if (TEMP_FAILURE_RETRY(stat(sandbox.c_str(), &sandboxStat)) == -1) {
        PLOG(ERROR) << "Failed to stat " << sandbox;
        return -1;
    }
    if (storageSb.st_dev == sandboxStat.st_dev && storageSb.st_ino == sandboxStat.st_ino) {
        return VoldNativeService::REMOUNT_MODE_WRITE;
    }

    return VoldNativeService::REMOUNT_MODE_NONE;
}

int VolumeManager::handleMountModeInstaller(int mountMode, int obbMountDirFd,
                                            const std::string& obbMountDir,
                                            const std::string& sandboxId) {
    if (mountMode == VoldNativeService::REMOUNT_MODE_INSTALLER) {
        if (TEMP_FAILURE_RETRY(faccessat(obbMountDirFd, sandboxId.c_str(), F_OK, 0)) != -1) {
            return 0;
        } else if (errno != ENOENT) {
            PLOG(ERROR) << "Failed to access " << obbMountDir << "/" << sandboxId;
            return -errno;
        }
        const unique_fd fd(
            TEMP_FAILURE_RETRY(openat(obbMountDirFd, sandboxId.c_str(), O_RDWR | O_CREAT, 0600)));
        if (fd.get() < 0) {
            PLOG(ERROR) << "Failed to create " << obbMountDir << "/" << sandboxId;
            return -errno;
        }
    } else {
        if (TEMP_FAILURE_RETRY(faccessat(obbMountDirFd, sandboxId.c_str(), F_OK, 0)) != -1) {
            if (TEMP_FAILURE_RETRY(unlinkat(obbMountDirFd, sandboxId.c_str(), 0)) == -1) {
                PLOG(ERROR) << "Failed to unlink " << obbMountDir << "/" << sandboxId;
                return -errno;
            }
        } else if (errno != ENOENT) {
            PLOG(ERROR) << "Failed to access " << obbMountDir << "/" << sandboxId;
            return -errno;
        }
    }
    return 0;
}

int VolumeManager::prepareSandboxes(userid_t userId, const std::vector<std::string>& packageNames,
                                    const std::vector<std::string>& visibleVolLabels) {
    if (visibleVolLabels.empty()) {
        return 0;
    }
    for (auto& volumeLabel : visibleVolLabels) {
        std::string volumeRoot(StringPrintf("/mnt/runtime/write/%s", volumeLabel.c_str()));
        bool isVolPrimaryEmulated = (volumeLabel == mPrimary->getLabel() && mPrimary->isEmulated());
        if (isVolPrimaryEmulated) {
            StringAppendF(&volumeRoot, "/%d", userId);
            if (CreateDir(volumeRoot, 0755) < 0) {
                return -errno;
            }
        }

        std::string sandboxRoot =
            prepareSubDirs(volumeRoot, "Android/sandbox/", 0700, AID_ROOT, AID_ROOT);
        if (sandboxRoot.empty()) {
            return -errno;
        }
    }

    if (prepareSandboxTargets(userId, visibleVolLabels) < 0) {
        return -errno;
    }

    if (mountPkgSpecificDirsForRunningProcs(userId, packageNames, visibleVolLabels, -1) < 0) {
        PLOG(ERROR) << "Failed to setup sandboxes for already running processes";
        return -errno;
    }
    return 0;
}

int VolumeManager::prepareSandboxTargets(userid_t userId,
                                         const std::vector<std::string>& visibleVolLabels) {
    std::string mntTargetRoot = StringPrintf("/mnt/user/%d", userId);
    if (fs_prepare_dir(mntTargetRoot.c_str(), 0751, AID_ROOT, AID_ROOT) != 0) {
        PLOG(ERROR) << "Failed to fs_prepare_dir " << mntTargetRoot;
        return -errno;
    }

    StringAppendF(&mntTargetRoot, "/package");
    if (fs_prepare_dir(mntTargetRoot.c_str(), 0755, AID_ROOT, AID_ROOT) != 0) {
        PLOG(ERROR) << "Failed to fs_prepare_dir " << mntTargetRoot;
        return -errno;
    }

    for (auto& volumeLabel : visibleVolLabels) {
        std::string sandboxTarget =
            StringPrintf("%s/%s", mntTargetRoot.c_str(), volumeLabel.c_str());
        if (fs_prepare_dir(sandboxTarget.c_str(), 0755, AID_ROOT, AID_ROOT) != 0) {
            PLOG(ERROR) << "Failed to fs_prepare_dir " << sandboxTarget;
            return -errno;
        }

        if (mPrimary && volumeLabel == mPrimary->getLabel() && mPrimary->isEmulated()) {
            StringAppendF(&sandboxTarget, "/%d", userId);
            if (fs_prepare_dir(sandboxTarget.c_str(), 0755, AID_ROOT, AID_ROOT) != 0) {
                PLOG(ERROR) << "Failed to fs_prepare_dir " << sandboxTarget;
                return -errno;
            }
        }
    }

    StringAppendF(&mntTargetRoot, "/self");
    if (fs_prepare_dir(mntTargetRoot.c_str(), 0755, AID_ROOT, AID_ROOT) != 0) {
        PLOG(ERROR) << "Failed to fs_prepare_dir " << mntTargetRoot;
        return -errno;
    }

    if (mPrimary) {
        std::string pkgPrimarySource(mPrimary->getPath());
        if (mPrimary->isEmulated()) {
            StringAppendF(&pkgPrimarySource, "/%d", userId);
        }
        StringAppendF(&mntTargetRoot, "/primary");
        if (Symlink(pkgPrimarySource, mntTargetRoot) < 0) {
            return -errno;
        }
    }
    return 0;
}

std::string VolumeManager::prepareSubDirs(const std::string& pathPrefix, const std::string& subDirs,
                                          mode_t mode, uid_t uid, gid_t gid) {
    std::string path(pathPrefix);
    std::vector<std::string> subDirList = android::base::Split(subDirs, "/");
    for (size_t i = 0; i < subDirList.size(); ++i) {
        std::string subDir = subDirList[i];
        if (subDir.empty()) {
            continue;
        }
        StringAppendF(&path, "/%s", subDir.c_str());
        if (CreateDir(path, mode) < 0) {
            return kEmptyString;
        }
    }
    return path;
}

bool VolumeManager::createPkgSpecificDirRoots(const std::string& volumeRoot) {
    std::string volumeAndroidRoot = StringPrintf("%s/Android", volumeRoot.c_str());
    if (CreateDir(volumeAndroidRoot, 0700) < 0) {
        return false;
    }
    std::array<std::string, 3> dirs = {"data", "media", "obb"};
    for (auto& dir : dirs) {
        std::string path = StringPrintf("%s/%s", volumeAndroidRoot.c_str(), dir.c_str());
        if (CreateDir(path, 0700) < 0) {
            return false;
        }
    }
    return true;
}

int VolumeManager::onUserAdded(userid_t userId, int userSerialNumber) {
    mAddedUsers[userId] = userSerialNumber;
    return 0;
}

int VolumeManager::onUserRemoved(userid_t userId) {
    mAddedUsers.erase(userId);
    return 0;
}

int VolumeManager::onUserStarted(userid_t userId, const std::vector<std::string>& packageNames,
                                 const std::vector<int>& appIds,
                                 const std::vector<std::string>& sandboxIds) {
    LOG(VERBOSE) << "onUserStarted: " << userId;
    // Note that sometimes the system will spin up processes from Zygote
    // before actually starting the user, so we're okay if Zygote
    // already created this directory.
    std::string path(StringPrintf("%s/%d", kPathUserMount, userId));
    fs_prepare_dir(path.c_str(), 0755, AID_ROOT, AID_ROOT);

    mStartedUsers.insert(userId);
    mUserPackages[userId] = packageNames;
    for (size_t i = 0; i < packageNames.size(); ++i) {
        mAppIds[packageNames[i]] = appIds[i];
        mSandboxIds[appIds[i]] = sandboxIds[i];
    }
    if (mPrimary) {
        linkPrimary(userId);
    }
    if (hasIsolatedStorage()) {
        std::vector<std::string> visibleVolLabels;
        for (auto& volId : mVisibleVolumeIds) {
            auto vol = findVolume(volId);
            userid_t mountUserId = vol->getMountUserId();
            if (mountUserId == userId || vol->isEmulated()) {
                visibleVolLabels.push_back(vol->getLabel());
            }
        }
        if (prepareSandboxes(userId, packageNames, visibleVolLabels) != 0) {
            return -errno;
        }
    }
    return 0;
}

int VolumeManager::onUserStopped(userid_t userId) {
    LOG(VERBOSE) << "onUserStopped: " << userId;
    mStartedUsers.erase(userId);

    if (hasIsolatedStorage()) {
        auto& userPackages = mUserPackages[userId];
        std::string userMntTargetRoot = StringPrintf("/mnt/user/%d", userId);
        std::string pkgPrimaryDir =
            StringPrintf("%s/package/self/primary", userMntTargetRoot.c_str());
        if (Unlink(pkgPrimaryDir) < 0) {
            return -errno;
        }
        mUserPackages.erase(userId);
        if (DeleteDirContentsAndDir(userMntTargetRoot) < 0) {
            PLOG(ERROR) << "DeleteDirContentsAndDir failed on " << userMntTargetRoot;
            return -errno;
        }
        LOG(VERBOSE) << "Success: DeleteDirContentsAndDir on " << userMntTargetRoot;
    }
    return 0;
}

int VolumeManager::addAppIds(const std::vector<std::string>& packageNames,
                             const std::vector<int32_t>& appIds) {
    for (size_t i = 0; i < packageNames.size(); ++i) {
        mAppIds[packageNames[i]] = appIds[i];
    }
    return 0;
}

int VolumeManager::addSandboxIds(const std::vector<int32_t>& appIds,
                                 const std::vector<std::string>& sandboxIds) {
    for (size_t i = 0; i < appIds.size(); ++i) {
        mSandboxIds[appIds[i]] = sandboxIds[i];
    }
    return 0;
}

int VolumeManager::prepareSandboxForApp(const std::string& packageName, appid_t appId,
                                        const std::string& sandboxId, userid_t userId) {
    if (!hasIsolatedStorage()) {
        return 0;
    } else if (mStartedUsers.find(userId) == mStartedUsers.end()) {
        // User not started, no need to do anything now. Required bind mounts for the package will
        // be created when the user starts.
        return 0;
    }

    auto& userPackages = mUserPackages[userId];
    if (std::find(userPackages.begin(), userPackages.end(), packageName) != userPackages.end()) {
        return 0;
    }

    LOG(VERBOSE) << "prepareSandboxForApp: " << packageName << ", appId=" << appId
                 << ", sandboxId=" << sandboxId << ", userId=" << userId;
    mUserPackages[userId].push_back(packageName);
    mAppIds[packageName] = appId;
    mSandboxIds[appId] = sandboxId;

    std::vector<std::string> visibleVolLabels;
    for (auto& volId : mVisibleVolumeIds) {
        auto vol = findVolume(volId);
        userid_t mountUserId = vol->getMountUserId();
        if (mountUserId == userId || vol->isEmulated()) {
            visibleVolLabels.push_back(vol->getLabel());
        }
    }
    return prepareSandboxes(userId, {packageName}, visibleVolLabels);
}

int VolumeManager::destroySandboxForApp(const std::string& packageName,
                                        const std::string& sandboxId, userid_t userId) {
    if (!hasIsolatedStorage()) {
        return 0;
    }
    LOG(VERBOSE) << "destroySandboxForApp: " << packageName << ", sandboxId=" << sandboxId
                 << ", userId=" << userId;
    auto& userPackages = mUserPackages[userId];
    userPackages.erase(std::remove(userPackages.begin(), userPackages.end(), packageName),
                       userPackages.end());
    // If the package is not uninstalled in any other users, remove appId and sandboxId
    // corresponding to it from the internal state.
    bool installedInAnyUser = false;
    for (auto& it : mUserPackages) {
        auto& packages = it.second;
        if (std::find(packages.begin(), packages.end(), packageName) != packages.end()) {
            installedInAnyUser = true;
            break;
        }
    }
    if (!installedInAnyUser) {
        const auto& entry = mAppIds.find(packageName);
        if (entry != mAppIds.end()) {
            mSandboxIds.erase(entry->second);
            mAppIds.erase(entry);
        }
    }

    std::vector<std::string> visibleVolLabels;
    for (auto& volId : mVisibleVolumeIds) {
        auto vol = findVolume(volId);
        userid_t mountUserId = vol->getMountUserId();
        if (mountUserId == userId || vol->isEmulated()) {
            if (destroySandboxForAppOnVol(packageName, sandboxId, userId, vol->getLabel()) < 0) {
                return -errno;
            }
        }
    }

    return 0;
}

int VolumeManager::destroySandboxForAppOnVol(const std::string& packageName,
                                             const std::string& sandboxId, userid_t userId,
                                             const std::string& volLabel) {
    LOG(VERBOSE) << "destroySandboxOnVol: " << packageName << ", userId=" << userId
                 << ", volLabel=" << volLabel;

    std::string sandboxDir = StringPrintf("/mnt/runtime/write/%s", volLabel.c_str());
    if (volLabel == mPrimary->getLabel() && mPrimary->isEmulated()) {
        StringAppendF(&sandboxDir, "/%d", userId);
    }
    StringAppendF(&sandboxDir, "/Android/sandbox/%s", sandboxId.c_str());

    if (DeleteDirContentsAndDir(sandboxDir) < 0) {
        PLOG(ERROR) << "DeleteDirContentsAndDir failed on " << sandboxDir;
        return -errno;
    }

    return 0;
}

int VolumeManager::onSecureKeyguardStateChanged(bool isShowing) {
    mSecureKeyguardShowing = isShowing;
    if (!mSecureKeyguardShowing) {
        // Now that secure keyguard has been dismissed, process
        // any pending disks
        for (const auto& disk : mPendingDisks) {
            disk->create();
            mDisks.push_back(disk);
        }
        mPendingDisks.clear();
    }
    return 0;
}

int VolumeManager::onVolumeMounted(android::vold::VolumeBase* vol) {
    if (!hasIsolatedStorage()) {
        return 0;
    }

    if ((vol->getMountFlags() & android::vold::VoldNativeService::MOUNT_FLAG_VISIBLE) == 0) {
        return 0;
    }

    mVisibleVolumeIds.insert(vol->getId());
    userid_t mountUserId = vol->getMountUserId();
    if ((vol->getMountFlags() & android::vold::VoldNativeService::MOUNT_FLAG_PRIMARY) != 0) {
        // We don't want to create another shared_ptr here because then we will end up with
        // two shared_ptrs owning the underlying pointer without sharing it.
        mPrimary = findVolume(vol->getId());
        for (userid_t userId : mStartedUsers) {
            if (linkPrimary(userId) != 0) {
                return -errno;
            }
        }
    }
    if (vol->isEmulated()) {
        for (userid_t userId : mStartedUsers) {
            if (prepareSandboxes(userId, mUserPackages[userId], {vol->getLabel()}) != 0) {
                return -errno;
            }
        }
    } else if (mStartedUsers.find(mountUserId) != mStartedUsers.end()) {
        if (prepareSandboxes(mountUserId, mUserPackages[mountUserId], {vol->getLabel()}) != 0) {
            return -errno;
        }
    }
    return 0;
}

int VolumeManager::onVolumeUnmounted(android::vold::VolumeBase* vol) {
    if (!hasIsolatedStorage()) {
        return 0;
    }

    if (mVisibleVolumeIds.erase(vol->getId()) == 0) {
        return 0;
    }

    if ((vol->getMountFlags() & android::vold::VoldNativeService::MOUNT_FLAG_PRIMARY) != 0) {
        mPrimary = nullptr;
    }

    LOG(VERBOSE) << "visibleVolumeUnmounted: " << vol;
    userid_t mountUserId = vol->getMountUserId();
    if (vol->isEmulated()) {
        for (userid_t userId : mStartedUsers) {
            if (destroySandboxesForVol(vol, userId) != 0) {
                return -errno;
            }
        }
    } else if (mStartedUsers.find(mountUserId) != mStartedUsers.end()) {
        if (destroySandboxesForVol(vol, mountUserId) != 0) {
            return -errno;
        }
    }
    return 0;
}

int VolumeManager::destroySandboxesForVol(android::vold::VolumeBase* vol, userid_t userId) {
    LOG(VERBOSE) << "destroysandboxesForVol: " << vol << " for user=" << userId;
    std::string volSandboxRoot =
        StringPrintf("/mnt/user/%d/package/%s", userId, vol->getLabel().c_str());
    if (android::vold::DeleteDirContentsAndDir(volSandboxRoot) < 0) {
        PLOG(ERROR) << "DeleteDirContentsAndDir failed on " << volSandboxRoot;
        return -errno;
    }
    LOG(VERBOSE) << "Success: DeleteDirContentsAndDir on " << volSandboxRoot;
    return 0;
}

int VolumeManager::setPrimary(const std::shared_ptr<android::vold::VolumeBase>& vol) {
    if (hasIsolatedStorage()) {
        return 0;
    }
    mPrimary = vol;
    for (userid_t userId : mStartedUsers) {
        linkPrimary(userId);
    }
    return 0;
}

int VolumeManager::remountUid(uid_t uid, int32_t mountMode) {
    if (!hasIsolatedStorage()) {
        return remountUidLegacy(uid, mountMode);
    }

    appid_t appId = multiuser_get_app_id(uid);
    userid_t userId = multiuser_get_user_id(uid);
    std::vector<std::string> visibleVolLabels;
    for (auto& volId : mVisibleVolumeIds) {
        auto vol = findVolume(volId);
        userid_t mountUserId = vol->getMountUserId();
        if (mountUserId == userId || vol->isEmulated()) {
            visibleVolLabels.push_back(vol->getLabel());
        }
    }

    // Finding one package with appId is enough
    std::vector<std::string> packageNames;
    for (auto it = mAppIds.begin(); it != mAppIds.end(); ++it) {
        if (it->second == appId) {
            packageNames.push_back(it->first);
            break;
        }
    }
    if (packageNames.empty()) {
        PLOG(ERROR) << "Failed to find packageName for " << uid;
        return -1;
    }
    return mountPkgSpecificDirsForRunningProcs(userId, packageNames, visibleVolLabels, mountMode);
}

int VolumeManager::remountUidLegacy(uid_t uid, int32_t mountMode) {
    std::string mode;
    switch (mountMode) {
        case VoldNativeService::REMOUNT_MODE_NONE:
            mode = "none";
            break;
        case VoldNativeService::REMOUNT_MODE_DEFAULT:
            mode = "default";
            break;
        case VoldNativeService::REMOUNT_MODE_READ:
            mode = "read";
            break;
        case VoldNativeService::REMOUNT_MODE_WRITE:
            mode = "write";
            break;
        default:
            PLOG(ERROR) << "Unknown mode " << std::to_string(mountMode);
            return -1;
    }
    LOG(DEBUG) << "Remounting " << uid << " as mode " << mode;

    DIR* dir;
    struct dirent* de;
    std::string rootName;
    std::string pidName;
    int pidFd;
    int nsFd;
    struct stat sb;
    pid_t child;

    static bool apexUpdatable = android::sysprop::ApexProperties::updatable().value_or(false);

    if (!(dir = opendir("/proc"))) {
        PLOG(ERROR) << "Failed to opendir";
        return -1;
    }

    // Figure out root namespace to compare against below
    if (!android::vold::Readlinkat(dirfd(dir), "1/ns/mnt", &rootName)) {
        PLOG(ERROR) << "Failed to read root namespace";
        closedir(dir);
        return -1;
    }

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
            PLOG(WARNING) << "Failed to stat " << de->d_name;
            goto next;
        }
        if (sb.st_uid != uid) {
            goto next;
        }

        // Matches so far, but refuse to touch if in root namespace
        LOG(DEBUG) << "Found matching PID " << de->d_name;
        if (!android::vold::Readlinkat(pidFd, "ns/mnt", &pidName)) {
            PLOG(WARNING) << "Failed to read namespace for " << de->d_name;
            goto next;
        }
        if (rootName == pidName) {
            LOG(WARNING) << "Skipping due to root namespace";
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
                PLOG(WARNING) << "Failed to read exe name for " << de->d_name;
                goto next;
            }
            if (!StartsWith(exeName, "/system/bin/app_process") && sb.st_uid < AID_APP_START) {
                LOG(WARNING) << "Skipping due to native system process";
                goto next;
            }
        }

        // We purposefully leave the namespace open across the fork
        nsFd = openat(pidFd, "ns/mnt", O_RDONLY);  // not O_CLOEXEC
        if (nsFd < 0) {
            PLOG(WARNING) << "Failed to open namespace for " << de->d_name;
            goto next;
        }

        if (!(child = fork())) {
            if (setns(nsFd, CLONE_NEWNS) != 0) {
                PLOG(ERROR) << "Failed to setns for " << de->d_name;
                _exit(1);
            }

            android::vold::UnmountTree("/storage/");

            std::string storageSource;
            if (mode == "default") {
                storageSource = "/mnt/runtime/default";
            } else if (mode == "read") {
                storageSource = "/mnt/runtime/read";
            } else if (mode == "write") {
                storageSource = "/mnt/runtime/write";
            } else {
                // Sane default of no storage visible
                _exit(0);
            }
            if (TEMP_FAILURE_RETRY(
                    mount(storageSource.c_str(), "/storage", NULL, MS_BIND | MS_REC, NULL)) == -1) {
                PLOG(ERROR) << "Failed to mount " << storageSource << " for " << de->d_name;
                _exit(1);
            }
            if (TEMP_FAILURE_RETRY(mount(NULL, "/storage", NULL, MS_REC | MS_SLAVE, NULL)) == -1) {
                PLOG(ERROR) << "Failed to set MS_SLAVE to /storage for " << de->d_name;
                _exit(1);
            }

            // Mount user-specific symlink helper into place
            userid_t user_id = multiuser_get_user_id(uid);
            std::string userSource(StringPrintf("/mnt/user/%d", user_id));
            if (TEMP_FAILURE_RETRY(
                    mount(userSource.c_str(), "/storage/self", NULL, MS_BIND, NULL)) == -1) {
                PLOG(ERROR) << "Failed to mount " << userSource << " for " << de->d_name;
                _exit(1);
            }

            _exit(0);
        }

        if (child == -1) {
            PLOG(ERROR) << "Failed to fork";
            goto next;
        } else {
            TEMP_FAILURE_RETRY(waitpid(child, nullptr, 0));
        }

    next:
        close(nsFd);
        close(pidFd);
    }
    closedir(dir);
    return 0;
}

int VolumeManager::reset() {
    // Tear down all existing disks/volumes and start from a blank slate so
    // newly connected framework hears all events.
    if (mInternalEmulated != nullptr) {
        mInternalEmulated->destroy();
        mInternalEmulated->create();
    }
    for (const auto& disk : mDisks) {
        disk->destroy();
        disk->create();
    }
    updateVirtualDisk();
    mAddedUsers.clear();

    mUserPackages.clear();
    mAppIds.clear();
    mSandboxIds.clear();
    mVisibleVolumeIds.clear();

    for (userid_t userId : mStartedUsers) {
        DeleteDirContents(StringPrintf("/mnt/user/%d/package", userId));
    }
    mStartedUsers.clear();
    return 0;
}

// Can be called twice (sequentially) during shutdown. should be safe for that.
int VolumeManager::shutdown() {
    if (mInternalEmulated == nullptr) {
        return 0;  // already shutdown
    }
    android::vold::sSleepOnUnmount = false;
    mInternalEmulated->destroy();
    mInternalEmulated = nullptr;
    for (const auto& disk : mDisks) {
        disk->destroy();
    }
    mStubVolumes.clear();
    mDisks.clear();
    mPendingDisks.clear();
    android::vold::sSleepOnUnmount = true;
    return 0;
}

int VolumeManager::unmountAll() {
    std::lock_guard<std::mutex> lock(mLock);
    ATRACE_NAME("VolumeManager::unmountAll()");

    // First, try gracefully unmounting all known devices
    if (mInternalEmulated != nullptr) {
        mInternalEmulated->unmount();
    }
    for (const auto& stub : mStubVolumes) {
        stub->unmount();
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
             !StartsWith(test, "/mnt/vendor") && !StartsWith(test, "/mnt/product")) ||
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

int VolumeManager::mkdirs(const std::string& path) {
    // Only offer to create directories for paths managed by vold
    if (StartsWith(path, "/storage/")) {
        // fs_mkdirs() does symlink checking and relative path enforcement
        return fs_mkdirs(path.c_str(), 0700);
    } else {
        LOG(ERROR) << "Failed to find mounted volume for " << path;
        return -EINVAL;
    }
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
                                    const std::string& fsLabel, std::string* outVolId) {
    int id = mNextStubVolumeId++;
    auto vol = std::shared_ptr<android::vold::VolumeBase>(
        new android::vold::StubVolume(id, sourcePath, mountPath, fsType, fsUuid, fsLabel));
    vol->create();

    mStubVolumes.push_back(vol);
    *outVolId = vol->getId();
    return android::OK;
}

int VolumeManager::destroyStubVolume(const std::string& volId) {
    auto i = mStubVolumes.begin();
    while (i != mStubVolumes.end()) {
        if ((*i)->getId() == volId) {
            (*i)->destroy();
            i = mStubVolumes.erase(i);
        } else {
            ++i;
        }
    }
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
