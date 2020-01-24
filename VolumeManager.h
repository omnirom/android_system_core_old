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

#ifndef ANDROID_VOLD_VOLUME_MANAGER_H
#define ANDROID_VOLD_VOLUME_MANAGER_H

#include <fnmatch.h>
#include <pthread.h>
#include <stdlib.h>

#include <list>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <android-base/unique_fd.h>
#include <cutils/multiuser.h>
#include <sysutils/NetlinkEvent.h>
#include <utils/List.h>
#include <utils/Timers.h>

#include "android/os/IVoldListener.h"

#include "model/Disk.h"
#include "model/VolumeBase.h"

class VolumeManager {
  private:
    static VolumeManager* sInstance;

    bool mDebug;

  public:
    virtual ~VolumeManager();

    // TODO: pipe all requests through VM to avoid exposing this lock
    std::mutex& getLock() { return mLock; }
    std::mutex& getCryptLock() { return mCryptLock; }

    void setListener(android::sp<android::os::IVoldListener> listener) { mListener = listener; }
    android::sp<android::os::IVoldListener> getListener() const { return mListener; }

    int start();
    int stop();

    void handleBlockEvent(NetlinkEvent* evt);

    class DiskSource {
      public:
        DiskSource(const std::string& sysPattern, const std::string& nickname, int flags)
            : mSysPattern(sysPattern), mNickname(nickname), mFlags(flags) {}

        bool matches(const std::string& sysPath) {
            return !fnmatch(mSysPattern.c_str(), sysPath.c_str(), 0);
        }

        const std::string& getNickname() const { return mNickname; }
        int getFlags() const { return mFlags; }

      private:
        std::string mSysPattern;
        std::string mNickname;
        int mFlags;
    };

    void addDiskSource(const std::shared_ptr<DiskSource>& diskSource);

    std::shared_ptr<android::vold::Disk> findDisk(const std::string& id);
    std::shared_ptr<android::vold::VolumeBase> findVolume(const std::string& id);

    template <typename Fn>
    std::shared_ptr<android::vold::VolumeBase> findVolumeWithFilter(Fn fn) {
        for (const auto& vol : mInternalEmulatedVolumes) {
            if (fn(*vol)) {
                return vol;
            }
        }
        for (const auto& disk : mDisks) {
            for (const auto& vol : disk->getVolumes()) {
                if (fn(*vol)) {
                    return vol;
                }
            }
        }

        return nullptr;
    }

    void listVolumes(android::vold::VolumeBase::Type type, std::list<std::string>& list) const;

    const std::set<userid_t>& getStartedUsers() const { return mStartedUsers; }

    int forgetPartition(const std::string& partGuid, const std::string& fsUuid);

    int onUserAdded(userid_t userId, int userSerialNumber);
    int onUserRemoved(userid_t userId);
    int onUserStarted(userid_t userId);
    int onUserStopped(userid_t userId);

    void createPendingDisksIfNeeded();
    int onSecureKeyguardStateChanged(bool isShowing);

    int setPrimary(const std::shared_ptr<android::vold::VolumeBase>& vol);

    int remountUid(uid_t uid, int32_t remountMode);

    /* Reset all internal state, typically during framework boot */
    int reset();
    /* Prepare for device shutdown, safely unmounting all devices */
    int shutdown();
    /* Unmount all volumes, usually for encryption */
    int unmountAll();

    int updateVirtualDisk();
    int setDebug(bool enable);

    static VolumeManager* Instance();

    /*
     * Creates a directory 'path' for an application, automatically creating
     * directories along the given path if they don't exist yet. 'appDirRoot'
     * is the "root" directory for app-specific directories of this kind;
     * 'path' must always start with 'appDirRoot'.
     *
     * Example:
     *   path = /storage/emulated/0/Android/data/com.foo/files/
     *   appDirRoot = /storage/emulated/0/Android/data/
     *
     * This function will set the UID of all app-specific directories below
     * 'appDirRoot' to the 'appUid' argument. In the given example, the UID
     * of /storage/emulated/0/Android/data/com.foo and
     * /storage/emulated/0/Android/data/com.foo/files would be set to 'appUid'.
     *
     * The UID of the parent directories will be set according to the
     * requirements of the underlying filesystem and are of no concern to the
     * caller.
     *
     * Validates that given paths are absolute and that they contain no relative
     * "." or ".." paths or symlinks.  Last path segment is treated as filename
     * and ignored, unless the path ends with "/".  Also ensures that path
     * belongs to a volume managed by vold.
     */
    int setupAppDir(const std::string& path, const std::string& appDirRoot, int32_t appUid);

    int createObb(const std::string& path, const std::string& key, int32_t ownerGid,
                  std::string* outVolId);
    int destroyObb(const std::string& volId);

    int createStubVolume(const std::string& sourcePath, const std::string& mountPath,
                         const std::string& fsType, const std::string& fsUuid,
                         const std::string& fsLabel, std::string* outVolId);
    int destroyStubVolume(const std::string& volId);

    int mountAppFuse(uid_t uid, int mountId, android::base::unique_fd* device_fd);
    int unmountAppFuse(uid_t uid, int mountId);
    int openAppFuseFile(uid_t uid, int mountId, int fileId, int flags);

  private:
    VolumeManager();
    void readInitialState();

    int linkPrimary(userid_t userId);

    void createEmulatedVolumesForUser(userid_t userId);
    void destroyEmulatedVolumesForUser(userid_t userId);

    void handleDiskAdded(const std::shared_ptr<android::vold::Disk>& disk);
    void handleDiskChanged(dev_t device);
    void handleDiskRemoved(dev_t device);

    std::mutex mLock;
    std::mutex mCryptLock;

    android::sp<android::os::IVoldListener> mListener;

    std::list<std::shared_ptr<DiskSource>> mDiskSources;
    std::list<std::shared_ptr<android::vold::Disk>> mDisks;
    std::list<std::shared_ptr<android::vold::Disk>> mPendingDisks;
    std::list<std::shared_ptr<android::vold::VolumeBase>> mObbVolumes;
    std::list<std::shared_ptr<android::vold::VolumeBase>> mStubVolumes;
    std::list<std::shared_ptr<android::vold::VolumeBase>> mInternalEmulatedVolumes;

    std::unordered_map<userid_t, int> mAddedUsers;
    // This needs to be a regular set because we care about the ordering here;
    // user 0 should always go first, because it is responsible for sdcardfs.
    std::set<userid_t> mStartedUsers;

    std::string mVirtualDiskPath;
    std::shared_ptr<android::vold::Disk> mVirtualDisk;
    std::shared_ptr<android::vold::VolumeBase> mPrimary;

    int mNextObbId;
    int mNextStubVolumeId;
    bool mSecureKeyguardShowing;
};

#endif
