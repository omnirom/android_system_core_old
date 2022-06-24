/*
 * Copyright (C) 2017 The Android Open Source Project
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

package android.os;

import android.os.incremental.IncrementalFileSystemControlParcel;
import android.os.IVoldListener;
import android.os.IVoldMountCallback;
import android.os.IVoldTaskListener;

/** {@hide} */
interface IVold {
    void setListener(IVoldListener listener);

    void abortFuse();
    void monitor();
    void reset();
    void shutdown();

    void onUserAdded(int userId, int userSerial);
    void onUserRemoved(int userId);
    void onUserStarted(int userId);
    void onUserStopped(int userId);

    void addAppIds(in @utf8InCpp String[] packageNames, in int[] appIds);
    void addSandboxIds(in int[] appIds, in @utf8InCpp String[] sandboxIds);

    void onSecureKeyguardStateChanged(boolean isShowing);

    void partition(@utf8InCpp String diskId, int partitionType, int ratio);
    void forgetPartition(@utf8InCpp String partGuid, @utf8InCpp String fsUuid);

    void mount(@utf8InCpp String volId, int mountFlags, int mountUserId,
         @nullable IVoldMountCallback callback);
    void unmount(@utf8InCpp String volId);
    void format(@utf8InCpp String volId, @utf8InCpp String fsType);
    void benchmark(@utf8InCpp String volId, IVoldTaskListener listener);

    void moveStorage(@utf8InCpp String fromVolId, @utf8InCpp String toVolId,
                     IVoldTaskListener listener);

    void remountUid(int uid, int remountMode);
    void remountAppStorageDirs(int uid, int pid, in @utf8InCpp String[] packageNames);
    void unmountAppStorageDirs(int uid, int pid, in @utf8InCpp String[] packageNames);

    void setupAppDir(@utf8InCpp String path, int appUid);
    void fixupAppDir(@utf8InCpp String path, int appUid);
    void ensureAppDirsCreated(in @utf8InCpp String[] paths, int appUid);

    @utf8InCpp String createObb(@utf8InCpp String sourcePath, int ownerGid);
    void destroyObb(@utf8InCpp String volId);

    void fstrim(int fstrimFlags, IVoldTaskListener listener);
    void runIdleMaint(boolean needGC, IVoldTaskListener listener);
    void abortIdleMaint(IVoldTaskListener listener);
    int getStorageLifeTime();
    void setGCUrgentPace(int neededSegments, int minSegmentThreshold,
                         float dirtyReclaimRate, float reclaimWeight,
                         int gcPeriod, int minGCSleepTime,
                         int targetDirtyRatio);
    void refreshLatestWrite();
    int getWriteAmount();

    FileDescriptor mountAppFuse(int uid, int mountId);
    void unmountAppFuse(int uid, int mountId);

    void fbeEnable();

    void initUser0();
    void mountFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint);
    void encryptFstab(@utf8InCpp String blkDevice, @utf8InCpp String mountPoint, boolean shouldFormat, @utf8InCpp String fsType);

    void setStorageBindingSeed(in byte[] seed);

    void createUserKey(int userId, int userSerial, boolean ephemeral);
    void destroyUserKey(int userId);

    void addUserKeyAuth(int userId, int userSerial, @utf8InCpp String secret);
    void clearUserKeyAuth(int userId, int userSerial, @utf8InCpp String secret);
    void fixateNewestUserKeyAuth(int userId);

    int[] getUnlockedUsers();
    void unlockUserKey(int userId, int userSerial, @utf8InCpp String secret);
    void lockUserKey(int userId);

    void prepareUserStorage(@nullable @utf8InCpp String uuid, int userId, int userSerial,
                            int storageFlags);
    void destroyUserStorage(@nullable @utf8InCpp String uuid, int userId, int storageFlags);

    void prepareSandboxForApp(in @utf8InCpp String packageName, int appId,
                              in @utf8InCpp String sandboxId, int userId);
    void destroySandboxForApp(in @utf8InCpp String packageName,
                              in @utf8InCpp String sandboxId, int userId);

    void startCheckpoint(int retry);
    boolean needsCheckpoint();
    boolean needsRollback();
    boolean isCheckpointing();
    void abortChanges(in @utf8InCpp String device, boolean retry);
    void commitChanges();
    void prepareCheckpoint();
    void restoreCheckpoint(@utf8InCpp String device);
    void restoreCheckpointPart(@utf8InCpp String device, int count);
    void markBootAttempt();
    boolean supportsCheckpoint();
    boolean supportsBlockCheckpoint();
    boolean supportsFileCheckpoint();
    void resetCheckpoint();

    void earlyBootEnded();
    @utf8InCpp String createStubVolume(@utf8InCpp String sourcePath,
            @utf8InCpp String mountPath, @utf8InCpp String fsType,
            @utf8InCpp String fsUuid, @utf8InCpp String fsLabel, int flags);
    void destroyStubVolume(@utf8InCpp String volId);

    FileDescriptor openAppFuseFile(int uid, int mountId, int fileId, int flags);

    boolean incFsEnabled();
    IncrementalFileSystemControlParcel mountIncFs(@utf8InCpp String backingPath, @utf8InCpp String targetDir, int flags, @utf8InCpp String sysfsName);
    void unmountIncFs(@utf8InCpp String dir);
    void setIncFsMountOptions(in IncrementalFileSystemControlParcel control, boolean enableReadLogs, boolean enableReadTimeouts, @utf8InCpp String sysfsName);
    void bindMount(@utf8InCpp String sourceDir, @utf8InCpp String targetDir);

    void destroyDsuMetadataKey(@utf8InCpp String dsuSlot);

    const int FSTRIM_FLAG_DEEP_TRIM = 1;

    const int MOUNT_FLAG_PRIMARY = 1;
    const int MOUNT_FLAG_VISIBLE_FOR_READ = 2;
    const int MOUNT_FLAG_VISIBLE_FOR_WRITE = 4;

    const int PARTITION_TYPE_PUBLIC = 0;
    const int PARTITION_TYPE_PRIVATE = 1;
    const int PARTITION_TYPE_MIXED = 2;

    const int STORAGE_FLAG_DE = 1;
    const int STORAGE_FLAG_CE = 2;

    const int REMOUNT_MODE_NONE = 0;
    const int REMOUNT_MODE_DEFAULT = 1;
    const int REMOUNT_MODE_INSTALLER = 2;
    const int REMOUNT_MODE_PASS_THROUGH = 3;
    const int REMOUNT_MODE_ANDROID_WRITABLE = 4;

    const int VOLUME_STATE_UNMOUNTED = 0;
    const int VOLUME_STATE_CHECKING = 1;
    const int VOLUME_STATE_MOUNTED = 2;
    const int VOLUME_STATE_MOUNTED_READ_ONLY = 3;
    const int VOLUME_STATE_FORMATTING = 4;
    const int VOLUME_STATE_EJECTING = 5;
    const int VOLUME_STATE_UNMOUNTABLE = 6;
    const int VOLUME_STATE_REMOVED = 7;
    const int VOLUME_STATE_BAD_REMOVAL = 8;

    const int VOLUME_TYPE_PUBLIC = 0;
    const int VOLUME_TYPE_PRIVATE = 1;
    const int VOLUME_TYPE_EMULATED = 2;
    const int VOLUME_TYPE_ASEC = 3;
    const int VOLUME_TYPE_OBB = 4;
    const int VOLUME_TYPE_STUB = 5;
}
