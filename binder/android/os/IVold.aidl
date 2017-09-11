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

/** {@hide} */
interface IVold {
    void reset();
    void shutdown();
    void mountAll();

    void onUserAdded(int userId, int userSerial);
    void onUserRemoved(int userId);
    void onUserStarted(int userId);
    void onUserStopped(int userId);

    void partition(@utf8InCpp String diskId, int partitionType, int ratio);
    void forgetPartition(@utf8InCpp String partGuid);

    void mount(@utf8InCpp String volId, int mountFlags, int mountUserId);
    void unmount(@utf8InCpp String volId);
    void format(@utf8InCpp String volId, @utf8InCpp String fsType);
    long benchmark(@utf8InCpp String volId);

    void moveStorage(@utf8InCpp String fromVolId, @utf8InCpp String toVolId);

    void remountUid(int uid, int remountMode);

    void mkdirs(@utf8InCpp String path);

    @utf8InCpp String createObb(@utf8InCpp String sourcePath,
            @utf8InCpp String sourceKey, int ownerGid);
    void destroyObb(@utf8InCpp String volId);

    void fstrim(int fstrimFlags);

    FileDescriptor mountAppFuse(int uid, int pid, int mountId);
    void unmountAppFuse(int uid, int pid, int mountId);

    const int FSTRIM_FLAG_DEEP_TRIM = 1;
    const int FSTRIM_FLAG_BENCHMARK_AFTER = 2;

    const int MOUNT_FLAG_PRIMARY = 1;
    const int MOUNT_FLAG_VISIBLE = 2;

    const int PARTITION_TYPE_PUBLIC = 0;
    const int PARTITION_TYPE_PRIVATE = 1;
    const int PARTITION_TYPE_MIXED = 2;

    const int REMOUNT_MODE_NONE = 0;
    const int REMOUNT_MODE_DEFAULT = 1;
    const int REMOUNT_MODE_READ = 2;
    const int REMOUNT_MODE_WRITE = 3;

    const int STATE_UNMOUNTED = 0;
    const int STATE_CHECKING = 1;
    const int STATE_MOUNTED = 2;
    const int STATE_MOUNTED_READ_ONLY = 3;
    const int STATE_FORMATTING = 4;
    const int STATE_EJECTING = 5;
    const int STATE_UNMOUNTABLE = 6;
    const int STATE_REMOVED = 7;
    const int STATE_BAD_REMOVAL = 8;

    const int TYPE_PUBLIC = 0;
    const int TYPE_PRIVATE = 1;
    const int TYPE_EMULATED = 2;
    const int TYPE_ASEC = 3;
    const int TYPE_OBB = 4;
}
