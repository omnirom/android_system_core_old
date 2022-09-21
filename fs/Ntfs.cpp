/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <selinux/selinux.h>

#include <logwrap/logwrap.h>

#include "Ntfs.h"
#include "Utils.h"
#include "VoldUtil.h"

using android::base::StringPrintf;

namespace android {
namespace vold {
namespace ntfs {

static const char* kFsckPath = "/system/bin/ntfsfix";
static const char* kMkfsPath = "/system/bin/mkntfs";

static const char* fsName = "ntfs3";

bool IsSupported() {
    return access(kFsckPath, X_OK) == 0 && access(kMkfsPath, X_OK) == 0 &&
           IsFilesystemSupported(fsName);
}

status_t Check(const std::string& source) {
    std::vector<std::string> cmd;
    cmd.push_back(kFsckPath);

    // ntfsfix sets the dirty bit by default, which prevents mounting the drive.
    // -d tells it to instead reset the dirty bit. Technically, this could be dangerous,
    // but since ntfsfix should report any errors with the drive and separately return
    // a failed check, this should be relatively safe.
    cmd.push_back("-d");

    cmd.push_back(source);

    int rc = ForkExecvpTimeout(cmd, kUntrustedFsckSleepTime, sFsckUntrustedContext);
    if (rc == 0) {
        LOG(INFO) << "Check NTFS OK";
        return 0;
    } else {
        LOG(ERROR) << "Check NTFS failed (code " << rc << ")";
        errno = EIO;
        return -1;
    }
}

status_t Mount(const std::string& source, const std::string& target, bool ro, bool remount,
               bool executable, int ownerUid, int ownerGid, int permMask) {
    unsigned long flags = MS_NODEV | MS_NOSUID | MS_DIRSYNC | MS_NOATIME;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    // Android mount does not support "utf8" as an option. We use the deprecated iocharset instead.
    auto mountData = android::base::StringPrintf("uid=%d,gid=%d,fmask=%o,dmask=%o,iocharset=%s",
                                                 ownerUid, ownerGid, permMask, permMask, "utf8");

    int rc = mount(source.c_str(), target.c_str(), fsName, flags, mountData.c_str());

    if (rc && errno == EROFS) {
        LOG(ERROR) << source << " appears to be a read only filesystem - retrying mount RO";
        flags |= MS_RDONLY;
        rc = mount(source.c_str(), target.c_str(), fsName, flags, mountData.c_str());
    }

    return rc;
}

status_t Format(const std::string& source, unsigned int numSectors) {
    std::vector<std::string> cmd;
    cmd.push_back(kMkfsPath);
    cmd.push_back(source);

    if (numSectors) {
        cmd.push_back(StringPrintf("%u", numSectors));
    }

    int rc = ForkExecvp(cmd);
    if (rc == 0) {
        LOG(INFO) << "Filesystem formatted OK";
        return 0;
    } else {
        LOG(ERROR) << "Format failed with error code: " << rc;
        errno = EIO;
        return -1;
    }
    return 0;
}

}  // namespace ntfs
}  // namespace vold
}  // namespace android