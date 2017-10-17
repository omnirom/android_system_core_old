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

#include "IdleMaint.h"
#include "Utils.h"
#include "VolumeManager.h"

#include <android-base/stringprintf.h>
#include <android-base/logging.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <hardware_legacy/power.h>

#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using android::base::StringPrintf;

namespace android {
namespace vold {

static const char* kWakeLock = "IdleMaint";

static void addFromVolumeManager(std::list<std::string>* paths) {
    VolumeManager* vm = VolumeManager::Instance();
    std::list<std::string> privateIds;
    vm->listVolumes(VolumeBase::Type::kPrivate, privateIds);
    for (const auto& id : privateIds) {
        auto vol = vm->findVolume(id);
        if (vol != nullptr && vol->getState() == VolumeBase::State::kMounted) {
            paths->push_back(vol->getPath());
        }
    }
}

static void addFromFstab(std::list<std::string>* paths) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    struct fstab_rec *prev_rec = NULL;

    for (int i = 0; i < fstab->num_entries; i++) {
        auto fs_type = std::string(fstab->recs[i].fs_type);
        /* Skip raw partitions */
        if (fs_type == "emmc" || fs_type == "mtd") {
            continue;
        }
        /* Skip read-only filesystems */
        if (fstab->recs[i].flags & MS_RDONLY) {
            continue;
        }
        if (fs_mgr_is_voldmanaged(&fstab->recs[i])) {
            continue; /* Should we trim fat32 filesystems? */
        }
        if (fs_mgr_is_notrim(&fstab->recs[i])) {
            continue;
        }

        /* Skip the multi-type partitions, which are required to be following each other.
         * See fs_mgr.c's mount_with_alternatives().
         */
        if (prev_rec && !strcmp(prev_rec->mount_point, fstab->recs[i].mount_point)) {
            continue;
        }

        paths->push_back(fstab->recs[i].mount_point);
        prev_rec = &fstab->recs[i];
    }
}

void Trim(const android::sp<android::os::IVoldTaskListener>& listener) {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    // Collect both fstab and vold volumes
    std::list<std::string> paths;
    addFromFstab(&paths);
    addFromVolumeManager(&paths);

    for (const auto& path : paths) {
        LOG(DEBUG) << "Starting trim of " << path;

        android::os::PersistableBundle extras;
        extras.putString(String16("path"), String16(path.c_str()));

        int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            PLOG(WARNING) << "Failed to open " << path;
            if (listener) {
                listener->onStatus(-1, extras);
            }
            continue;
        }

        struct fstrim_range range;
        memset(&range, 0, sizeof(range));
        range.len = ULLONG_MAX;

        nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);
        if (ioctl(fd, FITRIM, &range)) {
            PLOG(WARNING) << "Trim failed on " << path;
            if (listener) {
                listener->onStatus(-1, extras);
            }
        } else {
            nsecs_t time = systemTime(SYSTEM_TIME_BOOTTIME) - start;
            LOG(INFO) << "Trimmed " << range.len << " bytes on " << path
                    << " in " << nanoseconds_to_milliseconds(time) << "ms";
            extras.putLong(String16("bytes"), range.len);
            extras.putLong(String16("time"), time);
            if (listener) {
                listener->onStatus(0, extras);
            }
        }
        close(fd);
    }

    if (listener) {
        android::os::PersistableBundle extras;
        listener->onFinished(0, extras);
    }

    release_wake_lock(kWakeLock);
}

}  // namespace vold
}  // namespace android
