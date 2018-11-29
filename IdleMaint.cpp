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
#include "FileDeviceUtils.h"
#include "Utils.h"
#include "VolumeManager.h"
#include "model/PrivateVolume.h"

#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
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

using android::base::Basename;
using android::base::ReadFileToString;
using android::base::Realpath;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::WriteStringToFile;

namespace android {
namespace vold {

enum class PathTypes {
    kMountPoint = 1,
    kBlkDevice,
};

enum class IdleMaintStats {
    kStopped = 1,
    kRunning,
    kAbort,
};

static const char* kWakeLock = "IdleMaint";
static const int DIRTY_SEGMENTS_THRESHOLD = 100;
/*
 * Timing policy:
 *  1. F2FS_GC = 7 mins
 *  2. Trim = 1 min
 *  3. Dev GC = 2 mins
 */
static const int GC_TIMEOUT_SEC = 420;
static const int DEVGC_TIMEOUT_SEC = 120;

static IdleMaintStats idle_maint_stat(IdleMaintStats::kStopped);
static std::condition_variable cv_abort, cv_stop;
static std::mutex cv_m;

static void addFromVolumeManager(std::list<std::string>* paths,
                                 PathTypes path_type) {
    VolumeManager* vm = VolumeManager::Instance();
    std::list<std::string> privateIds;
    vm->listVolumes(VolumeBase::Type::kPrivate, privateIds);
    for (const auto& id : privateIds) {
        PrivateVolume* vol = static_cast<PrivateVolume*>(vm->findVolume(id).get());
        if (vol != nullptr && vol->getState() == VolumeBase::State::kMounted) {
            if (path_type == PathTypes::kMountPoint) {
                paths->push_back(vol->getPath());
            } else if (path_type == PathTypes::kBlkDevice) {
                std::string gc_path;
                const std::string& fs_type = vol->getFsType();
                if (fs_type == "f2fs" && (Realpath(vol->getRawDmDevPath(), &gc_path) ||
                                          Realpath(vol->getRawDevPath(), &gc_path))) {
                    paths->push_back(std::string("/sys/fs/") + fs_type +
                                     "/" + Basename(gc_path));
                }
            }

        }
    }
}

static void addFromFstab(std::list<std::string>* paths, PathTypes path_type) {
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

        if (path_type == PathTypes::kMountPoint) {
            paths->push_back(fstab->recs[i].mount_point);
        } else if (path_type == PathTypes::kBlkDevice) {
            std::string gc_path;
            if (std::string(fstab->recs[i].fs_type) == "f2fs" &&
                Realpath(android::vold::BlockDeviceForPath(
                    std::string(fstab->recs[i].mount_point) + "/"), &gc_path)) {
                paths->push_back(std::string("/sys/fs/") + fstab->recs[i].fs_type +
                                 "/" + Basename(gc_path));
            }
        }

        prev_rec = &fstab->recs[i];
    }
}

void Trim(const android::sp<android::os::IVoldTaskListener>& listener) {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    // Collect both fstab and vold volumes
    std::list<std::string> paths;
    addFromFstab(&paths, PathTypes::kMountPoint);
    addFromVolumeManager(&paths, PathTypes::kMountPoint);

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

static bool waitForGc(const std::list<std::string>& paths) {
    std::unique_lock<std::mutex> lk(cv_m, std::defer_lock);
    bool stop = false, aborted = false;
    Timer timer;

    while (!stop && !aborted) {
        stop = true;
        for (const auto& path : paths) {
            std::string dirty_segments;
            if (!ReadFileToString(path + "/dirty_segments", &dirty_segments)) {
                PLOG(WARNING) << "Reading dirty_segments failed in " << path;
                continue;
            }
            if (std::stoi(dirty_segments) > DIRTY_SEGMENTS_THRESHOLD) {
                stop = false;
                break;
            }
        }

        if (stop) break;

        if (timer.duration() >= std::chrono::seconds(GC_TIMEOUT_SEC)) {
            LOG(WARNING) << "GC timeout";
            break;
        }

        lk.lock();
        aborted = cv_abort.wait_for(lk, 10s, []{
            return idle_maint_stat == IdleMaintStats::kAbort;});
        lk.unlock();
    }

    return aborted;
}

static int startGc(const std::list<std::string>& paths) {
    for (const auto& path : paths) {
        LOG(DEBUG) << "Start GC on " << path;
        if (!WriteStringToFile("1", path + "/discard_granularity")) {
            PLOG(WARNING) << "Set discard gralunarity failed on" << path;
        }
        if (!WriteStringToFile("1", path + "/gc_urgent")) {
            PLOG(WARNING) << "Start GC failed on " << path;
        }
    }
    return android::OK;
}

static int stopGc(const std::list<std::string>& paths) {
    for (const auto& path : paths) {
        LOG(DEBUG) << "Stop GC on " << path;
        if (!WriteStringToFile("0", path + "/gc_urgent")) {
            PLOG(WARNING) << "Stop GC failed on " << path;
        }
        if (!WriteStringToFile("16", path + "/discard_granularity")) {
            PLOG(WARNING) << "Set discard gralunarity failed on" << path;
        }
    }
    return android::OK;
}

static void runDevGc(void) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    struct fstab_rec *rec = NULL;

    for (int i = 0; i < fstab->num_entries; i++) {
        if (fs_mgr_has_sysfs_path(&fstab->recs[i])) {
            rec = &fstab->recs[i];
            break;
        }
    }
    if (!rec) {
        return;
    }

    std::string path;
    path.append(rec->sysfs_path);
    path = path + "/manual_gc";
    Timer timer;

    LOG(DEBUG) << "Start Dev GC on " << path;
    while (1) {
        std::string require;
        if (!ReadFileToString(path, &require)) {
            PLOG(WARNING) << "Reading manual_gc failed in " << path;
            break;
        }

        if (require == "" || require == "off" || require == "disabled") {
            LOG(DEBUG) << "No more to do Dev GC";
            break;
        }

        LOG(DEBUG) << "Trigger Dev GC on " << path;
        if (!WriteStringToFile("1", path)) {
            PLOG(WARNING) << "Start Dev GC failed on " << path;
            break;
        }

        if (timer.duration() >= std::chrono::seconds(DEVGC_TIMEOUT_SEC)) {
            LOG(WARNING) << "Dev GC timeout";
            break;
        }
        sleep(2);
    }
    LOG(DEBUG) << "Stop Dev GC on " << path;
    if (!WriteStringToFile("0", path)) {
        PLOG(WARNING) << "Stop Dev GC failed on " << path;
    }
    return;
}

int RunIdleMaint(const android::sp<android::os::IVoldTaskListener>& listener) {
    std::unique_lock<std::mutex> lk(cv_m);
    if (idle_maint_stat != IdleMaintStats::kStopped) {
        LOG(DEBUG) << "idle maintenance is already running";
        if (listener) {
            android::os::PersistableBundle extras;
            listener->onFinished(0, extras);
        }
        return android::OK;
    }
    idle_maint_stat = IdleMaintStats::kRunning;
    lk.unlock();

    LOG(DEBUG) << "idle maintenance started";

    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    std::list<std::string> paths;
    addFromFstab(&paths, PathTypes::kBlkDevice);
    addFromVolumeManager(&paths, PathTypes::kBlkDevice);

    startGc(paths);

    bool gc_aborted = waitForGc(paths);

    stopGc(paths);

    lk.lock();
    idle_maint_stat = IdleMaintStats::kStopped;
    lk.unlock();

    cv_stop.notify_one();

    if (!gc_aborted) {
        Trim(nullptr);
        runDevGc();
    }

    if (listener) {
        android::os::PersistableBundle extras;
        listener->onFinished(0, extras);
    }

    LOG(DEBUG) << "idle maintenance completed";

    release_wake_lock(kWakeLock);

    return android::OK;
}

int AbortIdleMaint(const android::sp<android::os::IVoldTaskListener>& listener) {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    std::unique_lock<std::mutex> lk(cv_m);
    if (idle_maint_stat != IdleMaintStats::kStopped) {
        idle_maint_stat = IdleMaintStats::kAbort;
        lk.unlock();
        cv_abort.notify_one();
        lk.lock();
        LOG(DEBUG) << "aborting idle maintenance";
        cv_stop.wait(lk, []{
            return idle_maint_stat == IdleMaintStats::kStopped;});
    }
    lk.unlock();

    if (listener) {
        android::os::PersistableBundle extras;
        listener->onFinished(0, extras);
    }

    release_wake_lock(kWakeLock);

    LOG(DEBUG) << "idle maintenance stopped";

    return android::OK;
}

}  // namespace vold
}  // namespace android
