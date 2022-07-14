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
#include "VoldUtil.h"
#include "VolumeManager.h"
#include "model/PrivateVolume.h"

#include <thread>
#include <utility>

#include <aidl/android/hardware/health/storage/BnGarbageCollectCallback.h>
#include <aidl/android/hardware/health/storage/IStorage.h>
#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/binder_manager.h>
#include <android/hardware/health/storage/1.0/IStorage.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <wakelock/wakelock.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

using android::base::Basename;
using android::base::ReadFileToString;
using android::base::Realpath;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::WriteStringToFile;
using android::hardware::Return;
using android::hardware::Void;
using AStorage = aidl::android::hardware::health::storage::IStorage;
using ABnGarbageCollectCallback =
        aidl::android::hardware::health::storage::BnGarbageCollectCallback;
using AResult = aidl::android::hardware::health::storage::Result;
using HStorage = android::hardware::health::storage::V1_0::IStorage;
using HGarbageCollectCallback = android::hardware::health::storage::V1_0::IGarbageCollectCallback;
using HResult = android::hardware::health::storage::V1_0::Result;
using std::string_literals::operator""s;

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
static const int KBYTES_IN_SEGMENT = 2048;
static const int ONE_MINUTE_IN_MS = 60000;
static const int GC_NORMAL_MODE = 0;
static const int GC_URGENT_MID_MODE = 3;

static int32_t previousSegmentWrite = 0;

static IdleMaintStats idle_maint_stat(IdleMaintStats::kStopped);
static std::condition_variable cv_abort, cv_stop;
static std::mutex cv_m;

static void addFromVolumeManager(std::list<std::string>* paths, PathTypes path_type) {
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
                    paths->push_back(std::string("/sys/fs/") + fs_type + "/" + Basename(gc_path));
                }
            }
        }
    }
}

static void addFromFstab(std::list<std::string>* paths, PathTypes path_type, bool only_data_part) {
    std::string previous_mount_point;
    for (const auto& entry : fstab_default) {
        // Skip raw partitions and swap space.
        if (entry.fs_type == "emmc" || entry.fs_type == "mtd" || entry.fs_type == "swap") {
            continue;
        }
        // Skip read-only filesystems and bind mounts.
        if (entry.flags & (MS_RDONLY | MS_BIND)) {
            continue;
        }
        // Skip anything without an underlying block device, e.g. virtiofs.
        if (entry.blk_device[0] != '/') {
            continue;
        }
        if (entry.fs_mgr_flags.vold_managed) {
            continue;  // Should we trim fat32 filesystems?
        }
        if (entry.fs_mgr_flags.no_trim) {
            continue;
        }

        if (only_data_part && entry.mount_point != "/data") {
            continue;
        }

        // Skip the multi-type partitions, which are required to be following each other.
        // See fs_mgr.c's mount_with_alternatives().
        if (entry.mount_point == previous_mount_point) {
            continue;
        }

        if (path_type == PathTypes::kMountPoint) {
            paths->push_back(entry.mount_point);
        } else if (path_type == PathTypes::kBlkDevice) {
            std::string path;
            if (entry.fs_type == "f2fs" &&
                Realpath(android::vold::BlockDeviceForPath(entry.mount_point + "/"), &path)) {
                paths->push_back("/sys/fs/" + entry.fs_type + "/" + Basename(path));
            }
        }

        previous_mount_point = entry.mount_point;
    }
}

void Trim(const android::sp<android::os::IVoldTaskListener>& listener) {
    auto wl = android::wakelock::WakeLock::tryGet(kWakeLock);
    if (!wl.has_value()) {
        return;
    }

    // Collect both fstab and vold volumes
    std::list<std::string> paths;
    addFromFstab(&paths, PathTypes::kMountPoint, false);
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
            LOG(INFO) << "Trimmed " << range.len << " bytes on " << path << " in "
                      << nanoseconds_to_milliseconds(time) << "ms";
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
        aborted =
            cv_abort.wait_for(lk, 10s, [] { return idle_maint_stat == IdleMaintStats::kAbort; });
        lk.unlock();
    }

    return aborted;
}

static int startGc(const std::list<std::string>& paths) {
    for (const auto& path : paths) {
        LOG(DEBUG) << "Start GC on " << path;
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
    }
    return android::OK;
}

static std::string getDevSysfsPath() {
    for (const auto& entry : fstab_default) {
        if (!entry.sysfs_path.empty()) {
            return entry.sysfs_path;
        }
    }
    LOG(WARNING) << "Cannot find dev sysfs path";
    return "";
}

static void runDevGcFstab(void) {
    std::string path = getDevSysfsPath();
    if (path.empty()) {
        return;
    }

    path = path + "/manual_gc";
    Timer timer;

    LOG(DEBUG) << "Start Dev GC on " << path;
    while (1) {
        std::string require;
        if (!ReadFileToString(path, &require)) {
            PLOG(WARNING) << "Reading manual_gc failed in " << path;
            break;
        }
        require = android::base::Trim(require);
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

enum class IDL { HIDL, AIDL };
std::ostream& operator<<(std::ostream& os, IDL idl) {
    return os << (idl == IDL::HIDL ? "HIDL" : "AIDL");
}

template <IDL idl, typename Result>
class GcCallbackImpl {
  protected:
    void onFinishInternal(Result result) {
        std::unique_lock<std::mutex> lock(mMutex);
        mFinished = true;
        mResult = result;
        lock.unlock();
        mCv.notify_all();
    }

  public:
    void wait(uint64_t seconds) {
        std::unique_lock<std::mutex> lock(mMutex);
        mCv.wait_for(lock, std::chrono::seconds(seconds), [this] { return mFinished; });

        if (!mFinished) {
            LOG(WARNING) << "Dev GC on " << idl << " HAL timeout";
        } else if (mResult != Result::SUCCESS) {
            LOG(WARNING) << "Dev GC on " << idl << " HAL failed with " << toString(mResult);
        } else {
            LOG(INFO) << "Dev GC on " << idl << " HAL successful";
        }
    }

  private:
    std::mutex mMutex;
    std::condition_variable mCv;
    bool mFinished{false};
    Result mResult{Result::UNKNOWN_ERROR};
};

class AGcCallbackImpl : public ABnGarbageCollectCallback,
                        public GcCallbackImpl<IDL::AIDL, AResult> {
    ndk::ScopedAStatus onFinish(AResult result) override {
        onFinishInternal(result);
        return ndk::ScopedAStatus::ok();
    }
};

class HGcCallbackImpl : public HGarbageCollectCallback, public GcCallbackImpl<IDL::HIDL, HResult> {
    Return<void> onFinish(HResult result) override {
        onFinishInternal(result);
        return Void();
    }
};

template <IDL idl, typename Service, typename GcCallbackImpl, typename GetDescription>
static void runDevGcOnHal(Service service, GcCallbackImpl cb, GetDescription get_description) {
    LOG(DEBUG) << "Start Dev GC on " << idl << " HAL";
    auto ret = service->garbageCollect(DEVGC_TIMEOUT_SEC, cb);
    if (!ret.isOk()) {
        LOG(WARNING) << "Cannot start Dev GC on " << idl
                     << " HAL: " << std::invoke(get_description, ret);
        return;
    }
    cb->wait(DEVGC_TIMEOUT_SEC);
}

static void runDevGc(void) {
    runDevGcFstab();
}

int RunIdleMaint(bool needGC, const android::sp<android::os::IVoldTaskListener>& listener) {
    std::unique_lock<std::mutex> lk(cv_m);
    bool gc_aborted = false;

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

    auto wl = android::wakelock::WakeLock::tryGet(kWakeLock);
    if (!wl.has_value()) {
        return android::UNEXPECTED_NULL;
    }

    if (needGC) {
        std::list<std::string> paths;
        addFromFstab(&paths, PathTypes::kBlkDevice, false);
        addFromVolumeManager(&paths, PathTypes::kBlkDevice);

        startGc(paths);

        gc_aborted = waitForGc(paths);

        stopGc(paths);
    }

    if (!gc_aborted) {
        Trim(nullptr);
        runDevGc();
    }

    lk.lock();
    idle_maint_stat = IdleMaintStats::kStopped;
    lk.unlock();

    cv_stop.notify_one();

    if (listener) {
        android::os::PersistableBundle extras;
        listener->onFinished(0, extras);
    }

    LOG(DEBUG) << "idle maintenance completed";

    return android::OK;
}

int AbortIdleMaint(const android::sp<android::os::IVoldTaskListener>& listener) {
    auto wl = android::wakelock::WakeLock::tryGet(kWakeLock);
    if (!wl.has_value()) {
        return android::UNEXPECTED_NULL;
    }

    std::unique_lock<std::mutex> lk(cv_m);
    if (idle_maint_stat != IdleMaintStats::kStopped) {
        idle_maint_stat = IdleMaintStats::kAbort;
        lk.unlock();
        cv_abort.notify_one();
        lk.lock();
        LOG(DEBUG) << "aborting idle maintenance";
        cv_stop.wait(lk, [] { return idle_maint_stat == IdleMaintStats::kStopped; });
    }
    lk.unlock();

    if (listener) {
        android::os::PersistableBundle extras;
        listener->onFinished(0, extras);
    }

    LOG(DEBUG) << "idle maintenance stopped";

    return android::OK;
}

int getLifeTime(const std::string& path) {
    std::string result;

    if (!ReadFileToString(path, &result)) {
        PLOG(WARNING) << "Reading lifetime estimation failed for " << path;
        return -1;
    }
    return std::stoi(result, 0, 16);
}

int32_t GetStorageLifeTime() {
    std::string path = getDevSysfsPath();
    if (path.empty()) {
        return -1;
    }

    std::string lifeTimeBasePath = path + "/health_descriptor/life_time_estimation_";

    int32_t lifeTime = getLifeTime(lifeTimeBasePath + "c");
    if (lifeTime != -1) {
        return lifeTime;
    }

    int32_t lifeTimeA = getLifeTime(lifeTimeBasePath + "a");
    int32_t lifeTimeB = getLifeTime(lifeTimeBasePath + "b");
    lifeTime = std::max(lifeTimeA, lifeTimeB);
    if (lifeTime != -1) {
        return lifeTime == 0 ? -1 : lifeTime * 10;
    }
    return -1;
}

void SetGCUrgentPace(int32_t neededSegments, int32_t minSegmentThreshold, float dirtyReclaimRate,
                     float reclaimWeight, int32_t gcPeriod, int32_t minGCSleepTime,
                     int32_t targetDirtyRatio) {
    std::list<std::string> paths;
    bool needGC = false;
    int32_t sleepTime;

    addFromFstab(&paths, PathTypes::kBlkDevice, true);
    if (paths.empty()) {
        LOG(WARNING) << "There is no valid blk device path for data partition";
        return;
    }

    std::string f2fsSysfsPath = paths.front();
    std::string freeSegmentsPath = f2fsSysfsPath + "/free_segments";
    std::string dirtySegmentsPath = f2fsSysfsPath + "/dirty_segments";
    std::string gcSleepTimePath = f2fsSysfsPath + "/gc_urgent_sleep_time";
    std::string gcUrgentModePath = f2fsSysfsPath + "/gc_urgent";
    std::string ovpSegmentsPath = f2fsSysfsPath + "/ovp_segments";
    std::string reservedBlocksPath = f2fsSysfsPath + "/reserved_blocks";
    std::string freeSegmentsStr, dirtySegmentsStr, ovpSegmentsStr, reservedBlocksStr;

    if (!ReadFileToString(freeSegmentsPath, &freeSegmentsStr)) {
        PLOG(WARNING) << "Reading failed in " << freeSegmentsPath;
        return;
    }

    if (!ReadFileToString(dirtySegmentsPath, &dirtySegmentsStr)) {
        PLOG(WARNING) << "Reading failed in " << dirtySegmentsPath;
        return;
    }

    if (!ReadFileToString(ovpSegmentsPath, &ovpSegmentsStr)) {
            PLOG(WARNING) << "Reading failed in " << ovpSegmentsPath;
            return;
        }

    if (!ReadFileToString(reservedBlocksPath, &reservedBlocksStr)) {
            PLOG(WARNING) << "Reading failed in " << reservedBlocksPath;
            return;
        }

    int32_t freeSegments = std::stoi(freeSegmentsStr);
    int32_t dirtySegments = std::stoi(dirtySegmentsStr);
    int32_t reservedBlocks = std::stoi(ovpSegmentsStr) + std::stoi(reservedBlocksStr);

    freeSegments = freeSegments > reservedBlocks ? freeSegments - reservedBlocks : 0;
    int32_t totalSegments = freeSegments + dirtySegments;
    int32_t finalTargetSegments = 0;

    if (totalSegments < minSegmentThreshold) {
        LOG(INFO) << "The sum of free segments: " << freeSegments
                  << ", dirty segments: " << dirtySegments << " is under " << minSegmentThreshold;
    } else {
        int32_t dirtyRatio = dirtySegments * 100 / totalSegments;
        int32_t neededForTargetRatio =
                (dirtyRatio > targetDirtyRatio)
                        ? totalSegments * (dirtyRatio - targetDirtyRatio) / 100
                        : 0;
        neededSegments *= reclaimWeight;
        neededSegments = (neededSegments > freeSegments) ? neededSegments - freeSegments : 0;

        finalTargetSegments = std::max(neededSegments, neededForTargetRatio);
        if (finalTargetSegments == 0) {
            LOG(INFO) << "Enough free segments: " << freeSegments;
        } else {
            finalTargetSegments =
                    std::min(finalTargetSegments, (int32_t)(dirtySegments * dirtyReclaimRate));
            if (finalTargetSegments == 0) {
                LOG(INFO) << "Low dirty segments: " << dirtySegments;
            } else if (neededSegments >= neededForTargetRatio) {
                LOG(INFO) << "Trigger GC, because of needed segments exceeding free segments";
                needGC = true;
            } else {
                LOG(INFO) << "Trigger GC for target dirty ratio diff of: "
                          << dirtyRatio - targetDirtyRatio;
                needGC = true;
            }
        }
    }

    if (!needGC) {
        if (!WriteStringToFile(std::to_string(GC_NORMAL_MODE), gcUrgentModePath)) {
            PLOG(WARNING) << "Writing failed in " << gcUrgentModePath;
        }
        return;
    }

    sleepTime = gcPeriod * ONE_MINUTE_IN_MS / finalTargetSegments;
    if (sleepTime < minGCSleepTime) {
        sleepTime = minGCSleepTime;
    }

    if (!WriteStringToFile(std::to_string(sleepTime), gcSleepTimePath)) {
        PLOG(WARNING) << "Writing failed in " << gcSleepTimePath;
        return;
    }

    if (!WriteStringToFile(std::to_string(GC_URGENT_MID_MODE), gcUrgentModePath)) {
        PLOG(WARNING) << "Writing failed in " << gcUrgentModePath;
        return;
    }

    LOG(INFO) << "Successfully set gc urgent mode: "
              << "free segments: " << freeSegments << ", reclaim target: " << finalTargetSegments
              << ", sleep time: " << sleepTime;
}

static int32_t getLifeTimeWrite() {
    std::list<std::string> paths;
    addFromFstab(&paths, PathTypes::kBlkDevice, true);
    if (paths.empty()) {
        LOG(WARNING) << "There is no valid blk device path for data partition";
        return -1;
    }

    std::string writeKbytesPath = paths.front() + "/lifetime_write_kbytes";
    std::string writeKbytesStr;
    if (!ReadFileToString(writeKbytesPath, &writeKbytesStr)) {
        PLOG(WARNING) << "Reading failed in " << writeKbytesPath;
        return -1;
    }

    long long writeBytes = std::stoll(writeKbytesStr);
    return writeBytes / KBYTES_IN_SEGMENT;
}

void RefreshLatestWrite() {
    int32_t segmentWrite = getLifeTimeWrite();
    if (segmentWrite != -1) {
        previousSegmentWrite = segmentWrite;
    }
}

int32_t GetWriteAmount() {
    int32_t currentSegmentWrite = getLifeTimeWrite();
    if (currentSegmentWrite == -1) {
        return -1;
    }

    int32_t writeAmount = currentSegmentWrite - previousSegmentWrite;
    previousSegmentWrite = currentSegmentWrite;
    return writeAmount;
}

}  // namespace vold
}  // namespace android
