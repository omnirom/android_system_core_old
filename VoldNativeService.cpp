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

#define ATRACE_TAG ATRACE_TAG_PACKAGE_MANAGER

#include "VoldNativeService.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fscrypt/fscrypt.h>
#include <private/android_filesystem_config.h>
#include <utils/Trace.h>

#include <fstream>
#include <thread>

#include "Benchmark.h"
#include "Checkpoint.h"
#include "FsCrypt.h"
#include "IdleMaint.h"
#include "KeyStorage.h"
#include "Keymaster.h"
#include "MetadataCrypt.h"
#include "MoveStorage.h"
#include "Process.h"
#include "VoldNativeServiceValidation.h"
#include "VoldUtil.h"
#include "VolumeManager.h"
#include "cryptfs.h"
#include "incfs.h"

using android::base::StringPrintf;
using std::endl;
using namespace std::literals;

namespace android {
namespace vold {

namespace {

constexpr const char* kDump = "android.permission.DUMP";

static binder::Status error(const std::string& msg) {
    PLOG(ERROR) << msg;
    return binder::Status::fromServiceSpecificError(errno, String8(msg.c_str()));
}

static binder::Status translate(int status) {
    if (status == 0) {
        return binder::Status::ok();
    } else {
        return binder::Status::fromServiceSpecificError(status);
    }
}

static binder::Status translateBool(bool status) {
    if (status) {
        return binder::Status::ok();
    } else {
        return binder::Status::fromServiceSpecificError(status);
    }
}

#define ENFORCE_SYSTEM_OR_ROOT                              \
    {                                                       \
        binder::Status status = CheckUidOrRoot(AID_SYSTEM); \
        if (!status.isOk()) {                               \
            return status;                                  \
        }                                                   \
    }

#define CHECK_ARGUMENT_ID(id)                          \
    {                                                  \
        binder::Status status = CheckArgumentId((id)); \
        if (!status.isOk()) {                          \
            return status;                             \
        }                                              \
    }

#define CHECK_ARGUMENT_PATH(path)                          \
    {                                                      \
        binder::Status status = CheckArgumentPath((path)); \
        if (!status.isOk()) {                              \
            return status;                                 \
        }                                                  \
    }

#define CHECK_ARGUMENT_HEX(hex)                          \
    {                                                    \
        binder::Status status = CheckArgumentHex((hex)); \
        if (!status.isOk()) {                            \
            return status;                               \
        }                                                \
    }

#define ACQUIRE_LOCK                                                        \
    std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock()); \
    ATRACE_CALL();

#define ACQUIRE_CRYPT_LOCK                                                       \
    std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getCryptLock()); \
    ATRACE_CALL();

}  // namespace

status_t VoldNativeService::start() {
    IPCThreadState::self()->disableBackgroundScheduling(true);
    status_t ret = BinderService<VoldNativeService>::publish();
    if (ret != android::OK) {
        return ret;
    }
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();
    ps->giveThreadPoolName();
    return android::OK;
}

status_t VoldNativeService::dump(int fd, const Vector<String16>& /* args */) {
    auto out = std::fstream(StringPrintf("/proc/self/fd/%d", fd));
    const binder::Status dump_permission = CheckPermission(kDump);
    if (!dump_permission.isOk()) {
        out << dump_permission.toString8() << endl;
        return PERMISSION_DENIED;
    }

    ACQUIRE_LOCK;
    out << "vold is happy!" << endl;
    return NO_ERROR;
}

binder::Status VoldNativeService::setListener(
        const android::sp<android::os::IVoldListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    VolumeManager::Instance()->setListener(listener);
    return Ok();
}

binder::Status VoldNativeService::monitor() {
    ENFORCE_SYSTEM_OR_ROOT;

    // Simply acquire/release each lock for watchdog
    { ACQUIRE_LOCK; }
    { ACQUIRE_CRYPT_LOCK; }

    return Ok();
}

binder::Status VoldNativeService::reset() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->reset());
}

binder::Status VoldNativeService::shutdown() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->shutdown());
}

binder::Status VoldNativeService::abortFuse() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->abortFuse());
}

binder::Status VoldNativeService::onUserAdded(int32_t userId, int32_t userSerial) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserAdded(userId, userSerial));
}

binder::Status VoldNativeService::onUserRemoved(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserRemoved(userId));
}

binder::Status VoldNativeService::onUserStarted(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserStarted(userId));
}

binder::Status VoldNativeService::onUserStopped(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserStopped(userId));
}

binder::Status VoldNativeService::addAppIds(const std::vector<std::string>& packageNames,
                                            const std::vector<int32_t>& appIds) {
    return Ok();
}

binder::Status VoldNativeService::addSandboxIds(const std::vector<int32_t>& appIds,
                                                const std::vector<std::string>& sandboxIds) {
    return Ok();
}

binder::Status VoldNativeService::onSecureKeyguardStateChanged(bool isShowing) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onSecureKeyguardStateChanged(isShowing));
}

binder::Status VoldNativeService::partition(const std::string& diskId, int32_t partitionType,
                                            int32_t ratio) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(diskId);
    ACQUIRE_LOCK;

    auto disk = VolumeManager::Instance()->findDisk(diskId);
    if (disk == nullptr) {
        return error("Failed to find disk " + diskId);
    }
    switch (partitionType) {
        case PARTITION_TYPE_PUBLIC:
            return translate(disk->partitionPublic());
        case PARTITION_TYPE_PRIVATE:
            return translate(disk->partitionPrivate());
        case PARTITION_TYPE_MIXED:
            return translate(disk->partitionMixed(ratio));
        default:
            return error("Unknown type " + std::to_string(partitionType));
    }
}

binder::Status VoldNativeService::forgetPartition(const std::string& partGuid,
                                                  const std::string& fsUuid) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_HEX(partGuid);
    CHECK_ARGUMENT_HEX(fsUuid);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->forgetPartition(partGuid, fsUuid));
}

binder::Status VoldNativeService::mount(
        const std::string& volId, int32_t mountFlags, int32_t mountUserId,
        const android::sp<android::os::IVoldMountCallback>& callback) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }

    vol->setMountFlags(mountFlags);
    vol->setMountUserId(mountUserId);

    vol->setMountCallback(callback);
    int res = vol->mount();
    vol->setMountCallback(nullptr);

    if (res != OK) {
        return translate(res);
    }

    return translate(OK);
}

binder::Status VoldNativeService::unmount(const std::string& volId) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }
    return translate(vol->unmount());
}

binder::Status VoldNativeService::format(const std::string& volId, const std::string& fsType) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }
    return translate(vol->format(fsType));
}

static binder::Status pathForVolId(const std::string& volId, std::string* path) {
    if (volId == "private" || volId == "null") {
        *path = "/data";
    } else {
        auto vol = VolumeManager::Instance()->findVolume(volId);
        if (vol == nullptr) {
            return error("Failed to find volume " + volId);
        }
        if (vol->getType() != VolumeBase::Type::kPrivate) {
            return error("Volume " + volId + " not private");
        }
        if (vol->getState() != VolumeBase::State::kMounted) {
            return error("Volume " + volId + " not mounted");
        }
        *path = vol->getPath();
        if (path->empty()) {
            return error("Volume " + volId + " missing path");
        }
    }
    return Ok();
}

binder::Status VoldNativeService::benchmark(
        const std::string& volId, const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    std::string path;
    auto status = pathForVolId(volId, &path);
    if (!status.isOk()) return status;

    std::thread([=]() { android::vold::Benchmark(path, listener); }).detach();
    return Ok();
}

binder::Status VoldNativeService::moveStorage(
        const std::string& fromVolId, const std::string& toVolId,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(fromVolId);
    CHECK_ARGUMENT_ID(toVolId);
    ACQUIRE_LOCK;

    auto fromVol = VolumeManager::Instance()->findVolume(fromVolId);
    auto toVol = VolumeManager::Instance()->findVolume(toVolId);
    if (fromVol == nullptr) {
        return error("Failed to find volume " + fromVolId);
    } else if (toVol == nullptr) {
        return error("Failed to find volume " + toVolId);
    }

    std::thread([=]() { android::vold::MoveStorage(fromVol, toVol, listener); }).detach();
    return Ok();
}

binder::Status VoldNativeService::remountUid(int32_t uid, int32_t remountMode) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->remountUid(uid, remountMode));
}

binder::Status VoldNativeService::remountAppStorageDirs(int uid, int pid,
        const std::vector<std::string>& packageNames) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->handleAppStorageDirs(uid, pid,
            false /* doUnmount */, packageNames));
}

binder::Status VoldNativeService::unmountAppStorageDirs(int uid, int pid,
        const std::vector<std::string>& packageNames) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->handleAppStorageDirs(uid, pid,
            true /* doUnmount */, packageNames));
}

binder::Status VoldNativeService::setupAppDir(const std::string& path, int32_t appUid) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(path);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->setupAppDir(path, appUid));
}

binder::Status VoldNativeService::ensureAppDirsCreated(const std::vector<std::string>& paths,
        int32_t appUid) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->ensureAppDirsCreated(paths, appUid));
}

binder::Status VoldNativeService::fixupAppDir(const std::string& path, int32_t appUid) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(path);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->fixupAppDir(path, appUid));
}

binder::Status VoldNativeService::createObb(const std::string& sourcePath,
                                            const std::string& sourceKey, int32_t ownerGid,
                                            std::string* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(sourcePath);
    CHECK_ARGUMENT_HEX(sourceKey);
    ACQUIRE_LOCK;

    return translate(
            VolumeManager::Instance()->createObb(sourcePath, sourceKey, ownerGid, _aidl_return));
}

binder::Status VoldNativeService::destroyObb(const std::string& volId) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->destroyObb(volId));
}

binder::Status VoldNativeService::createStubVolume(const std::string& sourcePath,
                                                   const std::string& mountPath,
                                                   const std::string& fsType,
                                                   const std::string& fsUuid,
                                                   const std::string& fsLabel, int32_t flags,
                                                   std::string* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(sourcePath);
    CHECK_ARGUMENT_PATH(mountPath);
    CHECK_ARGUMENT_HEX(fsUuid);
    // Label limitation seems to be different between fs (including allowed characters), so checking
    // is quite meaningless.
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->createStubVolume(
            sourcePath, mountPath, fsType, fsUuid, fsLabel, flags, _aidl_return));
}

binder::Status VoldNativeService::destroyStubVolume(const std::string& volId) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->destroyStubVolume(volId));
}

binder::Status VoldNativeService::fstrim(
        int32_t fstrimFlags, const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    std::thread([=]() { android::vold::Trim(listener); }).detach();
    return Ok();
}

binder::Status VoldNativeService::runIdleMaint(
        const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    std::thread([=]() { android::vold::RunIdleMaint(listener); }).detach();
    return Ok();
}

binder::Status VoldNativeService::abortIdleMaint(
        const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    std::thread([=]() { android::vold::AbortIdleMaint(listener); }).detach();
    return Ok();
}

binder::Status VoldNativeService::mountAppFuse(int32_t uid, int32_t mountId,
                                               android::base::unique_fd* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->mountAppFuse(uid, mountId, _aidl_return));
}

binder::Status VoldNativeService::unmountAppFuse(int32_t uid, int32_t mountId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->unmountAppFuse(uid, mountId));
}

binder::Status VoldNativeService::openAppFuseFile(int32_t uid, int32_t mountId, int32_t fileId,
                                                  int32_t flags,
                                                  android::base::unique_fd* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    int fd = VolumeManager::Instance()->openAppFuseFile(uid, mountId, fileId, flags);
    if (fd == -1) {
        return error("Failed to open AppFuse file for uid: " + std::to_string(uid) +
                     " mountId: " + std::to_string(mountId) + " fileId: " + std::to_string(fileId) +
                     " flags: " + std::to_string(flags));
    }

    *_aidl_return = android::base::unique_fd(fd);
    return Ok();
}

binder::Status VoldNativeService::fdeCheckPassword(const std::string& password) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_check_passwd(password.c_str()));
}

binder::Status VoldNativeService::fdeRestart() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    // Spawn as thread so init can issue commands back to vold without
    // causing deadlock, usually as a result of prep_data_fs.
    std::thread(&cryptfs_restart).detach();
    return Ok();
}

binder::Status VoldNativeService::fdeComplete(int32_t* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_crypto_complete();
    return Ok();
}

static int fdeEnableInternal(int32_t passwordType, const std::string& password,
                             int32_t encryptionFlags) {
    bool noUi = (encryptionFlags & VoldNativeService::ENCRYPTION_FLAG_NO_UI) != 0;

    for (int tries = 0; tries < 2; ++tries) {
        int rc;
        if (passwordType == VoldNativeService::PASSWORD_TYPE_DEFAULT) {
            rc = cryptfs_enable_default(noUi);
        } else {
            rc = cryptfs_enable(passwordType, password.c_str(), noUi);
        }

        if (rc == 0) {
            return 0;
        } else if (tries == 0) {
            KillProcessesWithOpenFiles(DATA_MNT_POINT, SIGKILL);
        }
    }

    return -1;
}

binder::Status VoldNativeService::fdeEnable(int32_t passwordType, const std::string& password,
                                            int32_t encryptionFlags) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    LOG(DEBUG) << "fdeEnable(" << passwordType << ", *, " << encryptionFlags << ")";
    if (fscrypt_is_native()) {
        LOG(ERROR) << "fscrypt_is_native, fdeEnable invalid";
        return error("fscrypt_is_native, fdeEnable invalid");
    }
    LOG(DEBUG) << "!fscrypt_is_native, spawning fdeEnableInternal";

    // Spawn as thread so init can issue commands back to vold without
    // causing deadlock, usually as a result of prep_data_fs.
    std::thread(&fdeEnableInternal, passwordType, password, encryptionFlags).detach();
    return Ok();
}

binder::Status VoldNativeService::fdeChangePassword(int32_t passwordType,
                                                    const std::string& password) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_changepw(passwordType, password.c_str()));
}

binder::Status VoldNativeService::fdeVerifyPassword(const std::string& password) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_verify_passwd(password.c_str()));
}

binder::Status VoldNativeService::fdeGetField(const std::string& key, std::string* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    char buf[PROPERTY_VALUE_MAX];
    if (cryptfs_getfield(key.c_str(), buf, sizeof(buf)) != CRYPTO_GETFIELD_OK) {
        return error(StringPrintf("Failed to read field %s", key.c_str()));
    } else {
        *_aidl_return = buf;
        return Ok();
    }
}

binder::Status VoldNativeService::fdeSetField(const std::string& key, const std::string& value) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_setfield(key.c_str(), value.c_str()));
}

binder::Status VoldNativeService::fdeGetPasswordType(int32_t* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_get_password_type();
    return Ok();
}

binder::Status VoldNativeService::fdeGetPassword(std::string* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    const char* res = cryptfs_get_password();
    if (res != nullptr) {
        *_aidl_return = res;
    }
    return Ok();
}

binder::Status VoldNativeService::fdeClearPassword() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    cryptfs_clear_password();
    return Ok();
}

binder::Status VoldNativeService::fbeEnable() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_initialize_systemwide_keys());
}

binder::Status VoldNativeService::mountDefaultEncrypted() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    if (!fscrypt_is_native()) {
        // Spawn as thread so init can issue commands back to vold without
        // causing deadlock, usually as a result of prep_data_fs.
        std::thread(&cryptfs_mount_default_encrypted).detach();
    }
    return Ok();
}

binder::Status VoldNativeService::initUser0() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_init_user0());
}

binder::Status VoldNativeService::isConvertibleToFbe(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_isConvertibleToFBE() != 0;
    return Ok();
}

binder::Status VoldNativeService::mountFstab(const std::string& blkDevice,
                                             const std::string& mountPoint) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translateBool(
            fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, false, false, "null"));
}

binder::Status VoldNativeService::encryptFstab(const std::string& blkDevice,
                                               const std::string& mountPoint, bool shouldFormat,
                                               const std::string& fsType) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translateBool(
            fscrypt_mount_metadata_encrypted(blkDevice, mountPoint, true, shouldFormat, fsType));
}

binder::Status VoldNativeService::setStorageBindingSeed(const std::vector<uint8_t>& seed) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(setKeyStorageBindingSeed(seed));
}

binder::Status VoldNativeService::createUserKey(int32_t userId, int32_t userSerial,
                                                bool ephemeral) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_vold_create_user_key(userId, userSerial, ephemeral));
}

binder::Status VoldNativeService::destroyUserKey(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_destroy_user_key(userId));
}

binder::Status VoldNativeService::addUserKeyAuth(int32_t userId, int32_t userSerial,
                                                 const std::string& token,
                                                 const std::string& secret) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_add_user_key_auth(userId, userSerial, token, secret));
}

binder::Status VoldNativeService::clearUserKeyAuth(int32_t userId, int32_t userSerial,
                                                   const std::string& token,
                                                   const std::string& secret) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_clear_user_key_auth(userId, userSerial, token, secret));
}

binder::Status VoldNativeService::fixateNewestUserKeyAuth(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_fixate_newest_user_key_auth(userId));
}

binder::Status VoldNativeService::unlockUserKey(int32_t userId, int32_t userSerial,
                                                const std::string& token,
                                                const std::string& secret) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_unlock_user_key(userId, userSerial, token, secret));
}

binder::Status VoldNativeService::lockUserKey(int32_t userId) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_CRYPT_LOCK;

    return translateBool(fscrypt_lock_user_key(userId));
}

binder::Status VoldNativeService::prepareUserStorage(const std::optional<std::string>& uuid,
                                                     int32_t userId, int32_t userSerial,
                                                     int32_t flags) {
    ENFORCE_SYSTEM_OR_ROOT;
    std::string empty_string = "";
    auto uuid_ = uuid ? *uuid : empty_string;
    CHECK_ARGUMENT_HEX(uuid_);

    ACQUIRE_CRYPT_LOCK;
    return translateBool(fscrypt_prepare_user_storage(uuid_, userId, userSerial, flags));
}

binder::Status VoldNativeService::destroyUserStorage(const std::optional<std::string>& uuid,
                                                     int32_t userId, int32_t flags) {
    ENFORCE_SYSTEM_OR_ROOT;
    std::string empty_string = "";
    auto uuid_ = uuid ? *uuid : empty_string;
    CHECK_ARGUMENT_HEX(uuid_);

    ACQUIRE_CRYPT_LOCK;
    return translateBool(fscrypt_destroy_user_storage(uuid_, userId, flags));
}

binder::Status VoldNativeService::prepareSandboxForApp(const std::string& packageName,
                                                       int32_t appId, const std::string& sandboxId,
                                                       int32_t userId) {
    return Ok();
}

binder::Status VoldNativeService::destroySandboxForApp(const std::string& packageName,
                                                       const std::string& sandboxId,
                                                       int32_t userId) {
    return Ok();
}

binder::Status VoldNativeService::startCheckpoint(int32_t retry) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_startCheckpoint(retry);
}

binder::Status VoldNativeService::needsRollback(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    *_aidl_return = cp_needsRollback();
    return Ok();
}

binder::Status VoldNativeService::needsCheckpoint(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    *_aidl_return = cp_needsCheckpoint();
    return Ok();
}

binder::Status VoldNativeService::isCheckpointing(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    *_aidl_return = cp_isCheckpointing();
    return Ok();
}

binder::Status VoldNativeService::commitChanges() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_commitChanges();
}

binder::Status VoldNativeService::prepareCheckpoint() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_prepareCheckpoint();
}

binder::Status VoldNativeService::restoreCheckpoint(const std::string& mountPoint) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(mountPoint);
    ACQUIRE_LOCK;

    return cp_restoreCheckpoint(mountPoint);
}

binder::Status VoldNativeService::restoreCheckpointPart(const std::string& mountPoint, int count) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(mountPoint);
    ACQUIRE_LOCK;

    return cp_restoreCheckpoint(mountPoint, count);
}

binder::Status VoldNativeService::markBootAttempt() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_markBootAttempt();
}

binder::Status VoldNativeService::abortChanges(const std::string& message, bool retry) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    cp_abortChanges(message, retry);
    return Ok();
}

binder::Status VoldNativeService::supportsCheckpoint(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_supportsCheckpoint(*_aidl_return);
}

binder::Status VoldNativeService::supportsBlockCheckpoint(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_supportsBlockCheckpoint(*_aidl_return);
}

binder::Status VoldNativeService::supportsFileCheckpoint(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return cp_supportsFileCheckpoint(*_aidl_return);
}

binder::Status VoldNativeService::resetCheckpoint() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    cp_resetCheckpoint();
    return Ok();
}

static void initializeIncFs() {
    // Obtaining IncFS features triggers initialization of IncFS.
    incfs::features();
}

binder::Status VoldNativeService::earlyBootEnded() {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    initializeIncFs();
    Keymaster::earlyBootEnded();
    return Ok();
}

binder::Status VoldNativeService::incFsEnabled(bool* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;

    *_aidl_return = incfs::enabled();
    return Ok();
}

binder::Status VoldNativeService::mountIncFs(
        const std::string& backingPath, const std::string& targetDir, int32_t flags,
        ::android::os::incremental::IncrementalFileSystemControlParcel* _aidl_return) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(backingPath);
    CHECK_ARGUMENT_PATH(targetDir);

    auto control = incfs::mount(backingPath, targetDir,
                                {.flags = IncFsMountFlags(flags),
                                 .defaultReadTimeoutMs = INCFS_DEFAULT_READ_TIMEOUT_MS,
                                 // Mount with read logs disabled.
                                 .readLogBufferPages = 0});
    if (!control) {
        return translate(-errno);
    }
    auto fds = control.releaseFds();
    using android::base::unique_fd;
    _aidl_return->cmd.reset(unique_fd(fds[CMD].release()));
    _aidl_return->pendingReads.reset(unique_fd(fds[PENDING_READS].release()));
    _aidl_return->log.reset(unique_fd(fds[LOGS].release()));
    if (fds[BLOCKS_WRITTEN].ok()) {
        _aidl_return->blocksWritten.emplace(unique_fd(fds[BLOCKS_WRITTEN].release()));
    }
    return Ok();
}

binder::Status VoldNativeService::unmountIncFs(const std::string& dir) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(dir);

    return translate(incfs::unmount(dir));
}

binder::Status VoldNativeService::setIncFsMountOptions(
        const ::android::os::incremental::IncrementalFileSystemControlParcel& control,
        bool enableReadLogs) {
    ENFORCE_SYSTEM_OR_ROOT;

    auto incfsControl =
            incfs::createControl(control.cmd.get(), control.pendingReads.get(), control.log.get(),
                                 control.blocksWritten ? control.blocksWritten->get() : -1);
    auto cleanupFunc = [](auto incfsControl) {
        for (auto& fd : incfsControl->releaseFds()) {
            (void)fd.release();
        }
    };
    auto cleanup =
            std::unique_ptr<incfs::Control, decltype(cleanupFunc)>(&incfsControl, cleanupFunc);
    if (auto error = incfs::setOptions(
                incfsControl,
                {.defaultReadTimeoutMs = INCFS_DEFAULT_READ_TIMEOUT_MS,
                 .readLogBufferPages = enableReadLogs ? INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES : 0});
        error < 0) {
        return binder::Status::fromServiceSpecificError(error);
    }

    return Ok();
}

binder::Status VoldNativeService::bindMount(const std::string& sourceDir,
                                            const std::string& targetDir) {
    ENFORCE_SYSTEM_OR_ROOT;
    CHECK_ARGUMENT_PATH(sourceDir);
    CHECK_ARGUMENT_PATH(targetDir);

    return translate(incfs::bindMount(sourceDir, targetDir));
}

binder::Status VoldNativeService::destroyDsuMetadataKey(const std::string& dsuSlot) {
    ENFORCE_SYSTEM_OR_ROOT;
    ACQUIRE_LOCK;

    return translateBool(destroy_dsu_metadata_key(dsuSlot));
}

}  // namespace vold
}  // namespace android
