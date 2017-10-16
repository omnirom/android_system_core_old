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
#include "VolumeManager.h"
#include "BenchmarkTask.h"
#include "MoveTask.h"
#include "Process.h"
#include "TrimTask.h"

#include "cryptfs.h"
#include "Ext4Crypt.h"
#include "MetadataCrypt.h"

#include <fstream>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <ext4_utils/ext4_crypt.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <utils/Trace.h>

#ifndef LOG_TAG
#define LOG_TAG "vold"
#endif

using android::base::StringPrintf;
using std::endl;

namespace android {
namespace vold {

namespace {

constexpr const char* kDump = "android.permission.DUMP";

static binder::Status ok() {
    return binder::Status::ok();
}

static binder::Status exception(uint32_t code, const std::string& msg) {
    return binder::Status::fromExceptionCode(code, String8(msg.c_str()));
}

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

binder::Status checkPermission(const char* permission) {
    pid_t pid;
    uid_t uid;

    if (checkCallingPermission(String16(permission), reinterpret_cast<int32_t*>(&pid),
            reinterpret_cast<int32_t*>(&uid))) {
        return ok();
    } else {
        return exception(binder::Status::EX_SECURITY,
                StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission));
    }
}

binder::Status checkUid(uid_t expectedUid) {
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid == expectedUid || uid == AID_ROOT) {
        return ok();
    } else {
        return exception(binder::Status::EX_SECURITY,
                StringPrintf("UID %d is not expected UID %d", uid, expectedUid));
    }
}

binder::Status checkArgumentId(const std::string& id) {
    if (id.empty()) {
        return exception(binder::Status::EX_ILLEGAL_ARGUMENT, "Missing ID");
    }
    for (const char& c : id) {
        if (!std::isalnum(c) && c != ':' && c != ',') {
            return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                    StringPrintf("ID %s is malformed", id.c_str()));
        }
    }
    return ok();
}

binder::Status checkArgumentPath(const std::string& path) {
    if (path.empty()) {
        return exception(binder::Status::EX_ILLEGAL_ARGUMENT, "Missing path");
    }
    if (path[0] != '/') {
        return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                StringPrintf("Path %s is relative", path.c_str()));
    }
    for (const char& c : path) {
        if (c == '\0' || c == '\n') {
            return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                    StringPrintf("Path %s is malformed", path.c_str()));
        }
    }
    return ok();
}

binder::Status checkArgumentHex(const std::string& hex) {
    // Empty hex strings are allowed
    for (const char& c : hex) {
        if (!std::isxdigit(c) && c != ':' && c != '-') {
            return exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                    StringPrintf("Hex %s is malformed", hex.c_str()));
        }
    }
    return ok();
}

#define ENFORCE_UID(uid) {                                  \
    binder::Status status = checkUid((uid));                \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define CHECK_ARGUMENT_ID(id) {                             \
    binder::Status status = checkArgumentId((id));          \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define CHECK_ARGUMENT_PATH(path) {                         \
    binder::Status status = checkArgumentPath((path));      \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define CHECK_ARGUMENT_HEX(hex) {                           \
    binder::Status status = checkArgumentHex((hex));        \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define ACQUIRE_LOCK \
    std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock()); \
    ATRACE_CALL();

#define ACQUIRE_CRYPT_LOCK \
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

status_t VoldNativeService::dump(int fd, const Vector<String16> & /* args */) {
    auto out = std::fstream(StringPrintf("/proc/self/fd/%d", fd));
    const binder::Status dump_permission = checkPermission(kDump);
    if (!dump_permission.isOk()) {
        out << dump_permission.toString8() << endl;
        return PERMISSION_DENIED;
    }

    ACQUIRE_LOCK;
    out << "vold is happy!" << endl;
    out.flush();
    return NO_ERROR;
}

binder::Status VoldNativeService::setListener(
        const android::sp<android::os::IVoldListener>& listener) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    VolumeManager::Instance()->setListener(listener);
    return ok();
}

binder::Status VoldNativeService::monitor() {
    ENFORCE_UID(AID_SYSTEM);

    // Simply acquire/release each lock for watchdog
    {
        ACQUIRE_LOCK;
    }
    {
        ACQUIRE_CRYPT_LOCK;
    }

    return ok();
}

binder::Status VoldNativeService::reset() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->reset());
}

binder::Status VoldNativeService::shutdown() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->shutdown());
}

binder::Status VoldNativeService::mountAll() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    struct fstab* fstab = fs_mgr_read_fstab_default();
    int res = fs_mgr_mount_all(fstab, MOUNT_MODE_DEFAULT);
    fs_mgr_free_fstab(fstab);
    return translate(res);
}

binder::Status VoldNativeService::onUserAdded(int32_t userId, int32_t userSerial) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserAdded(userId, userSerial));
}

binder::Status VoldNativeService::onUserRemoved(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserRemoved(userId));
}

binder::Status VoldNativeService::onUserStarted(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserStarted(userId));
}

binder::Status VoldNativeService::onUserStopped(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->onUserStopped(userId));
}

binder::Status VoldNativeService::partition(const std::string& diskId, int32_t partitionType,
        int32_t ratio) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(diskId);
    ACQUIRE_LOCK;

    auto disk = VolumeManager::Instance()->findDisk(diskId);
    if (disk == nullptr) {
        return error("Failed to find disk " + diskId);
    }
    switch (partitionType) {
    case PARTITION_TYPE_PUBLIC: return translate(disk->partitionPublic());
    case PARTITION_TYPE_PRIVATE: return translate(disk->partitionPrivate());
    case PARTITION_TYPE_MIXED: return translate(disk->partitionMixed(ratio));
    default: return error("Unknown type " + std::to_string(partitionType));
    }
}

binder::Status VoldNativeService::forgetPartition(const std::string& partGuid) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_HEX(partGuid);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->forgetPartition(partGuid));
}

binder::Status VoldNativeService::mount(const std::string& volId, int32_t mountFlags,
        int32_t mountUserId) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }

    vol->setMountFlags(mountFlags);
    vol->setMountUserId(mountUserId);

    int res = vol->mount();
    if ((mountFlags & MOUNT_FLAG_PRIMARY) != 0) {
        VolumeManager::Instance()->setPrimary(vol);
    }
    return translate(res);
}

binder::Status VoldNativeService::unmount(const std::string& volId) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }
    return translate(vol->unmount());
}

binder::Status VoldNativeService::format(const std::string& volId, const std::string& fsType) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    auto vol = VolumeManager::Instance()->findVolume(volId);
    if (vol == nullptr) {
        return error("Failed to find volume " + volId);
    }
    return translate(vol->format(fsType));
}

binder::Status VoldNativeService::benchmark(const std::string& volId,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    std::string path;
    if (volId == "private" || volId == "null") {
        path = "/data";
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
        path = vol->getPath();
    }

    if (path.empty()) {
        return error("Volume " + volId + " missing path");
    }

    (new android::vold::BenchmarkTask(path, listener))->start();
    return ok();
}

binder::Status VoldNativeService::moveStorage(const std::string& fromVolId,
        const std::string& toVolId, const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_UID(AID_SYSTEM);
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
    (new android::vold::MoveTask(fromVol, toVol, listener))->start();
    return ok();
}

binder::Status VoldNativeService::remountUid(int32_t uid, int32_t remountMode) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    std::string tmp;
    switch (remountMode) {
    case REMOUNT_MODE_NONE: tmp = "none"; break;
    case REMOUNT_MODE_DEFAULT: tmp = "default"; break;
    case REMOUNT_MODE_READ: tmp = "read"; break;
    case REMOUNT_MODE_WRITE: tmp = "write"; break;
    default: return error("Unknown mode " + std::to_string(remountMode));
    }
    return translate(VolumeManager::Instance()->remountUid(uid, tmp));
}

binder::Status VoldNativeService::mkdirs(const std::string& path) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PATH(path);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->mkdirs(path.c_str()));
}

binder::Status VoldNativeService::createObb(const std::string& sourcePath,
        const std::string& sourceKey, int32_t ownerGid, std::string* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_PATH(sourcePath);
    CHECK_ARGUMENT_HEX(sourceKey);
    ACQUIRE_LOCK;

    return translate(
            VolumeManager::Instance()->createObb(sourcePath, sourceKey, ownerGid, _aidl_return));
}

binder::Status VoldNativeService::destroyObb(const std::string& volId) {
    ENFORCE_UID(AID_SYSTEM);
    CHECK_ARGUMENT_ID(volId);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->destroyObb(volId));
}

binder::Status VoldNativeService::fstrim(int32_t fstrimFlags,
        const android::sp<android::os::IVoldTaskListener>& listener) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    (new android::vold::TrimTask(fstrimFlags, listener))->start();
    return ok();
}

binder::Status VoldNativeService::mountAppFuse(int32_t uid, int32_t pid, int32_t mountId,
        android::base::unique_fd* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->mountAppFuse(uid, pid, mountId, _aidl_return));
}

binder::Status VoldNativeService::unmountAppFuse(int32_t uid, int32_t pid, int32_t mountId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_LOCK;

    return translate(VolumeManager::Instance()->unmountAppFuse(uid, pid, mountId));
}

binder::Status VoldNativeService::fdeCheckPassword(const std::string& password) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_check_passwd(password.c_str()));
}

binder::Status VoldNativeService::fdeRestart() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    // Spawn as thread so init can issue commands back to vold without
    // causing deadlock, usually as a result of prep_data_fs.
    std::thread(&cryptfs_restart).detach();
    return ok();
}

binder::Status VoldNativeService::fdeComplete(int32_t* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_crypto_complete();
    return ok();
}

static int fdeEnableInternal(int32_t passwordType, const std::string& password,
        int32_t encryptionFlags) {
    bool noUi = (encryptionFlags & VoldNativeService::ENCRYPTION_FLAG_NO_UI) != 0;

    std::string how;
    if ((encryptionFlags & VoldNativeService::ENCRYPTION_FLAG_IN_PLACE) != 0) {
        how = "inplace";
    } else if ((encryptionFlags & VoldNativeService::ENCRYPTION_FLAG_WIPE) != 0) {
        how = "wipe";
    } else {
        LOG(ERROR) << "Missing encryption flag";
        return -1;
    }

    for (int tries = 0; tries < 2; ++tries) {
        int rc;
        if (passwordType == VoldNativeService::PASSWORD_TYPE_DEFAULT) {
            rc = cryptfs_enable_default(how.c_str(), noUi);
        } else {
            rc = cryptfs_enable(how.c_str(), passwordType, password.c_str(), noUi);
        }

        if (rc == 0) {
            return 0;
        } else if (tries == 0) {
            Process::killProcessesWithOpenFiles(DATA_MNT_POINT, SIGKILL);
        }
    }

    return -1;
}

binder::Status VoldNativeService::fdeEnable(int32_t passwordType,
        const std::string& password, int32_t encryptionFlags) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    if (e4crypt_is_native()) {
        if (passwordType != PASSWORD_TYPE_DEFAULT) {
            return error("Unexpected password type");
        }
        if (encryptionFlags != (ENCRYPTION_FLAG_IN_PLACE | ENCRYPTION_FLAG_NO_UI)) {
            return error("Unexpected flags");
        }
        return translateBool(e4crypt_enable_crypto());
    }

    // Spawn as thread so init can issue commands back to vold without
    // causing deadlock, usually as a result of prep_data_fs.
    std::thread(&fdeEnableInternal, passwordType, password, encryptionFlags).detach();
    return ok();
}

binder::Status VoldNativeService::fdeChangePassword(int32_t passwordType,
        const std::string& password) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_changepw(passwordType, password.c_str()));
}

binder::Status VoldNativeService::fdeVerifyPassword(const std::string& password) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_verify_passwd(password.c_str()));
}

binder::Status VoldNativeService::fdeGetField(const std::string& key,
        std::string* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    char buf[PROPERTY_VALUE_MAX];
    if (cryptfs_getfield(key.c_str(), buf, sizeof(buf)) != CRYPTO_GETFIELD_OK) {
        return error(StringPrintf("Failed to read field %s", key.c_str()));
    } else {
        *_aidl_return = buf;
        return ok();
    }
}

binder::Status VoldNativeService::fdeSetField(const std::string& key,
        const std::string& value) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translate(cryptfs_setfield(key.c_str(), value.c_str()));
}

binder::Status VoldNativeService::fdeGetPasswordType(int32_t* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_get_password_type();
    return ok();
}

binder::Status VoldNativeService::fdeGetPassword(std::string* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    const char* res = cryptfs_get_password();
    if (res != nullptr) {
        *_aidl_return = res;
    }
    return ok();
}

binder::Status VoldNativeService::fdeClearPassword() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    cryptfs_clear_password();
    return ok();
}

binder::Status VoldNativeService::fbeEnable() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_initialize_global_de());
}

binder::Status VoldNativeService::mountDefaultEncrypted() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    if (e4crypt_is_native()) {
        return translateBool(e4crypt_mount_metadata_encrypted());
    } else {
        // Spawn as thread so init can issue commands back to vold without
        // causing deadlock, usually as a result of prep_data_fs.
        std::thread(&cryptfs_mount_default_encrypted).detach();
        return ok();
    }
}

binder::Status VoldNativeService::initUser0() {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_init_user0());
}

binder::Status VoldNativeService::isConvertibleToFbe(bool* _aidl_return) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    *_aidl_return = cryptfs_isConvertibleToFBE() != 0;
    return ok();
}

binder::Status VoldNativeService::createUserKey(int32_t userId, int32_t userSerial,
        bool ephemeral) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_vold_create_user_key(userId, userSerial, ephemeral));
}

binder::Status VoldNativeService::destroyUserKey(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_destroy_user_key(userId));
}

binder::Status VoldNativeService::addUserKeyAuth(int32_t userId, int32_t userSerial,
        const std::string& token, const std::string& secret) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_add_user_key_auth(userId, userSerial, token, secret));
}

binder::Status VoldNativeService::fixateNewestUserKeyAuth(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_fixate_newest_user_key_auth(userId));
}

binder::Status VoldNativeService::unlockUserKey(int32_t userId, int32_t userSerial,
        const std::string& token, const std::string& secret) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_unlock_user_key(userId, userSerial, token, secret));
}

binder::Status VoldNativeService::lockUserKey(int32_t userId) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_lock_user_key(userId));
}

binder::Status VoldNativeService::prepareUserStorage(const std::unique_ptr<std::string>& uuid,
        int32_t userId, int32_t userSerial, int32_t flags) {
    ENFORCE_UID(AID_SYSTEM);
    std::string empty_string = "";
    auto uuid_ = uuid ? *uuid : empty_string;
    CHECK_ARGUMENT_HEX(uuid_);

    ACQUIRE_CRYPT_LOCK;
    return translateBool(e4crypt_prepare_user_storage(uuid_, userId, userSerial, flags));
}

binder::Status VoldNativeService::destroyUserStorage(const std::unique_ptr<std::string>& uuid,
        int32_t userId, int32_t flags) {
    ENFORCE_UID(AID_SYSTEM);
    std::string empty_string = "";
    auto uuid_ = uuid ? *uuid : empty_string;
    CHECK_ARGUMENT_HEX(uuid_);

    ACQUIRE_CRYPT_LOCK;
    return translateBool(e4crypt_destroy_user_storage(uuid_, userId, flags));
}

binder::Status VoldNativeService::secdiscard(const std::string& path) {
    ENFORCE_UID(AID_SYSTEM);
    ACQUIRE_CRYPT_LOCK;

    return translateBool(e4crypt_secdiscard(path));
}

}  // namespace vold
}  // namespace android
