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

#ifndef _VOLD_NATIVE_SERVICE_H_
#define _VOLD_NATIVE_SERVICE_H_

#include <android-base/unique_fd.h>
#include <binder/BinderService.h>

#include "android/os/BnVold.h"

namespace android {
namespace vold {

class VoldNativeService : public BinderService<VoldNativeService>, public os::BnVold {
public:
    static status_t start();
    static char const* getServiceName() { return "vold"; }
    virtual status_t dump(int fd, const Vector<String16> &args) override;

    binder::Status setListener(const android::sp<android::os::IVoldListener>& listener);

    binder::Status monitor();
    binder::Status reset();
    binder::Status shutdown();
    binder::Status mountAll();

    binder::Status onUserAdded(int32_t userId, int32_t userSerial);
    binder::Status onUserRemoved(int32_t userId);
    binder::Status onUserStarted(int32_t userId);
    binder::Status onUserStopped(int32_t userId);

    binder::Status partition(const std::string& diskId, int32_t partitionType, int32_t ratio);
    binder::Status forgetPartition(const std::string& partGuid, const std::string& fsUuid);

    binder::Status mount(const std::string& volId, int32_t mountFlags, int32_t mountUserId);
    binder::Status unmount(const std::string& volId);
    binder::Status format(const std::string& volId, const std::string& fsType);
    binder::Status benchmark(const std::string& volId,
            const android::sp<android::os::IVoldTaskListener>& listener);
    binder::Status checkEncryption(const std::string& volId);

    binder::Status moveStorage(const std::string& fromVolId, const std::string& toVolId,
            const android::sp<android::os::IVoldTaskListener>& listener);

    binder::Status remountUid(int32_t uid, int32_t remountMode);

    binder::Status mkdirs(const std::string& path);

    binder::Status createObb(const std::string& sourcePath, const std::string& sourceKey,
            int32_t ownerGid, std::string* _aidl_return);
    binder::Status destroyObb(const std::string& volId);

    binder::Status fstrim(int32_t fstrimFlags,
            const android::sp<android::os::IVoldTaskListener>& listener);

    binder::Status mountAppFuse(int32_t uid, int32_t pid, int32_t mountId,
            android::base::unique_fd* _aidl_return);
    binder::Status unmountAppFuse(int32_t uid, int32_t pid, int32_t mountId);

    binder::Status fdeCheckPassword(const std::string& password);
    binder::Status fdeRestart();
    binder::Status fdeComplete(int32_t* _aidl_return);
    binder::Status fdeEnable(int32_t passwordType,
            const std::string& password, int32_t encryptionFlags);
    binder::Status fdeChangePassword(int32_t passwordType,
            const std::string& password);
    binder::Status fdeVerifyPassword(const std::string& password);
    binder::Status fdeGetField(const std::string& key, std::string* _aidl_return);
    binder::Status fdeSetField(const std::string& key, const std::string& value);
    binder::Status fdeGetPasswordType(int32_t* _aidl_return);
    binder::Status fdeGetPassword(std::string* _aidl_return);
    binder::Status fdeClearPassword();

    binder::Status fbeEnable();

    binder::Status mountDefaultEncrypted();
    binder::Status initUser0();
    binder::Status isConvertibleToFbe(bool* _aidl_return);

    binder::Status createUserKey(int32_t userId, int32_t userSerial, bool ephemeral);
    binder::Status destroyUserKey(int32_t userId);

    binder::Status addUserKeyAuth(int32_t userId, int32_t userSerial,
            const std::string& token, const std::string& secret);
    binder::Status fixateNewestUserKeyAuth(int32_t userId);

    binder::Status unlockUserKey(int32_t userId, int32_t userSerial,
            const std::string& token, const std::string& secret);
    binder::Status lockUserKey(int32_t userId);

    binder::Status prepareUserStorage(const std::unique_ptr<std::string>& uuid,
            int32_t userId, int32_t userSerial, int32_t flags);
    binder::Status destroyUserStorage(const std::unique_ptr<std::string>& uuid,
            int32_t userId, int32_t flags);

    binder::Status secdiscard(const std::string& path);
};

}  // namespace vold
}  // namespace android

#endif  // _VOLD_NATIVE_SERVICE_H_
