/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "Keymaster.h"

#include <android-base/logging.h>
#include <keystore/keymaster_tags.h>
#include <keystore/authorization_set.h>
#include <keystore/keystore_hidl_support.h>

using namespace ::keystore;

namespace android {
namespace vold {

KeymasterOperation::~KeymasterOperation() {
    if (mDevice.get()) mDevice->abort(mOpHandle);
}

bool KeymasterOperation::updateCompletely(const std::string& input, std::string* output) {
    output->clear();
    auto it = input.begin();
    uint32_t inputConsumed;

    ErrorCode km_error;
    auto hidlCB = [&] (ErrorCode ret, uint32_t _inputConsumed,
            const hidl_vec<KeyParameter>& /*ignored*/, const hidl_vec<uint8_t>& _output) {
        km_error = ret;
        if (km_error != ErrorCode::OK) return;
        inputConsumed = _inputConsumed;
        if (output)
            output->append(reinterpret_cast<const char*>(&_output[0]), _output.size());
    };

    while (it != input.end()) {
        size_t toRead = static_cast<size_t>(input.end() - it);
        auto inputBlob = blob2hidlVec(reinterpret_cast<const uint8_t*>(&*it), toRead);
        auto error = mDevice->update(mOpHandle, hidl_vec<KeyParameter>(), inputBlob, hidlCB);
        if (!error.isOk()) {
            LOG(ERROR) << "update failed: " << error.description();
            mDevice = nullptr;
            return false;
        }
        if (km_error != ErrorCode::OK) {
            LOG(ERROR) << "update failed, code " << uint32_t(km_error);
            mDevice = nullptr;
            return false;
        }
        if (inputConsumed > toRead) {
            LOG(ERROR) << "update reported too much input consumed";
            mDevice = nullptr;
            return false;
        }
        it += inputConsumed;
    }
    return true;
}

bool KeymasterOperation::finish(std::string* output) {
    ErrorCode km_error;
    auto hidlCb = [&] (ErrorCode ret, const hidl_vec<KeyParameter>& /*ignored*/,
            const hidl_vec<uint8_t>& _output) {
        km_error = ret;
        if (km_error != ErrorCode::OK) return;
        if (output)
            output->assign(reinterpret_cast<const char*>(&_output[0]), _output.size());
    };
    auto error = mDevice->finish(mOpHandle, hidl_vec<KeyParameter>(), hidl_vec<uint8_t>(),
            hidl_vec<uint8_t>(), hidlCb);
    mDevice = nullptr;
    if (!error.isOk()) {
        LOG(ERROR) << "finish failed: " << error.description();
        return false;
    }
    if (km_error != ErrorCode::OK) {
        LOG(ERROR) << "finish failed, code " << uint32_t(km_error);
        return false;
    }
    return true;
}

Keymaster::Keymaster() {
    mDevice = ::android::hardware::keymaster::V3_0::IKeymasterDevice::getService("keymaster");
}

bool Keymaster::generateKey(const AuthorizationSet& inParams, std::string* key) {
    ErrorCode km_error;
    auto hidlCb = [&] (ErrorCode ret, const hidl_vec<uint8_t>& keyBlob,
            const KeyCharacteristics& /*ignored*/) {
        km_error = ret;
        if (km_error != ErrorCode::OK) return;
        if (key)
            key->assign(reinterpret_cast<const char*>(&keyBlob[0]), keyBlob.size());
    };

    auto error = mDevice->generateKey(inParams.hidl_data(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "generate_key failed: " << error.description();
        return false;
    }
    if (km_error != ErrorCode::OK) {
        LOG(ERROR) << "generate_key failed, code " << int32_t(km_error);
        return false;
    }
    return true;
}

bool Keymaster::deleteKey(const std::string& key) {
    auto keyBlob = blob2hidlVec(key);
    auto error = mDevice->deleteKey(keyBlob);
    if (!error.isOk()) {
        LOG(ERROR) << "delete_key failed: " << error.description();
        return false;
    }
    if (ErrorCode(error) != ErrorCode::OK) {
        LOG(ERROR) << "delete_key failed, code " << uint32_t(ErrorCode(error));
        return false;
    }
    return true;
}

bool Keymaster::upgradeKey(const std::string& oldKey, const AuthorizationSet& inParams,
                           std::string* newKey) {
    auto oldKeyBlob = blob2hidlVec(oldKey);
    ErrorCode km_error;
    auto hidlCb = [&] (ErrorCode ret, const hidl_vec<uint8_t>& upgradedKeyBlob) {
        km_error = ret;
        if (km_error != ErrorCode::OK) return;
        if (newKey)
            newKey->assign(reinterpret_cast<const char*>(&upgradedKeyBlob[0]),
                    upgradedKeyBlob.size());
    };
    auto error = mDevice->upgradeKey(oldKeyBlob, inParams.hidl_data(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "upgrade_key failed: " << error.description();
        return false;
    }
    if (km_error != ErrorCode::OK) {
        LOG(ERROR) << "upgrade_key failed, code " << int32_t(km_error);
        return false;
    }
    return true;
}

KeymasterOperation Keymaster::begin(KeyPurpose purpose, const std::string& key,
                                    const AuthorizationSet& inParams,
                                    AuthorizationSet* outParams) {
    auto keyBlob = blob2hidlVec(key);
    uint64_t mOpHandle;
    ErrorCode km_error;

    auto hidlCb = [&] (ErrorCode ret, const hidl_vec<KeyParameter>& _outParams,
            uint64_t operationHandle) {
        km_error = ret;
        if (km_error != ErrorCode::OK) return;
        if (outParams)
            *outParams = _outParams;
        mOpHandle = operationHandle;
    };

    auto error = mDevice->begin(purpose, keyBlob, inParams.hidl_data(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "begin failed: " << error.description();
        return KeymasterOperation(ErrorCode::UNKNOWN_ERROR);
    }
    if (km_error != ErrorCode::OK) {
        LOG(ERROR) << "begin failed, code " << uint32_t(km_error);
        return KeymasterOperation(km_error);
    }
    return KeymasterOperation(mDevice, mOpHandle);
}

}  // namespace vold
}  // namespace android
