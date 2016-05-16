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

#ifndef ANDROID_VOLD_KEYMASTER_H
#define ANDROID_VOLD_KEYMASTER_H

#include <memory>
#include <string>
#include <utility>

#include <keymaster/authorization_set.h>

namespace android {
namespace vold {

using namespace keymaster;

// C++ wrappers to the Keymaster C interface.
// This is tailored to the needs of KeyStorage, but could be extended to be
// a more general interface.

// Class that wraps a keymaster1_device_t or keymaster2_device_t and provides methods
// they have in common. Also closes the device on destruction.
class IKeymasterDevice;

// Wrapper for a keymaster_operation_handle_t representing an
// ongoing Keymaster operation.  Aborts the operation
// in the destructor if it is unfinished. Methods log failures
// to LOG(ERROR).
class KeymasterOperation {
  public:
    ~KeymasterOperation();
    // Is this instance valid? This is false if creation fails, and becomes
    // false on finish or if an update fails.
    explicit operator bool() { return mError == KM_ERROR_OK; }
    keymaster_error_t error() { return mError; }
    // Call "update" repeatedly until all of the input is consumed, and
    // concatenate the output. Return true on success.
    bool updateCompletely(const std::string& input, std::string* output);
    // Finish and write the output to this string, unless pointer is null.
    bool finish(std::string* output);
    // Move constructor
    KeymasterOperation(KeymasterOperation&& rhs) {
        mDevice = std::move(rhs.mDevice);
        mOpHandle = std::move(rhs.mOpHandle);
        mError = std::move(rhs.mError);
    }
    // Construct an object in an error state for error returns
    KeymasterOperation() : KeymasterOperation(KM_ERROR_UNKNOWN_ERROR) {}

  private:
    KeymasterOperation(std::shared_ptr<IKeymasterDevice> d, keymaster_operation_handle_t h)
        : mDevice{d}, mOpHandle{h}, mError {KM_ERROR_OK} {}
    KeymasterOperation(keymaster_error_t error)
        : mDevice{nullptr}, mOpHandle{static_cast<keymaster_operation_handle_t>(0)},
          mError {error} {}
    std::shared_ptr<IKeymasterDevice> mDevice;
    keymaster_operation_handle_t mOpHandle;
    keymaster_error_t mError;
    DISALLOW_COPY_AND_ASSIGN(KeymasterOperation);
    friend class Keymaster;
};

// Wrapper for a Keymaster device for methods that start a KeymasterOperation or are not
// part of one.
class Keymaster {
  public:
    Keymaster();
    // false if we failed to open the keymaster device.
    explicit operator bool() { return mDevice != nullptr; }
    // Generate a key in the keymaster from the given params.
    bool generateKey(const AuthorizationSet& inParams, std::string* key);
    // If the keymaster supports it, permanently delete a key.
    bool deleteKey(const std::string& key);
    // Replace stored key blob in response to KM_ERROR_KEY_REQUIRES_UPGRADE.
    bool upgradeKey(const std::string& oldKey, const AuthorizationSet& inParams,
                    std::string* newKey);
    // Begin a new cryptographic operation, collecting output parameters if pointer is non-null
    KeymasterOperation begin(keymaster_purpose_t purpose, const std::string& key,
                             const AuthorizationSet& inParams, AuthorizationSet* outParams);

  private:
    std::shared_ptr<IKeymasterDevice> mDevice;
    DISALLOW_COPY_AND_ASSIGN(Keymaster);
};

template <keymaster_tag_t Tag>
inline AuthorizationSetBuilder& addStringParam(AuthorizationSetBuilder&& params,
                                               TypedTag<KM_BYTES, Tag> tag,
                                               const std::string& val) {
    return params.Authorization(tag, val.data(), val.size());
}

template <keymaster_tag_t Tag>
inline void addStringParam(AuthorizationSetBuilder* params, TypedTag<KM_BYTES, Tag> tag,
                           const std::string& val) {
    params->Authorization(tag, val.data(), val.size());
}

}  // namespace vold
}  // namespace android

#endif
