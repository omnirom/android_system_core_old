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
#include <hardware/hardware.h>
#include <hardware/keymaster1.h>
#include <hardware/keymaster2.h>
#include <keymaster/keymaster_configuration.h>

namespace android {
namespace vold {

class IKeymasterDevice {
  public:
    IKeymasterDevice() {}
    virtual ~IKeymasterDevice() {}
    virtual keymaster_error_t generate_key(const keymaster_key_param_set_t* params,
                                           keymaster_key_blob_t* key_blob) const = 0;
    virtual keymaster_error_t delete_key(const keymaster_key_blob_t* key) const = 0;
    virtual keymaster_error_t upgrade_key(const keymaster_key_blob_t* key_to_upgrade,
                                         const keymaster_key_param_set_t* upgrade_params,
                                         keymaster_key_blob_t* upgraded_key) const = 0;
    virtual keymaster_error_t begin(keymaster_purpose_t purpose, const keymaster_key_blob_t* key,
                                    const keymaster_key_param_set_t* in_params,
                                    keymaster_key_param_set_t* out_params,
                                    keymaster_operation_handle_t* operation_handle) const = 0;
    virtual keymaster_error_t update(keymaster_operation_handle_t operation_handle,
                                     const keymaster_key_param_set_t* in_params,
                                     const keymaster_blob_t* input, size_t* input_consumed,
                                     keymaster_key_param_set_t* out_params,
                                     keymaster_blob_t* output) const = 0;
    virtual keymaster_error_t finish(keymaster_operation_handle_t operation_handle,
                                     const keymaster_key_param_set_t* in_params,
                                     const keymaster_blob_t* signature,
                                     keymaster_key_param_set_t* out_params,
                                     keymaster_blob_t* output) const = 0;
    virtual keymaster_error_t abort(keymaster_operation_handle_t operation_handle) const = 0;

  protected:
    DISALLOW_COPY_AND_ASSIGN(IKeymasterDevice);
};

template <typename T> class KeymasterDevice : public IKeymasterDevice {
  public:
    explicit KeymasterDevice(T* d) : mDevice{d} {}
    keymaster_error_t generate_key(const keymaster_key_param_set_t* params,
                                   keymaster_key_blob_t* key_blob) const override final {
        return mDevice->generate_key(mDevice, params, key_blob, nullptr);
    }
    keymaster_error_t delete_key(const keymaster_key_blob_t* key) const override final {
        if (mDevice->delete_key == nullptr) return KM_ERROR_OK;
        return mDevice->delete_key(mDevice, key);
    }
    keymaster_error_t begin(keymaster_purpose_t purpose, const keymaster_key_blob_t* key,
                            const keymaster_key_param_set_t* in_params,
                            keymaster_key_param_set_t* out_params,
                            keymaster_operation_handle_t* operation_handle) const override final {
        return mDevice->begin(mDevice, purpose, key, in_params, out_params, operation_handle);
    }
    keymaster_error_t update(keymaster_operation_handle_t operation_handle,
                             const keymaster_key_param_set_t* in_params,
                             const keymaster_blob_t* input, size_t* input_consumed,
                             keymaster_key_param_set_t* out_params,
                             keymaster_blob_t* output) const override final {
        return mDevice->update(mDevice, operation_handle, in_params, input, input_consumed,
                               out_params, output);
    }
    keymaster_error_t abort(keymaster_operation_handle_t operation_handle) const override final {
        return mDevice->abort(mDevice, operation_handle);
    }

  protected:
    T* const mDevice;
};

class Keymaster1Device : public KeymasterDevice<keymaster1_device_t> {
  public:
    explicit Keymaster1Device(keymaster1_device_t* d) : KeymasterDevice<keymaster1_device_t>{d} {}
    ~Keymaster1Device() override final { keymaster1_close(mDevice); }
    keymaster_error_t upgrade_key(const keymaster_key_blob_t* key_to_upgrade,
                                  const keymaster_key_param_set_t* upgrade_params,
                                  keymaster_key_blob_t* upgraded_key) const override final {
        return KM_ERROR_UNIMPLEMENTED;
    }
    keymaster_error_t finish(keymaster_operation_handle_t operation_handle,
                             const keymaster_key_param_set_t* in_params,
                             const keymaster_blob_t* signature,
                             keymaster_key_param_set_t* out_params,
                             keymaster_blob_t* output) const override final {
        return mDevice->finish(mDevice, operation_handle, in_params, signature, out_params, output);
    }
};

class Keymaster2Device : public KeymasterDevice<keymaster2_device_t> {
  public:
    explicit Keymaster2Device(keymaster2_device_t* d) : KeymasterDevice<keymaster2_device_t>{d} {}
    ~Keymaster2Device() override final { keymaster2_close(mDevice); }
    keymaster_error_t upgrade_key(const keymaster_key_blob_t* key_to_upgrade,
                                  const keymaster_key_param_set_t* upgrade_params,
                                  keymaster_key_blob_t* upgraded_key) const override final {
        return mDevice->upgrade_key(mDevice, key_to_upgrade, upgrade_params, upgraded_key);
    }
    keymaster_error_t finish(keymaster_operation_handle_t operation_handle,
                             const keymaster_key_param_set_t* in_params,
                             const keymaster_blob_t* signature,
                             keymaster_key_param_set_t* out_params,
                             keymaster_blob_t* output) const override final {
        return mDevice->finish(mDevice, operation_handle, in_params, nullptr, signature, out_params,
                               output);
    }
};

KeymasterOperation::~KeymasterOperation() {
    if (mDevice) mDevice->abort(mOpHandle);
}

bool KeymasterOperation::updateCompletely(const std::string& input, std::string* output) {
    output->clear();
    auto it = input.begin();
    while (it != input.end()) {
        size_t toRead = static_cast<size_t>(input.end() - it);
        keymaster_blob_t inputBlob{reinterpret_cast<const uint8_t*>(&*it), toRead};
        keymaster_blob_t outputBlob;
        size_t inputConsumed;
        auto error =
            mDevice->update(mOpHandle, nullptr, &inputBlob, &inputConsumed, nullptr, &outputBlob);
        if (error != KM_ERROR_OK) {
            LOG(ERROR) << "update failed, code " << error;
            mDevice = nullptr;
            return false;
        }
        output->append(reinterpret_cast<const char*>(outputBlob.data), outputBlob.data_length);
        free(const_cast<uint8_t*>(outputBlob.data));
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
    keymaster_blob_t outputBlob;
    auto error = mDevice->finish(mOpHandle, nullptr, nullptr, nullptr,
        output ? &outputBlob : nullptr);
    mDevice = nullptr;
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "finish failed, code " << error;
        return false;
    }
    if (output) {
        output->assign(reinterpret_cast<const char*>(outputBlob.data), outputBlob.data_length);
        free(const_cast<uint8_t*>(outputBlob.data));
    }
    return true;
}

Keymaster::Keymaster() {
    mDevice = nullptr;
    const hw_module_t* module;
    int ret = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &module);
    if (ret != 0) {
        LOG(ERROR) << "hw_get_module_by_class returned " << ret;
        return;
    }
    LOG(DEBUG) << "module_api_version is " << module->module_api_version;
    if (module->module_api_version == KEYMASTER_MODULE_API_VERSION_1_0) {
        keymaster1_device_t* device;
        ret = keymaster1_open(module, &device);
        if (ret != 0) {
            LOG(ERROR) << "keymaster1_open returned " << ret;
            return;
        }
        mDevice = std::make_shared<Keymaster1Device>(device);
    } else if (module->module_api_version == KEYMASTER_MODULE_API_VERSION_2_0) {
        keymaster2_device_t* device;
        ret = keymaster2_open(module, &device);
        if (ret != 0) {
            LOG(ERROR) << "keymaster2_open returned " << ret;
            return;
        }
        auto error = ConfigureDevice(device);
        if (error != KM_ERROR_OK) {
            LOG(ERROR) << "ConfigureDevice returned " << error;
            return;
        }
        mDevice = std::make_shared<Keymaster2Device>(device);
    } else {
        LOG(ERROR) << "module_api_version is " << module->module_api_version;
        return;
    }
}

bool Keymaster::generateKey(const keymaster::AuthorizationSet& inParams, std::string* key) {
    keymaster_key_blob_t keyBlob;
    auto error = mDevice->generate_key(&inParams, &keyBlob);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "generate_key failed, code " << error;
        return false;
    }
    key->assign(reinterpret_cast<const char*>(keyBlob.key_material), keyBlob.key_material_size);
    free(const_cast<uint8_t*>(keyBlob.key_material));
    return true;
}

bool Keymaster::deleteKey(const std::string& key) {
    keymaster_key_blob_t keyBlob{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    auto error = mDevice->delete_key(&keyBlob);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "delete_key failed, code " << error;
        return false;
    }
    return true;
}

bool Keymaster::upgradeKey(const std::string& oldKey, const AuthorizationSet& inParams,
                           std::string* newKey) {
    keymaster_key_blob_t oldKeyBlob{reinterpret_cast<const uint8_t*>(oldKey.data()), oldKey.size()};
    keymaster_key_blob_t newKeyBlob;
    auto error = mDevice->upgrade_key(&oldKeyBlob, &inParams, &newKeyBlob);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "upgrade_key failed, code " << error;
        return false;
    }
    newKey->assign(reinterpret_cast<const char*>(newKeyBlob.key_material),
                   newKeyBlob.key_material_size);
    free(const_cast<uint8_t*>(newKeyBlob.key_material));
    return true;
}

KeymasterOperation Keymaster::begin(keymaster_purpose_t purpose, const std::string& key,
                                    const keymaster::AuthorizationSet& inParams,
                                    keymaster::AuthorizationSet* outParams) {
    keymaster_key_blob_t keyBlob{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    keymaster_operation_handle_t mOpHandle;
    keymaster_key_param_set_t outParams_set;
    auto error = mDevice->begin(purpose, &keyBlob, &inParams,
        outParams ? &outParams_set : nullptr, &mOpHandle);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "begin failed, code " << error;
        return KeymasterOperation(error);
    }
    if (outParams) {
        outParams->Clear();
        outParams->push_back(outParams_set);
        keymaster_free_param_set(&outParams_set);
    }
    return KeymasterOperation(mDevice, mOpHandle);
}

}  // namespace vold
}  // namespace android
