/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "VolumeEncryption.h"

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "KeyBuffer.h"
#include "KeyUtil.h"
#include "MetadataCrypt.h"
#include "cryptfs.h"

namespace android {
namespace vold {

enum class VolumeMethod { kFailed, kCrypt, kDefaultKey };

static VolumeMethod lookup_volume_method() {
    constexpr uint64_t pre_gki_level = 29;
    auto first_api_level =
            android::base::GetUintProperty<uint64_t>("ro.product.first_api_level", 0);
    auto method = android::base::GetProperty("ro.crypto.volume.metadata.method", "default");
    if (method == "default") {
        return first_api_level > pre_gki_level ? VolumeMethod::kDefaultKey : VolumeMethod::kCrypt;
    } else if (method == "dm-default-key") {
        return VolumeMethod::kDefaultKey;
    } else if (method == "dm-crypt") {
        if (first_api_level > pre_gki_level) {
            LOG(ERROR) << "volume encryption method dm-crypt cannot be used, "
                          "ro.product.first_api_level = "
                       << first_api_level;
            return VolumeMethod::kFailed;
        }
        return VolumeMethod::kCrypt;
    } else {
        LOG(ERROR) << "Unknown volume encryption method: " << method;
        return VolumeMethod::kFailed;
    }
}

static VolumeMethod volume_method() {
    static VolumeMethod method = lookup_volume_method();
    return method;
}

bool generate_volume_key(android::vold::KeyBuffer* key) {
    KeyGeneration gen;
    switch (volume_method()) {
        case VolumeMethod::kFailed:
            LOG(ERROR) << "Volume encryption setup failed";
            return false;
        case VolumeMethod::kCrypt:
            gen = cryptfs_get_keygen();
            break;
        case VolumeMethod::kDefaultKey:
            if (!defaultkey_volume_keygen(&gen)) return false;
            break;
    }
    if (!generateStorageKey(gen, key)) return false;
    return true;
}

bool setup_ext_volume(const std::string& label, const std::string& blk_device,
                      const android::vold::KeyBuffer& key, std::string* out_crypto_blkdev) {
    switch (volume_method()) {
        case VolumeMethod::kFailed:
            LOG(ERROR) << "Volume encryption setup failed";
            return false;
        case VolumeMethod::kCrypt:
            return cryptfs_setup_ext_volume(label.c_str(), blk_device.c_str(), key,
                                            out_crypto_blkdev) == 0;
        case VolumeMethod::kDefaultKey:
            return defaultkey_setup_ext_volume(label, blk_device, key, out_crypto_blkdev);
    }
}

}  // namespace vold
}  // namespace android
