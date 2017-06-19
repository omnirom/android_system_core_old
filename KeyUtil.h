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

#ifndef ANDROID_VOLD_KEYUTIL_H
#define ANDROID_VOLD_KEYUTIL_H

#include <string>

namespace android {
namespace vold {

// ext4enc:TODO get this const from somewhere good
const int EXT4_KEY_DESCRIPTOR_SIZE = 8;

// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
constexpr int EXT4_ENCRYPTION_MODE_AES_256_XTS = 1;
constexpr int EXT4_AES_256_XTS_KEY_SIZE = 64;
constexpr int EXT4_MAX_KEY_SIZE = 64;
struct ext4_encryption_key {
    uint32_t mode;
    char raw[EXT4_MAX_KEY_SIZE];
    uint32_t size;
};

bool randomKey(std::string* key);
bool installKey(const std::string& key, std::string* raw_ref);
bool evictKey(const std::string& raw_ref);
bool retrieveAndInstallKey(bool create_if_absent, const std::string& key_path,
                           const std::string& tmp_path, std::string* key_ref);
bool retrieveKey(bool create_if_absent, const std::string& key_path,
                 const std::string& tmp_path, std::string* key);

}  // namespace vold
}  // namespace android

#endif
