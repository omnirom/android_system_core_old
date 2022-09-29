/*
 * Copyright (C) 2010 The Android Open Source Project
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

//
// This file contains the implementation of the dm-crypt volume metadata
// encryption method, which is deprecated.  Devices that launched with Android
// 11 or higher use a different method instead.  For details, see
// https://source.android.com/security/encryption/metadata#configuration-on-adoptable-storage
//

#define LOG_TAG "Cryptfs"

#include "cryptfs.h"

#include "CryptoType.h"
#include "Utils.h"

#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <cutils/properties.h>
#include <libdm/dm.h>
#include <log/log.h>

#include <chrono>

using android::base::ParseUint;
using android::vold::CryptoType;
using android::vold::KeyBuffer;
using android::vold::KeyGeneration;
using namespace android::dm;
using namespace android::vold;
using namespace std::chrono_literals;

#define MAX_KEY_LEN 48

#define TABLE_LOAD_RETRIES 10

constexpr CryptoType aes_128_cbc = CryptoType()
                                           .set_config_name("AES-128-CBC")
                                           .set_kernel_name("aes-cbc-essiv:sha256")
                                           .set_keysize(16);

constexpr CryptoType supported_crypto_types[] = {aes_128_cbc, android::vold::adiantum};

static_assert(validateSupportedCryptoTypes(MAX_KEY_LEN, supported_crypto_types,
                                           array_length(supported_crypto_types)),
              "We have a CryptoType with keysize > MAX_KEY_LEN or which was "
              "incompletely constructed.");

static const CryptoType& get_crypto_type() {
    // We only want to parse this read-only property once.  But we need to wait
    // until the system is initialized before we can read it.  So we use a static
    // scoped within this function to get it only once.
    static CryptoType crypto_type =
            lookup_crypto_algorithm(supported_crypto_types, array_length(supported_crypto_types),
                                    aes_128_cbc, "ro.crypto.fde_algorithm");
    return crypto_type;
}

const KeyGeneration cryptfs_get_keygen() {
    return KeyGeneration{get_crypto_type().get_keysize(), true, false};
}

/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
static void convert_key_to_hex_ascii(const KeyBuffer& key, char* key_ascii) {
    unsigned int i, a;
    unsigned char nibble;

    for (i = 0, a = 0; i < key.size(); i++, a += 2) {
        /* For each byte, write out two ascii hex digits */
        nibble = (key[i] >> 4) & 0xf;
        key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

        nibble = key[i] & 0xf;
        key_ascii[a + 1] = nibble + (nibble > 9 ? 0x37 : 0x30);
    }

    /* Add the null termination */
    key_ascii[a] = '\0';
}

/*
 * Called by vold when it's asked to mount an encrypted external
 * storage volume. The incoming partition has no crypto header/footer,
 * as any metadata is been stored in a separate, small partition.  We
 * assume it must be using our same crypt type and keysize.
 */
int cryptfs_setup_ext_volume(const char* label, const char* real_blkdev, const KeyBuffer& key,
                             std::string* out_crypto_blkdev) {
    auto crypto_type = get_crypto_type();
    if (key.size() != crypto_type.get_keysize()) {
        SLOGE("Raw keysize %zu does not match crypt keysize %zu", key.size(),
              crypto_type.get_keysize());
        return -1;
    }
    uint64_t nr_sec = 0;
    if (android::vold::GetBlockDev512Sectors(real_blkdev, &nr_sec) != android::OK) {
        SLOGE("Failed to get size of %s: %s", real_blkdev, strerror(errno));
        return -1;
    }

    constexpr char DM_CRYPT_SECTOR_SIZE[] = "ro.crypto.fde_sector_size";
    char value[PROPERTY_VALUE_MAX];
    unsigned int sector_size = 0;

    if (property_get(DM_CRYPT_SECTOR_SIZE, value, "") > 0) {
        if (!ParseUint(value, &sector_size) || sector_size < 512 || sector_size > 4096 ||
            (sector_size & (sector_size - 1)) != 0) {
            SLOGE("Invalid value for %s: %s.  Must be >= 512, <= 4096, and a power of 2\n",
                  DM_CRYPT_SECTOR_SIZE, value);
            return -1;
        }
    }

    // Round the crypto device size down to a crypto sector boundary.
    if (sector_size > 0) {
        nr_sec &= ~((sector_size / 512) - 1);
    }

    auto& dm = DeviceMapper::Instance();
    // We need two ASCII characters to represent each byte, and need space for
    // the '\0' terminator.
    char key_ascii[MAX_KEY_LEN * 2 + 1];
    convert_key_to_hex_ascii(key, key_ascii);

    auto target = std::make_unique<DmTargetCrypt>(0, nr_sec, crypto_type.get_kernel_name(),
                                                  key_ascii, 0, real_blkdev, 0);
    target->AllowDiscards();

    if (IsFbeEnabled() &&
        android::base::GetBoolProperty("ro.crypto.allow_encrypt_override", false)) {
        target->AllowEncryptOverride();
    }

    // Append the parameters to make dm-crypt use the specified crypto sector size.
    if (sector_size > 0) {
        target->SetSectorSize(sector_size);
        // With this option, IVs will match the sector numbering, instead
        // of being hard-coded to being based on 512-byte sectors.
        target->SetIvLargeSectors();
    }

    DmTable table;
    table.AddTarget(std::move(target));

    int load_count = 1;
    while (load_count < TABLE_LOAD_RETRIES) {
        if (dm.CreateDevice(label, table)) {
            break;
        }
        load_count++;
    }

    if (load_count >= TABLE_LOAD_RETRIES) {
        SLOGE("Cannot load dm-crypt mapping table.\n");
        return -1;
    }
    if (load_count > 1) {
        SLOGI("Took %d tries to load dmcrypt table.\n", load_count);
    }

    if (!dm.GetDmDevicePathByName(label, out_crypto_blkdev)) {
        SLOGE("Cannot determine dm-crypt path for %s.\n", label);
        return -1;
    }

    /* Ensure the dm device has been created before returning. */
    if (android::vold::WaitForFile(out_crypto_blkdev->c_str(), 1s) < 0) {
        // WaitForFile generates a suitable log message
        return -1;
    }
    return 0;
}
