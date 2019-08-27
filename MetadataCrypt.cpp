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

#include "MetadataCrypt.h"
#include "KeyBuffer.h"

#include <algorithm>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <cutils/fs.h>
#include <fs_mgr.h>
#include <libdm/dm.h>

#include "Checkpoint.h"
#include "EncryptInplace.h"
#include "KeyStorage.h"
#include "KeyUtil.h"
#include "Keymaster.h"
#include "Utils.h"
#include "VoldUtil.h"

#define TABLE_LOAD_RETRIES 10

using android::fs_mgr::FstabEntry;
using android::fs_mgr::GetEntryForMountPoint;
using android::vold::KeyBuffer;
using namespace android::dm;

static const std::string kDmNameUserdata = "userdata";

static const char* kFn_keymaster_key_blob = "keymaster_key_blob";
static const char* kFn_keymaster_key_blob_upgraded = "keymaster_key_blob_upgraded";

static bool mount_via_fs_mgr(const char* mount_point, const char* blk_device) {
    // fs_mgr_do_mount runs fsck. Use setexeccon to run trusted
    // partitions in the fsck domain.
    if (setexeccon(android::vold::sFsckContext)) {
        PLOG(ERROR) << "Failed to setexeccon";
        return false;
    }
    auto mount_rc = fs_mgr_do_mount(&fstab_default, const_cast<char*>(mount_point),
                                    const_cast<char*>(blk_device), nullptr,
                                    android::vold::cp_needsCheckpoint());
    if (setexeccon(nullptr)) {
        PLOG(ERROR) << "Failed to clear setexeccon";
        return false;
    }
    if (mount_rc != 0) {
        LOG(ERROR) << "fs_mgr_do_mount failed with rc " << mount_rc;
        return false;
    }
    LOG(DEBUG) << "Mounted " << mount_point;
    return true;
}

namespace android {
namespace vold {

// Note: It is possible to orphan a key if it is removed before deleting
// Update this once keymaster APIs change, and we have a proper commit.
static void commit_key(const std::string& dir) {
    while (!android::base::WaitForProperty("vold.checkpoint_committed", "1")) {
        LOG(ERROR) << "Wait for boot timed out";
    }
    Keymaster keymaster;
    auto keyPath = dir + "/" + kFn_keymaster_key_blob;
    auto newKeyPath = dir + "/" + kFn_keymaster_key_blob_upgraded;
    std::string key;

    if (!android::base::ReadFileToString(keyPath, &key)) {
        LOG(ERROR) << "Failed to read old key: " << dir;
        return;
    }
    if (rename(newKeyPath.c_str(), keyPath.c_str()) != 0) {
        PLOG(ERROR) << "Unable to move upgraded key to location: " << keyPath;
        return;
    }
    if (!keymaster.deleteKey(key)) {
        LOG(ERROR) << "Key deletion failed during upgrade, continuing anyway: " << dir;
    }
    LOG(INFO) << "Old Key deleted: " << dir;
}

static bool read_key(const FstabEntry& data_rec, bool create_if_absent, KeyBuffer* key) {
    if (data_rec.key_dir.empty()) {
        LOG(ERROR) << "Failed to get key_dir";
        return false;
    }
    std::string key_dir = data_rec.key_dir;
    std::string sKey;
    auto dir = key_dir + "/key";
    LOG(DEBUG) << "key_dir/key: " << dir;
    if (fs_mkdirs(dir.c_str(), 0700)) {
        PLOG(ERROR) << "Creating directories: " << dir;
        return false;
    }
    auto temp = key_dir + "/tmp";
    auto newKeyPath = dir + "/" + kFn_keymaster_key_blob_upgraded;
    /* If we have a leftover upgraded key, delete it.
     * We either failed an update and must return to the old key,
     * or we rebooted before commiting the keys in a freak accident.
     * Either way, we can re-upgrade the key if we need to.
     */
    Keymaster keymaster;
    if (pathExists(newKeyPath)) {
        if (!android::base::ReadFileToString(newKeyPath, &sKey))
            LOG(ERROR) << "Failed to read old key: " << dir;
        else if (!keymaster.deleteKey(sKey))
            LOG(ERROR) << "Old key deletion failed, continuing anyway: " << dir;
        else
            unlink(newKeyPath.c_str());
    }
    bool needs_cp = cp_needsCheckpoint();
    if (!android::vold::retrieveKey(create_if_absent, dir, temp, key, needs_cp)) return false;
    if (needs_cp && pathExists(newKeyPath)) std::thread(commit_key, dir).detach();
    return true;
}

}  // namespace vold
}  // namespace android

static bool get_number_of_sectors(const std::string& real_blkdev, uint64_t* nr_sec) {
    if (android::vold::GetBlockDev512Sectors(real_blkdev, nr_sec) != android::OK) {
        PLOG(ERROR) << "Unable to measure size of " << real_blkdev;
        return false;
    }
    return true;
}

static bool create_crypto_blk_dev(const std::string& dm_name, uint64_t nr_sec,
                                  const std::string& real_blkdev, const KeyBuffer& key,
                                  std::string* crypto_blkdev, bool set_dun) {
    auto& dm = DeviceMapper::Instance();

    KeyBuffer hex_key_buffer;
    if (android::vold::StrToHex(key, hex_key_buffer) != android::OK) {
        LOG(ERROR) << "Failed to turn key to hex";
        return false;
    }
    std::string hex_key(hex_key_buffer.data(), hex_key_buffer.size());

    DmTable table;
    table.Emplace<DmTargetDefaultKey>(0, nr_sec, "AES-256-XTS", hex_key, real_blkdev, 0, set_dun);

    for (int i = 0;; i++) {
        if (dm.CreateDevice(dm_name, table)) {
            break;
        }
        if (i + 1 >= TABLE_LOAD_RETRIES) {
            LOG(ERROR) << "Could not create default-key device " << dm_name;
            return false;
        }
        PLOG(INFO) << "Could not create default-key device, retrying";
        usleep(500000);
    }

    if (!dm.GetDmDevicePathByName(dm_name, crypto_blkdev)) {
        LOG(ERROR) << "Cannot retrieve default-key device status " << dm_name;
        return false;
    }
    return true;
}

bool fscrypt_mount_metadata_encrypted(const std::string& blk_device, const std::string& mount_point,
                                      bool needs_encrypt) {
    LOG(DEBUG) << "fscrypt_mount_metadata_encrypted: " << mount_point << " " << needs_encrypt;
    auto encrypted_state = android::base::GetProperty("ro.crypto.state", "");
    if (encrypted_state != "") {
        LOG(DEBUG) << "fscrypt_enable_crypto got unexpected starting state: " << encrypted_state;
        return false;
    }

    auto data_rec = GetEntryForMountPoint(&fstab_default, mount_point);
    if (!data_rec) {
        LOG(ERROR) << "Failed to get data_rec";
        return false;
    }
    KeyBuffer key;
    if (!read_key(*data_rec, needs_encrypt, &key)) return false;
    uint64_t nr_sec;
    if (!get_number_of_sectors(data_rec->blk_device, &nr_sec)) return false;
    bool set_dun = android::base::GetBoolProperty("ro.crypto.set_dun", false);
    if (!set_dun && data_rec->fs_mgr_flags.checkpoint_blk) {
        LOG(ERROR) << "Block checkpoints and metadata encryption require setdun option!";
        return false;
    }

    std::string crypto_blkdev;
    if (!create_crypto_blk_dev(kDmNameUserdata, nr_sec, blk_device, key, &crypto_blkdev, set_dun))
        return false;

    // FIXME handle the corrupt case
    if (needs_encrypt) {
        LOG(INFO) << "Beginning inplace encryption, nr_sec: " << nr_sec;
        off64_t size_already_done = 0;
        auto rc = cryptfs_enable_inplace(crypto_blkdev.data(), blk_device.data(), nr_sec,
                                         &size_already_done, nr_sec, 0, false);
        if (rc != 0) {
            LOG(ERROR) << "Inplace crypto failed with code: " << rc;
            return false;
        }
        if (static_cast<uint64_t>(size_already_done) != nr_sec) {
            LOG(ERROR) << "Inplace crypto only got up to sector: " << size_already_done;
            return false;
        }
        LOG(INFO) << "Inplace encryption complete";
    }

    LOG(DEBUG) << "Mounting metadata-encrypted filesystem:" << mount_point;
    mount_via_fs_mgr(data_rec->mount_point.c_str(), crypto_blkdev.c_str());
    return true;
}
