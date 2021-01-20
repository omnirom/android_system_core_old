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

#include "KeyStorage.h"

#include "Checkpoint.h"
#include "Keymaster.h"
#include "ScryptParameters.h"
#include "Utils.h"

#include <algorithm>
#include <thread>
#include <vector>

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include <cutils/properties.h>

#include <hardware/hw_auth_token.h>
#include <keymasterV4_1/authorization_set.h>
#include <keymasterV4_1/keymaster_utils.h>

extern "C" {

#include "crypto_scrypt.h"
}

namespace android {
namespace vold {

const KeyAuthentication kEmptyAuthentication{"", ""};

static constexpr size_t AES_KEY_BYTES = 32;
static constexpr size_t GCM_NONCE_BYTES = 12;
static constexpr size_t GCM_MAC_BYTES = 16;
static constexpr size_t SALT_BYTES = 1 << 4;
static constexpr size_t SECDISCARDABLE_BYTES = 1 << 14;
static constexpr size_t STRETCHED_BYTES = 1 << 6;

static constexpr uint32_t AUTH_TIMEOUT = 30;  // Seconds

static const char* kCurrentVersion = "1";
static const char* kRmPath = "/system/bin/rm";
static const char* kSecdiscardPath = "/system/bin/secdiscard";
static const char* kStretch_none = "none";
static const char* kStretch_nopassword = "nopassword";
static const std::string kStretchPrefix_scrypt = "scrypt ";
static const char* kHashPrefix_secdiscardable = "Android secdiscardable SHA512";
static const char* kHashPrefix_keygen = "Android key wrapping key generation SHA512";
static const char* kFn_encrypted_key = "encrypted_key";
static const char* kFn_keymaster_key_blob = "keymaster_key_blob";
static const char* kFn_keymaster_key_blob_upgraded = "keymaster_key_blob_upgraded";
static const char* kFn_salt = "salt";
static const char* kFn_secdiscardable = "secdiscardable";
static const char* kFn_stretching = "stretching";
static const char* kFn_version = "version";

static bool checkSize(const std::string& kind, size_t actual, size_t expected) {
    if (actual != expected) {
        LOG(ERROR) << "Wrong number of bytes in " << kind << ", expected " << expected << " got "
                   << actual;
        return false;
    }
    return true;
}

static void hashWithPrefix(char const* prefix, const std::string& tohash, std::string* res) {
    SHA512_CTX c;

    SHA512_Init(&c);
    // Personalise the hashing by introducing a fixed prefix.
    // Hashing applications should use personalization except when there is a
    // specific reason not to; see section 4.11 of https://www.schneier.com/skein1.3.pdf
    std::string hashingPrefix = prefix;
    hashingPrefix.resize(SHA512_CBLOCK);
    SHA512_Update(&c, hashingPrefix.data(), hashingPrefix.size());
    SHA512_Update(&c, tohash.data(), tohash.size());
    res->assign(SHA512_DIGEST_LENGTH, '\0');
    SHA512_Final(reinterpret_cast<uint8_t*>(&(*res)[0]), &c);
}

static bool generateKeymasterKey(Keymaster& keymaster, const KeyAuthentication& auth,
                                 const std::string& appId, std::string* key) {
    auto paramBuilder = km::AuthorizationSetBuilder()
                            .AesEncryptionKey(AES_KEY_BYTES * 8)
                            .GcmModeMinMacLen(GCM_MAC_BYTES * 8)
                            .Authorization(km::TAG_APPLICATION_ID, km::support::blob2hidlVec(appId));
    if (auth.token.empty()) {
        LOG(DEBUG) << "Creating key that doesn't need auth token";
        paramBuilder.Authorization(km::TAG_NO_AUTH_REQUIRED);
    } else {
        LOG(DEBUG) << "Auth token required for key";
        if (auth.token.size() != sizeof(hw_auth_token_t)) {
            LOG(ERROR) << "Auth token should be " << sizeof(hw_auth_token_t) << " bytes, was "
                       << auth.token.size() << " bytes";
            return false;
        }
        const hw_auth_token_t* at = reinterpret_cast<const hw_auth_token_t*>(auth.token.data());
        auto user_id = at->user_id;  // Make a copy because at->user_id is unaligned.
        paramBuilder.Authorization(km::TAG_USER_SECURE_ID, user_id);
        paramBuilder.Authorization(km::TAG_USER_AUTH_TYPE, km::HardwareAuthenticatorType::PASSWORD);
        paramBuilder.Authorization(km::TAG_AUTH_TIMEOUT, AUTH_TIMEOUT);
    }

    auto paramsWithRollback = paramBuilder;
    paramsWithRollback.Authorization(km::TAG_ROLLBACK_RESISTANCE);

    // Generate rollback-resistant key if possible.
    return keymaster.generateKey(paramsWithRollback, key) ||
           keymaster.generateKey(paramBuilder, key);
}

bool generateWrappedStorageKey(KeyBuffer* key) {
    Keymaster keymaster;
    if (!keymaster) return false;
    std::string key_temp;
    auto paramBuilder = km::AuthorizationSetBuilder().AesEncryptionKey(AES_KEY_BYTES * 8);
    paramBuilder.Authorization(km::TAG_STORAGE_KEY);
    auto paramsWithRollback = paramBuilder;
    paramsWithRollback.Authorization(km::TAG_ROLLBACK_RESISTANCE);
    if (!keymaster.generateKey(paramsWithRollback, &key_temp)) {
        if (!keymaster.generateKey(paramBuilder, &key_temp)) return false;
    }
    *key = KeyBuffer(key_temp.size());
    memcpy(reinterpret_cast<void*>(key->data()), key_temp.c_str(), key->size());
    return true;
}

bool exportWrappedStorageKey(const KeyBuffer& kmKey, KeyBuffer* key) {
    Keymaster keymaster;
    if (!keymaster) return false;
    std::string key_temp;

    if (!keymaster.exportKey(kmKey, &key_temp)) return false;
    *key = KeyBuffer(key_temp.size());
    memcpy(reinterpret_cast<void*>(key->data()), key_temp.c_str(), key->size());
    return true;
}

static std::pair<km::AuthorizationSet, km::HardwareAuthToken> beginParams(
    const KeyAuthentication& auth, const std::string& appId) {
    auto paramBuilder = km::AuthorizationSetBuilder()
                            .GcmModeMacLen(GCM_MAC_BYTES * 8)
                            .Authorization(km::TAG_APPLICATION_ID, km::support::blob2hidlVec(appId));
    km::HardwareAuthToken authToken;
    if (!auth.token.empty()) {
        LOG(DEBUG) << "Supplying auth token to Keymaster";
        authToken = km::support::hidlVec2AuthToken(km::support::blob2hidlVec(auth.token));
    }
    return {paramBuilder, authToken};
}

static bool readFileToString(const std::string& filename, std::string* result) {
    if (!android::base::ReadFileToString(filename, result)) {
        PLOG(ERROR) << "Failed to read from " << filename;
        return false;
    }
    return true;
}

static bool readRandomBytesOrLog(size_t count, std::string* out) {
    auto status = ReadRandomBytes(count, *out);
    if (status != OK) {
        LOG(ERROR) << "Random read failed with status: " << status;
        return false;
    }
    return true;
}

bool createSecdiscardable(const std::string& filename, std::string* hash) {
    std::string secdiscardable;
    if (!readRandomBytesOrLog(SECDISCARDABLE_BYTES, &secdiscardable)) return false;
    if (!writeStringToFile(secdiscardable, filename)) return false;
    hashWithPrefix(kHashPrefix_secdiscardable, secdiscardable, hash);
    return true;
}

bool readSecdiscardable(const std::string& filename, std::string* hash) {
    std::string secdiscardable;
    if (!readFileToString(filename, &secdiscardable)) return false;
    hashWithPrefix(kHashPrefix_secdiscardable, secdiscardable, hash);
    return true;
}

static std::mutex key_upgrade_lock;

// List of key directories that have had their Keymaster key upgraded during
// this boot and written to "keymaster_key_blob_upgraded", but replacing the old
// key was delayed due to an active checkpoint.  Protected by key_upgrade_lock.
static std::vector<std::string> key_dirs_to_commit;

// Replaces |dir|/keymaster_key_blob with |dir|/keymaster_key_blob_upgraded and
// deletes the old key from Keymaster.
static bool CommitUpgradedKey(Keymaster& keymaster, const std::string& dir) {
    auto blob_file = dir + "/" + kFn_keymaster_key_blob;
    auto upgraded_blob_file = dir + "/" + kFn_keymaster_key_blob_upgraded;

    std::string blob;
    if (!readFileToString(blob_file, &blob)) return false;

    if (rename(upgraded_blob_file.c_str(), blob_file.c_str()) != 0) {
        PLOG(ERROR) << "Failed to rename " << upgraded_blob_file << " to " << blob_file;
        return false;
    }
    // Ensure that the rename is persisted before deleting the Keymaster key.
    if (!FsyncDirectory(dir)) return false;

    if (!keymaster || !keymaster.deleteKey(blob)) {
        LOG(WARNING) << "Failed to delete old key " << blob_file
                     << " from Keymaster; continuing anyway";
        // Continue on, but the space in Keymaster used by the old key won't be freed.
    }
    return true;
}

static void DeferredCommitKeys() {
    android::base::WaitForProperty("vold.checkpoint_committed", "1");
    LOG(INFO) << "Committing upgraded keys";
    Keymaster keymaster;
    if (!keymaster) {
        LOG(ERROR) << "Failed to open Keymaster; old keys won't be deleted from Keymaster";
        // Continue on, but the space in Keymaster used by the old keys won't be freed.
    }
    std::lock_guard<std::mutex> lock(key_upgrade_lock);
    for (auto& dir : key_dirs_to_commit) {
        LOG(INFO) << "Committing upgraded key " << dir;
        CommitUpgradedKey(keymaster, dir);
    }
    key_dirs_to_commit.clear();
}

// Returns true if the Keymaster key in |dir| has already been upgraded and is
// pending being committed.  Assumes that key_upgrade_lock is held.
static bool IsKeyCommitPending(const std::string& dir) {
    for (const auto& dir_to_commit : key_dirs_to_commit) {
        if (IsSameFile(dir, dir_to_commit)) return true;
    }
    return false;
}

// Schedules the upgraded Keymaster key in |dir| to be committed later.
// Assumes that key_upgrade_lock is held.
static void ScheduleKeyCommit(const std::string& dir) {
    if (key_dirs_to_commit.empty()) std::thread(DeferredCommitKeys).detach();
    key_dirs_to_commit.push_back(dir);
}

static void CancelPendingKeyCommit(const std::string& dir) {
    std::lock_guard<std::mutex> lock(key_upgrade_lock);
    for (auto it = key_dirs_to_commit.begin(); it != key_dirs_to_commit.end(); it++) {
        if (IsSameFile(*it, dir)) {
            LOG(DEBUG) << "Cancelling pending commit of upgraded key " << dir
                       << " because it is being destroyed";
            key_dirs_to_commit.erase(it);
            break;
        }
    }
}

// Deletes a leftover upgraded key, if present.  An upgraded key can be left
// over if an update failed, or if we rebooted before committing the key in a
// freak accident.  Either way, we can re-upgrade the key if we need to.
static void DeleteUpgradedKey(Keymaster& keymaster, const std::string& path) {
    if (pathExists(path)) {
        LOG(DEBUG) << "Deleting leftover upgraded key " << path;
        std::string blob;
        if (!android::base::ReadFileToString(path, &blob)) {
            LOG(WARNING) << "Failed to read leftover upgraded key " << path
                         << "; continuing anyway";
        } else if (!keymaster.deleteKey(blob)) {
            LOG(WARNING) << "Failed to delete leftover upgraded key " << path
                         << " from Keymaster; continuing anyway";
        }
        if (unlink(path.c_str()) != 0) {
            LOG(WARNING) << "Failed to unlink leftover upgraded key " << path
                         << "; continuing anyway";
        }
    }
}

// Begins a Keymaster operation using the key stored in |dir|.
static KeymasterOperation BeginKeymasterOp(Keymaster& keymaster, const std::string& dir,
                                           km::KeyPurpose purpose,
                                           const km::AuthorizationSet& keyParams,
                                           const km::AuthorizationSet& opParams,
                                           const km::HardwareAuthToken& authToken,
                                           km::AuthorizationSet* outParams) {
    km::AuthorizationSet inParams(keyParams);
    inParams.append(opParams.begin(), opParams.end());

    auto blob_file = dir + "/" + kFn_keymaster_key_blob;
    auto upgraded_blob_file = dir + "/" + kFn_keymaster_key_blob_upgraded;

    std::lock_guard<std::mutex> lock(key_upgrade_lock);

    std::string blob;
    bool already_upgraded = IsKeyCommitPending(dir);
    if (already_upgraded) {
        LOG(DEBUG)
                << blob_file
                << " was already upgraded and is waiting to be committed; using the upgraded blob";
        if (!readFileToString(upgraded_blob_file, &blob)) return KeymasterOperation();
    } else {
        DeleteUpgradedKey(keymaster, upgraded_blob_file);
        if (!readFileToString(blob_file, &blob)) return KeymasterOperation();
    }

    auto opHandle = keymaster.begin(purpose, blob, inParams, authToken, outParams);
    if (opHandle) return opHandle;
    if (opHandle.errorCode() != km::ErrorCode::KEY_REQUIRES_UPGRADE) return opHandle;

    if (already_upgraded) {
        LOG(ERROR) << "Unexpected case; already-upgraded key " << upgraded_blob_file
                   << " still requires upgrade";
        return KeymasterOperation();
    }
    LOG(INFO) << "Upgrading key: " << blob_file;
    if (!keymaster.upgradeKey(blob, keyParams, &blob)) return KeymasterOperation();
    if (!writeStringToFile(blob, upgraded_blob_file)) return KeymasterOperation();
    if (cp_needsCheckpoint()) {
        LOG(INFO) << "Wrote upgraded key to " << upgraded_blob_file
                  << "; delaying commit due to checkpoint";
        ScheduleKeyCommit(dir);
    } else {
        if (!CommitUpgradedKey(keymaster, dir)) return KeymasterOperation();
        LOG(INFO) << "Key upgraded: " << blob_file;
    }

    return keymaster.begin(purpose, blob, inParams, authToken, outParams);
}

static bool encryptWithKeymasterKey(Keymaster& keymaster, const std::string& dir,
                                    const km::AuthorizationSet& keyParams,
                                    const km::HardwareAuthToken& authToken,
                                    const KeyBuffer& message, std::string* ciphertext) {
    km::AuthorizationSet opParams;
    km::AuthorizationSet outParams;
    auto opHandle = BeginKeymasterOp(keymaster, dir, km::KeyPurpose::ENCRYPT, keyParams, opParams,
                                     authToken, &outParams);
    if (!opHandle) return false;
    auto nonceBlob = outParams.GetTagValue(km::TAG_NONCE);
    if (!nonceBlob.isOk()) {
        LOG(ERROR) << "GCM encryption but no nonce generated";
        return false;
    }
    // nonceBlob here is just a pointer into existing data, must not be freed
    std::string nonce(reinterpret_cast<const char*>(&nonceBlob.value()[0]),
                      nonceBlob.value().size());
    if (!checkSize("nonce", nonce.size(), GCM_NONCE_BYTES)) return false;
    std::string body;
    if (!opHandle.updateCompletely(message, &body)) return false;

    std::string mac;
    if (!opHandle.finish(&mac)) return false;
    if (!checkSize("mac", mac.size(), GCM_MAC_BYTES)) return false;
    *ciphertext = nonce + body + mac;
    return true;
}

static bool decryptWithKeymasterKey(Keymaster& keymaster, const std::string& dir,
                                    const km::AuthorizationSet& keyParams,
                                    const km::HardwareAuthToken& authToken,
                                    const std::string& ciphertext, KeyBuffer* message) {
    auto nonce = ciphertext.substr(0, GCM_NONCE_BYTES);
    auto bodyAndMac = ciphertext.substr(GCM_NONCE_BYTES);
    auto opParams = km::AuthorizationSetBuilder().Authorization(km::TAG_NONCE,
                                                                km::support::blob2hidlVec(nonce));
    auto opHandle = BeginKeymasterOp(keymaster, dir, km::KeyPurpose::DECRYPT, keyParams, opParams,
                                     authToken, nullptr);
    if (!opHandle) return false;
    if (!opHandle.updateCompletely(bodyAndMac, message)) return false;
    if (!opHandle.finish(nullptr)) return false;
    return true;
}

static std::string getStretching(const KeyAuthentication& auth) {
    if (!auth.usesKeymaster()) {
        return kStretch_none;
    } else if (auth.secret.empty()) {
        return kStretch_nopassword;
    } else {
        char paramstr[PROPERTY_VALUE_MAX];

        property_get(SCRYPT_PROP, paramstr, SCRYPT_DEFAULTS);
        return std::string() + kStretchPrefix_scrypt + paramstr;
    }
}

static bool stretchingNeedsSalt(const std::string& stretching) {
    return stretching != kStretch_nopassword && stretching != kStretch_none;
}

static bool stretchSecret(const std::string& stretching, const std::string& secret,
                          const std::string& salt, std::string* stretched) {
    if (stretching == kStretch_nopassword) {
        if (!secret.empty()) {
            LOG(WARNING) << "Password present but stretching is nopassword";
            // Continue anyway
        }
        stretched->clear();
    } else if (stretching == kStretch_none) {
        *stretched = secret;
    } else if (std::equal(kStretchPrefix_scrypt.begin(), kStretchPrefix_scrypt.end(),
                          stretching.begin())) {
        int Nf, rf, pf;
        if (!parse_scrypt_parameters(stretching.substr(kStretchPrefix_scrypt.size()).c_str(), &Nf,
                                     &rf, &pf)) {
            LOG(ERROR) << "Unable to parse scrypt params in stretching: " << stretching;
            return false;
        }
        stretched->assign(STRETCHED_BYTES, '\0');
        if (crypto_scrypt(reinterpret_cast<const uint8_t*>(secret.data()), secret.size(),
                          reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 1 << Nf,
                          1 << rf, 1 << pf, reinterpret_cast<uint8_t*>(&(*stretched)[0]),
                          stretched->size()) != 0) {
            LOG(ERROR) << "scrypt failed with params: " << stretching;
            return false;
        }
    } else {
        LOG(ERROR) << "Unknown stretching type: " << stretching;
        return false;
    }
    return true;
}

static bool generateAppId(const KeyAuthentication& auth, const std::string& stretching,
                          const std::string& salt, const std::string& secdiscardable_hash,
                          std::string* appId) {
    std::string stretched;
    if (!stretchSecret(stretching, auth.secret, salt, &stretched)) return false;
    *appId = secdiscardable_hash + stretched;
    return true;
}

static void logOpensslError() {
    LOG(ERROR) << "Openssl error: " << ERR_get_error();
}

static bool encryptWithoutKeymaster(const std::string& preKey, const KeyBuffer& plaintext,
                                    std::string* ciphertext) {
    std::string key;
    hashWithPrefix(kHashPrefix_keygen, preKey, &key);
    key.resize(AES_KEY_BYTES);
    if (!readRandomBytesOrLog(GCM_NONCE_BYTES, ciphertext)) return false;
    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        logOpensslError();
        return false;
    }
    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL,
                                reinterpret_cast<const uint8_t*>(key.data()),
                                reinterpret_cast<const uint8_t*>(ciphertext->data()))) {
        logOpensslError();
        return false;
    }
    ciphertext->resize(GCM_NONCE_BYTES + plaintext.size() + GCM_MAC_BYTES);
    int outlen;
    if (1 != EVP_EncryptUpdate(
                 ctx.get(), reinterpret_cast<uint8_t*>(&(*ciphertext)[0] + GCM_NONCE_BYTES),
                 &outlen, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size())) {
        logOpensslError();
        return false;
    }
    if (outlen != static_cast<int>(plaintext.size())) {
        LOG(ERROR) << "GCM ciphertext length should be " << plaintext.size() << " was " << outlen;
        return false;
    }
    if (1 != EVP_EncryptFinal_ex(
                 ctx.get(),
                 reinterpret_cast<uint8_t*>(&(*ciphertext)[0] + GCM_NONCE_BYTES + plaintext.size()),
                 &outlen)) {
        logOpensslError();
        return false;
    }
    if (outlen != 0) {
        LOG(ERROR) << "GCM EncryptFinal should be 0, was " << outlen;
        return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_MAC_BYTES,
                                 reinterpret_cast<uint8_t*>(&(*ciphertext)[0] + GCM_NONCE_BYTES +
                                                            plaintext.size()))) {
        logOpensslError();
        return false;
    }
    return true;
}

static bool decryptWithoutKeymaster(const std::string& preKey, const std::string& ciphertext,
                                    KeyBuffer* plaintext) {
    if (ciphertext.size() < GCM_NONCE_BYTES + GCM_MAC_BYTES) {
        LOG(ERROR) << "GCM ciphertext too small: " << ciphertext.size();
        return false;
    }
    std::string key;
    hashWithPrefix(kHashPrefix_keygen, preKey, &key);
    key.resize(AES_KEY_BYTES);
    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        logOpensslError();
        return false;
    }
    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL,
                                reinterpret_cast<const uint8_t*>(key.data()),
                                reinterpret_cast<const uint8_t*>(ciphertext.data()))) {
        logOpensslError();
        return false;
    }
    *plaintext = KeyBuffer(ciphertext.size() - GCM_NONCE_BYTES - GCM_MAC_BYTES);
    int outlen;
    if (1 != EVP_DecryptUpdate(ctx.get(), reinterpret_cast<uint8_t*>(&(*plaintext)[0]), &outlen,
                               reinterpret_cast<const uint8_t*>(ciphertext.data() + GCM_NONCE_BYTES),
                               plaintext->size())) {
        logOpensslError();
        return false;
    }
    if (outlen != static_cast<int>(plaintext->size())) {
        LOG(ERROR) << "GCM plaintext length should be " << plaintext->size() << " was " << outlen;
        return false;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_MAC_BYTES,
                                 const_cast<void*>(reinterpret_cast<const void*>(
                                     ciphertext.data() + GCM_NONCE_BYTES + plaintext->size())))) {
        logOpensslError();
        return false;
    }
    if (1 != EVP_DecryptFinal_ex(ctx.get(),
                                 reinterpret_cast<uint8_t*>(&(*plaintext)[0] + plaintext->size()),
                                 &outlen)) {
        logOpensslError();
        return false;
    }
    if (outlen != 0) {
        LOG(ERROR) << "GCM EncryptFinal should be 0, was " << outlen;
        return false;
    }
    return true;
}

bool pathExists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

bool storeKey(const std::string& dir, const KeyAuthentication& auth, const KeyBuffer& key) {
    if (TEMP_FAILURE_RETRY(mkdir(dir.c_str(), 0700)) == -1) {
        PLOG(ERROR) << "key mkdir " << dir;
        return false;
    }
    if (!writeStringToFile(kCurrentVersion, dir + "/" + kFn_version)) return false;
    std::string secdiscardable_hash;
    if (!createSecdiscardable(dir + "/" + kFn_secdiscardable, &secdiscardable_hash)) return false;
    std::string stretching = getStretching(auth);
    if (!writeStringToFile(stretching, dir + "/" + kFn_stretching)) return false;
    std::string salt;
    if (stretchingNeedsSalt(stretching)) {
        if (ReadRandomBytes(SALT_BYTES, salt) != OK) {
            LOG(ERROR) << "Random read failed";
            return false;
        }
        if (!writeStringToFile(salt, dir + "/" + kFn_salt)) return false;
    }
    std::string appId;
    if (!generateAppId(auth, stretching, salt, secdiscardable_hash, &appId)) return false;
    std::string encryptedKey;
    if (auth.usesKeymaster()) {
        Keymaster keymaster;
        if (!keymaster) return false;
        std::string kmKey;
        if (!generateKeymasterKey(keymaster, auth, appId, &kmKey)) return false;
        if (!writeStringToFile(kmKey, dir + "/" + kFn_keymaster_key_blob)) return false;
        km::AuthorizationSet keyParams;
        km::HardwareAuthToken authToken;
        std::tie(keyParams, authToken) = beginParams(auth, appId);
        if (!encryptWithKeymasterKey(keymaster, dir, keyParams, authToken, key, &encryptedKey))
            return false;
    } else {
        if (!encryptWithoutKeymaster(appId, key, &encryptedKey)) return false;
    }
    if (!writeStringToFile(encryptedKey, dir + "/" + kFn_encrypted_key)) return false;
    if (!FsyncDirectory(dir)) return false;
    return true;
}

bool storeKeyAtomically(const std::string& key_path, const std::string& tmp_path,
                        const KeyAuthentication& auth, const KeyBuffer& key) {
    if (pathExists(key_path)) {
        LOG(ERROR) << "Already exists, cannot create key at: " << key_path;
        return false;
    }
    if (pathExists(tmp_path)) {
        LOG(DEBUG) << "Already exists, destroying: " << tmp_path;
        destroyKey(tmp_path);  // May be partially created so ignore errors
    }
    if (!storeKey(tmp_path, auth, key)) return false;
    if (rename(tmp_path.c_str(), key_path.c_str()) != 0) {
        PLOG(ERROR) << "Unable to move new key to location: " << key_path;
        return false;
    }
    LOG(DEBUG) << "Created key: " << key_path;
    return true;
}

bool retrieveKey(const std::string& dir, const KeyAuthentication& auth, KeyBuffer* key) {
    std::string version;
    if (!readFileToString(dir + "/" + kFn_version, &version)) return false;
    if (version != kCurrentVersion) {
        LOG(ERROR) << "Version mismatch, expected " << kCurrentVersion << " got " << version;
        return false;
    }
    std::string secdiscardable_hash;
    if (!readSecdiscardable(dir + "/" + kFn_secdiscardable, &secdiscardable_hash)) return false;
    std::string stretching;
    if (!readFileToString(dir + "/" + kFn_stretching, &stretching)) return false;
    std::string salt;
    if (stretchingNeedsSalt(stretching)) {
        if (!readFileToString(dir + "/" + kFn_salt, &salt)) return false;
    }
    std::string appId;
    if (!generateAppId(auth, stretching, salt, secdiscardable_hash, &appId)) return false;
    std::string encryptedMessage;
    if (!readFileToString(dir + "/" + kFn_encrypted_key, &encryptedMessage)) return false;
    if (auth.usesKeymaster()) {
        Keymaster keymaster;
        if (!keymaster) return false;
        km::AuthorizationSet keyParams;
        km::HardwareAuthToken authToken;
        std::tie(keyParams, authToken) = beginParams(auth, appId);
        if (!decryptWithKeymasterKey(keymaster, dir, keyParams, authToken, encryptedMessage, key))
            return false;
    } else {
        if (!decryptWithoutKeymaster(appId, encryptedMessage, key)) return false;
    }
    return true;
}

static bool DeleteKeymasterKey(const std::string& blob_file) {
    std::string blob;
    if (!readFileToString(blob_file, &blob)) return false;
    Keymaster keymaster;
    if (!keymaster) return false;
    LOG(DEBUG) << "Deleting key " << blob_file << " from Keymaster";
    if (!keymaster.deleteKey(blob)) return false;
    return true;
}

bool runSecdiscardSingle(const std::string& file) {
    if (ForkExecvp(std::vector<std::string>{kSecdiscardPath, "--", file}) != 0) {
        LOG(ERROR) << "secdiscard failed";
        return false;
    }
    return true;
}

static bool recursiveDeleteKey(const std::string& dir) {
    if (ForkExecvp(std::vector<std::string>{kRmPath, "-rf", dir}) != 0) {
        LOG(ERROR) << "recursive delete failed";
        return false;
    }
    return true;
}

bool destroyKey(const std::string& dir) {
    bool success = true;

    CancelPendingKeyCommit(dir);

    auto secdiscard_cmd = std::vector<std::string>{
        kSecdiscardPath,
        "--",
        dir + "/" + kFn_encrypted_key,
        dir + "/" + kFn_secdiscardable,
    };
    // Try each thing, even if previous things failed.

    for (auto& fn : {kFn_keymaster_key_blob, kFn_keymaster_key_blob_upgraded}) {
        auto blob_file = dir + "/" + fn;
        if (pathExists(blob_file)) {
            success &= DeleteKeymasterKey(blob_file);
            secdiscard_cmd.push_back(blob_file);
        }
    }
    if (ForkExecvp(secdiscard_cmd) != 0) {
        LOG(ERROR) << "secdiscard failed";
        success = false;
    }
    success &= recursiveDeleteKey(dir);
    return success;
}

}  // namespace vold
}  // namespace android