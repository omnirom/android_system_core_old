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

#include "VoldNativeServiceValidation.h"

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <private/android_filesystem_config.h>

#include <cctype>
#include <string_view>

using android::base::StringPrintf;
using namespace std::literals;

namespace android::vold {

binder::Status Ok() {
    return binder::Status::ok();
}

binder::Status Exception(uint32_t code, const std::string& msg) {
    return binder::Status::fromExceptionCode(code, String8(msg.c_str()));
}

binder::Status CheckPermission(const char* permission) {
    int32_t pid;
    int32_t uid;

    if (checkCallingPermission(String16(permission), &pid, &uid)) {
        return Ok();
    } else {
        return Exception(binder::Status::EX_SECURITY,
                         StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission));
    }
}

binder::Status CheckUidOrRoot(uid_t expectedUid) {
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid == expectedUid || uid == AID_ROOT) {
        return Ok();
    } else {
        return Exception(binder::Status::EX_SECURITY,
                         StringPrintf("UID %d is not expected UID %d", uid, expectedUid));
    }
}

binder::Status CheckArgumentId(const std::string& id) {
    if (id.empty()) {
        return Exception(binder::Status::EX_ILLEGAL_ARGUMENT, "Missing ID");
    }
    for (const char& c : id) {
        if (!std::isalnum(c) && c != ':' && c != ',' && c != ';') {
            return Exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                             StringPrintf("ID %s is malformed", id.c_str()));
        }
    }
    return Ok();
}

binder::Status CheckArgumentPath(const std::string& path) {
    if (path.empty()) {
        return Exception(binder::Status::EX_ILLEGAL_ARGUMENT, "Missing path");
    }
    if (path[0] != '/') {
        return Exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                         StringPrintf("Path %s is relative", path.c_str()));
    }
    if (path.find("/../"sv) != path.npos || android::base::EndsWith(path, "/.."sv)) {
        return Exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                         StringPrintf("Path %s is shady", path.c_str()));
    }
    for (const char& c : path) {
        if (c == '\0' || c == '\n') {
            return Exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                             StringPrintf("Path %s is malformed", path.c_str()));
        }
    }
    return Ok();
}

binder::Status CheckArgumentHex(const std::string& hex) {
    // Empty hex strings are allowed
    for (const char& c : hex) {
        if (!std::isxdigit(c) && c != ':' && c != '-') {
            return Exception(binder::Status::EX_ILLEGAL_ARGUMENT,
                             StringPrintf("Hex %s is malformed", hex.c_str()));
        }
    }
    return Ok();
}

}  // namespace android::vold
