/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "Utils.h"
#include "android/os/IVold.h"

#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <utils/Errors.h>

#include <private/android_filesystem_config.h>

static void usage(char* progname);

static android::sp<android::IBinder> getServiceAggressive() {
    android::sp<android::IBinder> res;
    auto sm = android::defaultServiceManager();
    auto name = android::String16("vold");
    for (int i = 0; i < 5000; i++) {
        res = sm->checkService(name);
        if (res) {
            LOG(VERBOSE) << "Waited " << (i * 10) << "ms for vold";
            break;
        }
        usleep(10000);  // 10ms
    }
    return res;
}

static void checkStatus(std::vector<std::string>& cmd, android::binder::Status status) {
    if (status.isOk()) return;
    std::string command = ::android::base::Join(cmd, " ");
    LOG(ERROR) << "Command: " << command << " Failed: " << status.toString8().string();
    exit(ENOTTY);
}

static void bindkeys(std::vector<std::string>& args, const android::sp<android::os::IVold>& vold) {
    std::string raw_bytes;
    const char* seed_value;

    seed_value = getenv("SEED_VALUE");
    if (seed_value == NULL) {
        LOG(ERROR) << "Empty seed";
        exit(EINVAL);
    }

    android::status_t status = android::vold::HexToStr(seed_value, raw_bytes);
    if (status != android::OK) {
        LOG(ERROR) << "Extraction of seed failed: " << status;
        exit(status);
    }

    std::vector<uint8_t> seed{raw_bytes.begin(), raw_bytes.end()};
    checkStatus(args, vold->setStorageBindingSeed(seed));
}

int main(int argc, char** argv) {
    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    if (getppid() == 1) {
        // If init is calling us then it's during boot and we should log to kmsg
        android::base::InitLogging(argv, &android::base::KernelLogger);
    } else {
        android::base::InitLogging(argv, &android::base::StderrLogger);
    }
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.size() > 0 && args[0] == "--wait") {
        // Just ignore the --wait flag
        args.erase(args.begin());
    }

    if (args.size() < 2) {
        usage(argv[0]);
        exit(5);
    }
    android::sp<android::IBinder> binder = getServiceAggressive();
    if (!binder) {
        LOG(ERROR) << "Failed to obtain vold Binder";
        exit(EINVAL);
    }
    auto vold = android::interface_cast<android::os::IVold>(binder);

    if (args[0] == "cryptfs" && args[1] == "enablefilecrypto") {
        checkStatus(args, vold->fbeEnable());
    } else if (args[0] == "cryptfs" && args[1] == "init_user0") {
        checkStatus(args, vold->initUser0());
    } else if (args[0] == "volume" && args[1] == "abort_fuse") {
        checkStatus(args, vold->abortFuse());
    } else if (args[0] == "volume" && args[1] == "shutdown") {
        checkStatus(args, vold->shutdown());
    } else if (args[0] == "volume" && args[1] == "reset") {
        checkStatus(args, vold->reset());
    } else if (args[0] == "volume" && args[1] == "getStorageSize") {
        int64_t size;
        checkStatus(args, vold->getStorageSize(&size));
        LOG(INFO) << size;
    } else if (args[0] == "cryptfs" && args[1] == "bindkeys") {
        bindkeys(args, vold);
    } else if (args[0] == "cryptfs" && args[1] == "mountFstab" && args.size() == 5) {
        checkStatus(args, vold->mountFstab(args[2], args[3], args[4]));
    } else if (args[0] == "cryptfs" && args[1] == "encryptFstab" && args.size() == 7) {
        auto shouldFormat = android::base::ParseBool(args[4]);
        if (shouldFormat == android::base::ParseBoolResult::kError) exit(EINVAL);
        checkStatus(args, vold->encryptFstab(args[2], args[3],
                                             shouldFormat == android::base::ParseBoolResult::kTrue,
                                             args[5], args[6]));
    } else if (args[0] == "checkpoint" && args[1] == "supportsCheckpoint" && args.size() == 2) {
        bool supported = false;
        checkStatus(args, vold->supportsCheckpoint(&supported));
        return supported ? 1 : 0;
    } else if (args[0] == "checkpoint" && args[1] == "supportsBlockCheckpoint" &&
               args.size() == 2) {
        bool supported = false;
        checkStatus(args, vold->supportsBlockCheckpoint(&supported));
        return supported ? 1 : 0;
    } else if (args[0] == "checkpoint" && args[1] == "supportsFileCheckpoint" && args.size() == 2) {
        bool supported = false;
        checkStatus(args, vold->supportsFileCheckpoint(&supported));
        return supported ? 1 : 0;
    } else if (args[0] == "checkpoint" && args[1] == "startCheckpoint" && args.size() == 3) {
        int retry;
        if (!android::base::ParseInt(args[2], &retry)) exit(EINVAL);
        checkStatus(args, vold->startCheckpoint(retry));
    } else if (args[0] == "checkpoint" && args[1] == "needsCheckpoint" && args.size() == 2) {
        bool enabled = false;
        checkStatus(args, vold->needsCheckpoint(&enabled));
        return enabled ? 1 : 0;
    } else if (args[0] == "checkpoint" && args[1] == "needsRollback" && args.size() == 2) {
        bool enabled = false;
        checkStatus(args, vold->needsRollback(&enabled));
        return enabled ? 1 : 0;
    } else if (args[0] == "checkpoint" && args[1] == "commitChanges" && args.size() == 2) {
        checkStatus(args, vold->commitChanges());
    } else if (args[0] == "checkpoint" && args[1] == "prepareCheckpoint" && args.size() == 2) {
        checkStatus(args, vold->prepareCheckpoint());
    } else if (args[0] == "checkpoint" && args[1] == "restoreCheckpoint" && args.size() == 3) {
        checkStatus(args, vold->restoreCheckpoint(args[2]));
    } else if (args[0] == "checkpoint" && args[1] == "restoreCheckpointPart" && args.size() == 4) {
        int count;
        if (!android::base::ParseInt(args[3], &count)) exit(EINVAL);
        checkStatus(args, vold->restoreCheckpointPart(args[2], count));
    } else if (args[0] == "checkpoint" && args[1] == "markBootAttempt" && args.size() == 2) {
        checkStatus(args, vold->markBootAttempt());
    } else if (args[0] == "checkpoint" && args[1] == "abortChanges" && args.size() == 4) {
        int retry;
        if (!android::base::ParseInt(args[2], &retry)) exit(EINVAL);
        checkStatus(args, vold->abortChanges(args[2], retry != 0));
    } else if (args[0] == "checkpoint" && args[1] == "resetCheckpoint") {
        checkStatus(args, vold->resetCheckpoint());
    } else if (args[0] == "keymaster" && args[1] == "earlyBootEnded") {
        checkStatus(args, vold->earlyBootEnded());
    } else {
        LOG(ERROR) << "Raw commands are no longer supported";
        exit(EINVAL);
    }
    return 0;
}

static void usage(char* progname) {
    LOG(INFO) << "Usage: " << progname << " [--wait] <system> <subcommand> [args...]";
}
