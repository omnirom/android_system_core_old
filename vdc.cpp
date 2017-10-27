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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "android/os/IVold.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>

#include <private/android_filesystem_config.h>

static void usage(char *progname);

static android::sp<android::IBinder> getServiceAggressive() {
    android::sp<android::IBinder> res;
    auto sm = android::defaultServiceManager();
    auto name = android::String16("vold");
    for (int i = 0; i < 500; i++) {
        res = sm->checkService(name);
        if (res) {
            LOG(VERBOSE) << "Waited " << (i * 10) << "ms for vold";
            break;
        }
        usleep(10000); // 10ms
    }
    return res;
}

static void checkStatus(android::binder::Status status) {
    if (status.isOk()) return;
    LOG(ERROR) << "Failed: " << status.toString8().string();
    exit(ENOTTY);
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
        checkStatus(vold->fbeEnable());
    } else if (args[0] == "cryptfs" && args[1] == "init_user0") {
        checkStatus(vold->initUser0());
    } else if (args[0] == "cryptfs" && args[1] == "enablecrypto") {
        int passwordType = android::os::IVold::PASSWORD_TYPE_DEFAULT;
        int encryptionFlags = android::os::IVold::ENCRYPTION_FLAG_IN_PLACE
                | android::os::IVold::ENCRYPTION_FLAG_NO_UI;
        checkStatus(vold->fdeEnable(passwordType, "", encryptionFlags));
    } else if (args[0] == "cryptfs" && args[1] == "mountdefaultencrypted") {
        checkStatus(vold->mountDefaultEncrypted());
    } else if (args[0] == "volume" && args[1] == "shutdown") {
        checkStatus(vold->shutdown());
    } else {
        LOG(ERROR) << "Raw commands are no longer supported";
        exit(EINVAL);
    }
    return 0;
}

static void usage(char *progname) {
    LOG(INFO) << "Usage: " << progname << " [--wait] <system> <subcommand> [args...]";
}
