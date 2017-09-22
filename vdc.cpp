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

int main(int argc, char **argv) {
    int sock;
    int wait;
    char *progname;

    progname = argv[0];

    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    if (getppid() == 1) {
        // If init is calling us then it's during boot and we should log to kmsg
        android::base::InitLogging(argv, &android::base::KernelLogger);
    } else {
        android::base::InitLogging(argv, &android::base::StderrLogger);
    }

    wait = argc > 1 && strcmp(argv[1], "--wait") == 0;
    if (wait) {
        argv++;
        argc--;
    }

    if (argc < 3) {
        usage(progname);
        exit(5);
    }

    std::string arg1 = argv[1];
    std::string arg2 = argv[2];

    android::sp<android::IBinder> binder = getServiceAggressive();
    if (!binder) {
        LOG(ERROR) << "Failed to obtain vold Binder";
        exit(EINVAL);
    }
    auto vold = android::interface_cast<android::os::IVold>(binder);

    if (arg1 == "cryptfs" && arg2 == "enablefilecrypto") {
        exit(vold->fbeEnable().isOk() ? 0 : ENOTTY);
    } else if (arg1 == "cryptfs" && arg2 == "init_user0") {
        exit(vold->initUser0().isOk() ? 0 : ENOTTY);
    } else if (arg1 == "cryptfs" && arg2 == "enablecrypto") {
        int passwordType = android::os::IVold::PASSWORD_TYPE_DEFAULT;
        int encryptionFlags = android::os::IVold::ENCRYPTION_FLAG_IN_PLACE
                | android::os::IVold::ENCRYPTION_FLAG_NO_UI;
        exit(vold->fdeEnable(passwordType, "", encryptionFlags).isOk() ? 0 : ENOTTY);
    } else if (arg1 == "cryptfs" && arg2 == "mountdefaultencrypted") {
        exit(vold->mountDefaultEncrypted().isOk() ? 0 : ENOTTY);
    } else if (arg1 == "volume" && arg2 == "shutdown") {
        exit(vold->shutdown().isOk() ? 0 : ENOTTY);
    } else {
        LOG(ERROR) << "Raw commands are no longer supported";
        exit(EINVAL);
    }
}

static void usage(char *progname) {
    LOG(INFO) << "Usage: " << progname << " [--wait] <monitor>|<cmd> [arg1] [arg2...]";
}
