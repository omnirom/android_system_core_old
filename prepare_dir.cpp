/*
 * Copyright (C) 2017 The Android Open Source Project
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

/*
 * Tool to create a directory with the right SELinux context applied, or
 * apply the context if it's absent. Also fixes mode, uid, gid.
 */

#include <string>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <android-base/logging.h>

#include <cutils/fs.h>
#include <selinux/android.h>

void usage(const char* progname) {
    fprintf(stderr, "Usage: %s --mode MODE --uid UID --gid GID -- <path>\n", progname);
}

bool small_int(const std::string& s) {
    return !s.empty() && s.size() < 7 && s.find_first_not_of("0123456789") == std::string::npos;
}

int main(int argc, const char* const argv[]) {
    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    android::base::InitLogging(const_cast<char**>(argv));
    std::vector<std::string> args(argv + 1, argv + argc);
    // Enforce exact format of arguments. You can always loosen but you can never tighten :)
    if (args.size() != 8 || args[0] != "--mode" || !small_int(args[1]) || args[2] != "--uid" ||
        !small_int(args[3]) || args[4] != "--gid" || !small_int(args[5]) || args[6] != "--") {
        usage(argv[0]);
        return -1;
    }
    mode_t mode = (mode_t)stoi(args[1], nullptr, 8);
    uid_t uid = (uid_t)stoi(args[3]);
    gid_t gid = (gid_t)stoi(args[5]);
    const char* path = args[7].c_str();

    struct selabel_handle* sehandle = selinux_android_file_context_handle();
    char* secontext = nullptr;
    if (sehandle) {
        if (selabel_lookup(sehandle, &secontext, path, S_IFDIR) == 0) {
            setfscreatecon(secontext);
        }
    }

    if (fs_prepare_dir(path, mode, uid, gid) != 0) {
        return -1;
    }
    if (secontext) {
        char* oldsecontext = nullptr;
        if (lgetfilecon(path, &oldsecontext) < 0) {
            PLOG(ERROR) << "Unable to read secontext for: " << path;
            return -1;
        }
        if (strcmp(secontext, oldsecontext) != 0) {
            LOG(INFO) << "Relabelling from " << oldsecontext << " to " << secontext << ": " << path;
            if (lsetfilecon(path, secontext) != 0) {
                PLOG(ERROR) << "Relabelling failed for: " << path;
            }
        }
    }
    return 0;
}
