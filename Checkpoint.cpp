/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "Checkpoint"
#include "Checkpoint.h"

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>
#include <mntent.h>
#include <sys/mount.h>

#include <list>
#include <string>

namespace android {
namespace vold {

static const std::string kMetadataCPFile = "/metadata/vold/checkpoint";

bool cp_startCheckpoint(int retry) {
    if (retry < -1) return false;
    std::string content = std::to_string(retry);
    return android::base::WriteStringToFile(content, kMetadataCPFile);
}

bool cp_commitChanges() {
    struct fstab* fstab = fs_mgr_read_fstab_default();
    if (!fstab) return false;

    FILE* fp = setmntent("/proc/mounts", "r");
    mntent* mentry;

    if (fp == NULL) return false;

    while ((mentry = getmntent(fp)) != NULL) {
        auto test = std::string(mentry->mnt_dir) + "/";
        for (int i = 0; i < fstab->num_entries; i++) {
            if (!fs_mgr_is_checkpoint(&fstab->recs[i])) continue;

            if (!strcmp(fstab->recs[i].mount_point, mentry->mnt_dir) &&
                !strcmp(fstab->recs[i].fs_type, mentry->mnt_type)) {
                if (!strcmp(fstab->recs[i].fs_type, "f2fs")) {
                    mount(mentry->mnt_fsname, mentry->mnt_dir, "none",
                          MS_REMOUNT | fstab->recs[i].flags, "checkpoint=enable");
                }
            }
        }
    }
    endmntent(fp);

    fs_mgr_free_fstab(fstab);
    return android::base::RemoveFileIfExists(kMetadataCPFile);
}

void cp_abortChanges() {
    android_reboot(ANDROID_RB_RESTART2, 0, nullptr);
}

bool cp_needRollback(const std::string& id) {
    std::string content;
    bool ret;

    ret = android::base::ReadFileToString(kMetadataCPFile, &content);
    if (ret) return content == "0";
    return false;
}

bool cp_needsCheckpoint(void) {
    bool ret;
    std::string content;

    ret = android::base::ReadFileToString(kMetadataCPFile, &content);
    if (ret) return content != "0";
    return false;
}

bool cp_prepareDriveForCheckpoint(const std::string& mountPoint) {
    return false;
}

bool cp_markBootAttempt() {
    std::string oldContent, newContent;
    int retry = 0;
    if (!android::base::ReadFileToString(kMetadataCPFile, &oldContent)) return false;

    if (!android::base::ParseInt(oldContent, &retry)) return false;
    if (retry > 0) retry--;

    newContent = std::to_string(retry);
    return android::base::WriteStringToFile(newContent, kMetadataCPFile);
}

}  // namespace vold
}  // namespace android
