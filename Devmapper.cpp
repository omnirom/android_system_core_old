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

#define ATRACE_TAG ATRACE_TAG_PACKAGE_MANAGER

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <linux/kdev_t.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libdm/dm.h>
#include <utils/Trace.h>

#include "Devmapper.h"

using android::base::StringPrintf;
using namespace android::dm;

static const char* kVoldPrefix = "vold:";

int Devmapper::create(const char* name_raw, const char* loopFile, const char* key,
                      unsigned long numSectors, char* ubuffer, size_t len) {
    auto& dm = DeviceMapper::Instance();
    auto name_string = StringPrintf("%s%s", kVoldPrefix, name_raw);

    DmTable table;
    table.Emplace<DmTargetCrypt>(0, numSectors, "twofish", key, 0, loopFile, 0);

    if (!dm.CreateDevice(name_string, table)) {
        LOG(ERROR) << "Failed to create device-mapper device " << name_string;
        return -1;
    }

    std::string path;
    if (!dm.GetDmDevicePathByName(name_string, &path)) {
        LOG(ERROR) << "Failed to get device-mapper device path for " << name_string;
        return -1;
    }
    snprintf(ubuffer, len, "%s", path.c_str());
    return 0;
}

int Devmapper::destroy(const char* name_raw) {
    auto& dm = DeviceMapper::Instance();

    auto name_string = StringPrintf("%s%s", kVoldPrefix, name_raw);
    if (!dm.DeleteDevice(name_string)) {
        if (errno != ENXIO) {
            PLOG(ERROR) << "Failed DM_DEV_REMOVE";
        }
        return -1;
    }
    return 0;
}

int Devmapper::destroyAll() {
    ATRACE_NAME("Devmapper::destroyAll");

    auto& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::DmBlockDevice> devices;
    if (!dm.GetAvailableDevices(&devices)) {
        LOG(ERROR) << "Failed to get dm devices";
        return -1;
    }

    for (const auto& device : devices) {
        if (android::base::StartsWith(device.name(), kVoldPrefix)) {
            LOG(DEBUG) << "Tearing down stale dm device named " << device.name();
            if (!dm.DeleteDevice(device.name())) {
                if (errno != ENXIO) {
                    PLOG(WARNING) << "Failed to destroy dm device named " << device.name();
                }
            }
        } else {
            LOG(DEBUG) << "Found unmanaged dm device named " << device.name();
        }
    }
    return 0;
}
