/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_VOLD_MOVE_TASK_H
#define ANDROID_VOLD_MOVE_TASK_H

#include "android/os/IVoldTaskListener.h"
#include "Utils.h"
#include "model/VolumeBase.h"

#include <thread>

namespace android {
namespace vold {

class MoveTask {
public:
    MoveTask(const std::shared_ptr<VolumeBase>& from, const std::shared_ptr<VolumeBase>& to,
            const android::sp<android::os::IVoldTaskListener>& listener);
    virtual ~MoveTask();

    void start();

private:
    std::shared_ptr<VolumeBase> mFrom;
    std::shared_ptr<VolumeBase> mTo;
    android::sp<android::os::IVoldTaskListener> mListener;
    std::thread mThread;

    void run();

    void notifyProgress(int progress);

    status_t execRm(const std::string& path, int startProgress, int stepProgress);
    status_t execCp(const std::string& fromPath, const std::string& toPath,
            int startProgress, int stepProgress);

    DISALLOW_COPY_AND_ASSIGN(MoveTask);
};

}  // namespace vold
}  // namespace android

#endif
