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

#ifndef _VOLD_NATIVE_SERVICE_H_
#define _VOLD_NATIVE_SERVICE_H_

#include <binder/BinderService.h>

#include "android/os/BnVold.h"

namespace android {
namespace vold {

class VoldNativeService : public BinderService<VoldNativeService>, public os::BnVold {
public:
    static status_t start();
    static char const* getServiceName() { return "vold"; }
    virtual status_t dump(int fd, const Vector<String16> &args) override;

    binder::Status reset();
};

}  // namespace vold
}  // namespace android

#endif  // _VOLD_NATIVE_SERVICE_H_
