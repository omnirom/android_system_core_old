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

#include "../VoldNativeServiceValidation.h"

#include <gtest/gtest.h>

#include <string_view>

using namespace std::literals;

namespace android::vold {

class VoldServiceValidationTest : public testing::Test {};

TEST_F(VoldServiceValidationTest, CheckArgumentPathTest) {
    EXPECT_TRUE(CheckArgumentPath("/").isOk());
    EXPECT_TRUE(CheckArgumentPath("/1/2").isOk());
    EXPECT_TRUE(CheckArgumentPath("/1/2/").isOk());
    EXPECT_TRUE(CheckArgumentPath("/1/2/./3").isOk());
    EXPECT_TRUE(CheckArgumentPath("/1/2/./3/.").isOk());
    EXPECT_TRUE(CheckArgumentPath(
                        "/very long path with some/ spaces and quite/ uncommon names /in\1 it/")
                        .isOk());

    EXPECT_FALSE(CheckArgumentPath("").isOk());
    EXPECT_FALSE(CheckArgumentPath("relative/path").isOk());
    EXPECT_FALSE(CheckArgumentPath("../data/..").isOk());
    EXPECT_FALSE(CheckArgumentPath("/../data/..").isOk());
    EXPECT_FALSE(CheckArgumentPath("/data/../system").isOk());
    EXPECT_FALSE(CheckArgumentPath("/data/..trick/../system").isOk());
    EXPECT_FALSE(CheckArgumentPath("/data/..").isOk());
    EXPECT_FALSE(CheckArgumentPath("/data/././../apex").isOk());
    EXPECT_FALSE(CheckArgumentPath(std::string("/data/strange\0one"sv)).isOk());
    EXPECT_FALSE(CheckArgumentPath(std::string("/data/strange\ntwo"sv)).isOk());
}

}  // namespace android::vold
