/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gmock/gmock.h"
#include "rdb_helper.h"
#include "security_guard_define.h"
#define private public
#define protected public
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
    std::shared_ptr<NativeRdb::MockRdbHelperInterface> NativeRdb::RdbHelper::instance_ = nullptr;
    std::mutex NativeRdb::RdbHelper::mutex_ {};
}
namespace OHOS::Security::SecurityGuardTest {
class AppInfoDataBaseTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AppInfoDataBaseTest::SetUpTestCase()
{
}

void AppInfoDataBaseTest::TearDownTestCase()
{
    NativeRdb::RdbHelper::DelInterface();
}

void AppInfoDataBaseTest::SetUp()
{
}

void AppInfoDataBaseTest::TearDown()
{
}

}
