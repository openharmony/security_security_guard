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

#include "acquire_data_manager_test.h"

#include "file_ex.h"

#include "security_guard_define.h"
#include "acquire_data_manager.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS::Security::SecurityGuardTest {

void AcquireDataManagerTest::SetUpTestCase()
{
    string isEnforcing;
    LoadStringFromFile("/sys/fs/selinux/enforce", isEnforcing);
    if (isEnforcing.compare("1") == 0) {
        AcquireDataManagerTest::isEnforcing_ = true;
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void AcquireDataManagerTest::TearDownTestCase()
{
    if (AcquireDataManagerTest::isEnforcing_) {
        SaveStringToFile("/sys/fs/selinux/enforce", "1");
    }
}

void AcquireDataManagerTest::SetUp()
{
}

void AcquireDataManagerTest::TearDown()
{
}

bool AcquireDataManagerTest::isEnforcing_ = false;

/**
 * @tc.name: Subscribe001
 * @tc.desc: AcquireDataManager Subscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(AcquireDataManagerTest, Subscribe001, TestSize.Level1)
{
    int ret = SecurityGuard::AcquireDataManager::GetInstance().Subscribe(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

/**
 * @tc.name: Unsubscribe001
 * @tc.desc: AcquireDataManager Unsubscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(AcquireDataManagerTest, Unsubscribe001, TestSize.Level1)
{
    int ret = SecurityGuard::AcquireDataManager::GetInstance().Unsubscribe(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

/**
 * @tc.name: ReportSecurityInfo007
 * @tc.desc: AcquireDataManager DeathRecipient OnRemoteDied
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(AcquireDataManagerTest, DeathRecipient001, TestSize.Level1)
{
    SecurityGuard::AcquireDataManager::DeathRecipient recipient =
        SecurityGuard::AcquireDataManager::DeathRecipient();
    recipient.OnRemoteDied(nullptr);
}
}