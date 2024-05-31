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

#include "security_guard_risk_analysis_test.h"

#include "file_ex.h"
#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public

#undef private
#undef protected
#include "os_account_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
    std::shared_ptr<AccountSA::MockOsAccountManagerInterface> AccountSA::OsAccountManager::instance_ = nullptr;
    std::mutex AccountSA::OsAccountManager::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {
void SecurityGuardRiskAnalysisTest::SetUpTestCase()
{
}

void SecurityGuardRiskAnalysisTest::TearDownTestCase()
{
}

void SecurityGuardRiskAnalysisTest::SetUp()
{
}

void SecurityGuardRiskAnalysisTest::TearDown()
{
}
}