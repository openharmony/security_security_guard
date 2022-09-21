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

#ifndef SECURITY_GUARD_RISK_CLASSIFY_KIT_TEST
#define SECURITY_GUARD_RISK_CLASSIFY_KIT_TEST

#include <gtest/gtest.h>

#include "sg_classify_client.h"
#include "security_model_result.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuardTest {
class RiskClassifyKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

    class RiskAnalysisManagerCallbackMock : public SecurityGuard::RiskAnalysisManagerCallback {
    public:
        RiskAnalysisManagerCallbackMock() = default;
        ~RiskAnalysisManagerCallbackMock() override = default;
        int32_t OnSecurityModelResult(const std::string &devId, uint32_t modelId, const std::string &result) override
        {
            return SecurityGuard::ErrorCode::SUCCESS;
        }
    };

    std::shared_ptr<SecurityGuard::RiskAnalysisManagerCallback> callback_;
};
}  // namespace OHOS::Security::SecurityGuardTest

#endif  // SECURITY_GUARD_RISK_CLASSIFY_KIT_TEST
