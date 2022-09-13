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

#include "risk_classify_kit_test.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;
using namespace OHOS::Security::SecurityGuard;

namespace OHOS::Security::SecurityGuardTest {
void RiskClassifyKitTest::SetUpTestCase()
{
}

void RiskClassifyKitTest::TearDownTestCase()
{
}

void RiskClassifyKitTest::SetUp()
{
    callback_ = std::make_shared<RiskAnalysisManagerCallbackMock>();
}

void RiskClassifyKitTest::TearDown()
{
}

/**
 * @tc.name: RequestSecurityModelResultSync001
 * @tc.desc: RequestSecurityModelResultSync with wrong modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync001, TestSize.Level1)
{
    static std::string devId;
    static uint32_t modelId = 0;
    std::shared_ptr<SecurityModelResult> result = std::make_shared<SecurityModelResult>();
    int ret = RiskAnalysisManagerKit::RequestSecurityModelResultSync(devId, modelId, result);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_STREQ(result->GetDevId().c_str(), devId.c_str());
    EXPECT_EQ(result->GetModelId(), modelId);
    EXPECT_STREQ(result->GetResult().c_str(), "unknown");
}

/**
 * @tc.name: RequestSecurityModelResultSync002
 * @tc.desc: RequestSecurityModelResultSync with right modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync002, TestSize.Level1)
{
    static std::string devId;
    static uint32_t modelId = 3001000000;
    std::shared_ptr<SecurityModelResult> result = std::make_shared<SecurityModelResult>();
    int ret = RiskAnalysisManagerKit::RequestSecurityModelResultSync(devId, modelId, result);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_STREQ(result->GetDevId().c_str(), devId.c_str());
    EXPECT_EQ(result->GetModelId(), modelId);
}

/**
 * @tc.name: RequestSecurityModelResultAsync001
 * @tc.desc: RequestSecurityModelResultAsync with wrong modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultAsync001, TestSize.Level1)
{
    static std::string devId;
    static uint32_t modelId = 0;
    int ret = RiskAnalysisManagerKit::RequestSecurityModelResultAsync(devId, modelId, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityModelResultAsync002
 * @tc.desc: RequestSecurityModelResultAsync with right modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultAsync002, TestSize.Level1)
{
    static std::string devId;
    static uint32_t modelId = 3001000000;
    int ret = RiskAnalysisManagerKit::RequestSecurityModelResultAsync(devId, modelId, callback_);
    EXPECT_EQ(ret, SUCCESS);
}
}