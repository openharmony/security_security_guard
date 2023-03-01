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

#include "file_ex.h"
#include "securec.h"

#include "sg_classify_client.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;

#ifdef __cplusplus
extern "C" {
#endif
    int32_t RequestSecurityEventInfoAsync(const DeviceIdentify *devId, const char *eventJson,
        RequestSecurityEventInfoCallBack callback);
    int32_t RequestSecurityModelResultSync(const DeviceIdentify *devId, uint32_t modelId, SecurityModelResult *result);
#ifdef __cplusplus
}
#endif

namespace OHOS::Security::SecurityGuardTest {
std::string g_enforceValue = "0";

void RiskClassifyKitTest::SetUpTestCase()
{
    bool isSuccess = LoadStringFromFile("/sys/fs/selinux/enforce", g_enforceValue);
    if (isSuccess && g_enforceValue == "1") {
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void RiskClassifyKitTest::TearDownTestCase()
{
    SaveStringToFile("/sys/fs/selinux/enforce", g_enforceValue);
}

void RiskClassifyKitTest::SetUp()
{
}

void RiskClassifyKitTest::TearDown()
{
}

void RiskClassifyKitTest::SecurityGuardRiskCallbackFunc(SecurityModelResult *result)
{
    EXPECT_TRUE(result != nullptr);
}

/**
 * @tc.name: RequestSecurityModelResultSync001
 * @tc.desc: RequestSecurityModelResultSync with wrong modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync001, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static uint32_t modelId = 0;
    SecurityModelResult result;
    (void) memset_s(&result, sizeof(SecurityModelResult), 0, sizeof(SecurityModelResult));
    int ret = RequestSecurityModelResultSync(&deviceIdentify, modelId, &result);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
    EXPECT_STREQ(reinterpret_cast<const char *>(result.devId.identity),
        reinterpret_cast<const char *>(deviceIdentify.identity));
    EXPECT_EQ(result.modelId, modelId);
    EXPECT_STREQ(reinterpret_cast<const char *>(result.result), "");
}

/**
 * @tc.name: RequestSecurityModelResultSync002
 * @tc.desc: RequestSecurityModelResultSync with right modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync002, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static uint32_t modelId = 3001000000;
    SecurityModelResult result;
    (void) memset_s(&result, sizeof(SecurityModelResult), 0, sizeof(SecurityModelResult));
    int ret = RequestSecurityModelResultSync(&deviceIdentify, modelId, &result);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
    EXPECT_STREQ(reinterpret_cast<const char *>(result.devId.identity),
        reinterpret_cast<const char *>(deviceIdentify.identity));
    EXPECT_TRUE(result.modelId == 0);
    EXPECT_STRNE(reinterpret_cast<const char *>(result.result), "unknown");
}

/**
 * @tc.name: RequestSecurityModelResultSync003
 * @tc.desc: RequestSecurityModelResultSync with null devId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync003, TestSize.Level1)
{
    static uint32_t modelId = 3001000000;
    SecurityModelResult result;
    (void) memset_s(&result, sizeof(SecurityModelResult), 0, sizeof(SecurityModelResult));
    int ret = RequestSecurityModelResultSync(nullptr, modelId, &result);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: RequestSecurityModelResultSync004
 * @tc.desc: RequestSecurityModelResultSync with null result
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultSync004, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static uint32_t modelId = 3001000000;
    int ret = RequestSecurityModelResultSync(&deviceIdentify, modelId, nullptr);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: RequestSecurityModelResultAsync001
 * @tc.desc: RequestSecurityModelResultAsync with wrong modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultAsync001, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static uint32_t modelId = 0;
    int ret = RequestSecurityModelResultAsync(&deviceIdentify, modelId, SecurityGuardRiskCallbackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityModelResultAsync002
 * @tc.desc: RequestSecurityModelResultAsync with right modelId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultAsync002, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static uint32_t modelId = 3001000000;
    int ret = RequestSecurityModelResultAsync(&deviceIdentify, modelId, SecurityGuardRiskCallbackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityModelResultAsync003
 * @tc.desc: RequestSecurityModelResultAsync with null devId
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskClassifyKitTest, RequestSecurityModelResultAsync003, TestSize.Level1)
{
    static uint32_t modelId = 3001000000;
    int ret = RequestSecurityModelResultAsync(nullptr, modelId, SecurityGuardRiskCallbackFunc);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}
}