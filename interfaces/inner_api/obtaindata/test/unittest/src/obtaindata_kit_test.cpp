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

#include "obtaindata_kit_test.h"

#include "file_ex.h"

#include "sg_obtaindata_client.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;

#ifdef __cplusplus
extern "C" {
#endif
    int32_t RequestSecurityModelResultAsync(const DeviceIdentify *devId, uint32_t modelId,
        SecurityGuardRiskCallback callback);
#ifdef __cplusplus
}
#endif

namespace OHOS::Security::SecurityGuardTest {
std::string g_enforceValue = "0";

void ObtainDataKitTest::SetUpTestCase()
{
    bool isSuccess = LoadStringFromFile("/sys/fs/selinux/enforce", g_enforceValue);
    if (isSuccess && g_enforceValue == "1") {
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void ObtainDataKitTest::TearDownTestCase()
{
    SaveStringToFile("/sys/fs/selinux/enforce", g_enforceValue);
}

void ObtainDataKitTest::SetUp()
{
}

void ObtainDataKitTest::TearDown()
{
}

void ObtainDataKitTest::RequestSecurityEventInfoCallBackFunc(const DeviceIdentify *devId, const char *eventBuffList,
    uint32_t status)
{
    EXPECT_TRUE(devId != nullptr);
    EXPECT_TRUE(eventBuffList != nullptr);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync001
 * @tc.desc: RequestSecurityEventInfoAsync with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync001, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventId\":[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync002
 * @tc.desc: RequestSecurityEventInfoAsync with right param, get all info
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync002, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventId\":[-1]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync003
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList key
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync003, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync004
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync004, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{eventId:[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync005
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList null
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync005, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync006
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList not contain right eventId
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync006, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[0]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync007
 * @tc.desc: RequestSecurityEventInfoAsync with null devId
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync007, TestSize.Level1)
{
    static std::string eventList = "{\"eventIds\":[0]}";
    int ret = RequestSecurityEventInfoAsync(nullptr, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync008
 * @tc.desc: RequestSecurityEventInfoAsync with null eventList
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync008, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, nullptr, RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}
}