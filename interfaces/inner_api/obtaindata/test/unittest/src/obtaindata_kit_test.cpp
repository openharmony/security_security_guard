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
#include "security_guard_define.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;
using namespace OHOS::Security::SecurityGuard;

namespace OHOS::Security::SecurityGuardTest {
void ObtainDataKitTest::SetUpTestCase()
{
}

void ObtainDataKitTest::TearDownTestCase()
{
}

void ObtainDataKitTest::SetUp()
{
    callback_ = std::make_shared<RequestSecurityEventInfoCallbackMock>();
}

void ObtainDataKitTest::TearDown()
{
}

/**
 * @tc.name: RequestSecurityEventInfoAsync001
 * @tc.desc: RequestSecurityEventInfoAsync with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync001, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{\"eventId\":[1011009000]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync002
 * @tc.desc: RequestSecurityEventInfoAsync with right param, get all info
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync002, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{\"eventId\":[-1]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync003
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList key
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync003, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{\"eventIds\":[1011009000]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync004
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync004, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{eventId:[1011009000]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync005
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList null
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync005, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{\"eventIds\":[]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync006
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList not contain right eventId
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(ObtainDataKitTest, RequestSecurityEventInfoAsync006, TestSize.Level1)
{
    static std::string devId = "";
    static std::string eventList = "{\"eventIds\":[0]}";
    int ret = ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback_);
    EXPECT_EQ(ret, SUCCESS);
}
}