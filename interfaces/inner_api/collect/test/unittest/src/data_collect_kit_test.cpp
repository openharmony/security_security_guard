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

#include "data_collect_kit_test.h"

#include "sg_collect_client.h"
#include "event_info.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;
using namespace OHOS::Security::SecurityGuard;

namespace {
}  // namespace

void DataCollectKitTest::SetUpTestCase()
{
}

void DataCollectKitTest::TearDownTestCase()
{
}

void DataCollectKitTest::SetUp()
{
}

void DataCollectKitTest::TearDown()
{
}

// RIGHT TEST
HWTEST_F(DataCollectKitTest, ReportSecurityInfo001, TestSize.Level1)
{
    int64_t eventId = 1011009000;
    std::string version = "0";
    std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, version, content);
    int ret = NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    EXPECT_EQ(ret, SUCCESS);
}

// wrong test:cred
HWTEST_F(DataCollectKitTest, ReportSecurityInfo002, TestSize.Level1)
{
    int64_t eventId = 1011009000;
    std::string version = "0";
    std::string content = "{\"cred\":\"0\",\"extra\":\"\",\"status\":0}";
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, version, content);
    int ret = NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    EXPECT_EQ(ret, BAD_PARAM);
}

// wrong test:extra
HWTEST_F(DataCollectKitTest, ReportSecurityInfo003, TestSize.Level1)
{
    int64_t eventId = 1011009000;
    std::string version = "0";
    std::string content = "{\"cred\":0,\"extra\":0,\"status\":0}";
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, version, content);
    int ret = NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    EXPECT_EQ(ret, BAD_PARAM);
}

// wrong test:status
HWTEST_F(DataCollectKitTest, ReportSecurityInfo004, TestSize.Level1)
{
    int64_t eventId = 1011009000;
    std::string version = "0";
    std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":\"0\"}";
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, version, content);
    int ret = NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    EXPECT_EQ(ret, BAD_PARAM);
}