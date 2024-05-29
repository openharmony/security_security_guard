/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hiview_listener_test.h"

#include <thread>
#include <iostream>
#include <cstring>
#include <securec.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include "hilog/log.h"
#include "file_ex.h"
#include "hisysevent_listener.h"

#define private public
#include "hiview_listener.h"
#undef private

using namespace OHOS::Security::SecurityGuard;

namespace OHOS::Security::SecurityGuardTest {

OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE,
    0xD002402,
    "hiview_listener_test"
};

std::int64_t g_eventId = 0;

void HiviewListenerTest::SetUpTestCase()
{
    std::cout << "SetUpTestCase called!" << std::endl;
}

void HiviewListenerTest::TearDownTestCase()
{
    std::cout << "TearDownTestCase called!" << std::endl;
}

void HiviewListenerTest::SetUp()
{
}

void HiviewListenerTest::TearDown()
{
}

HWTEST_F(HiviewListenerTest, TestHiviewListener001, testing::ext::TestSize.Level1)
{
    std::string jsonStr = "{\"moduleList\":[],\"modules\":[{\"moduleId\":\"0\",";
    jsonStr += "\"moduleName\":\"libaudit_window_collector.z.so\",\"modulePath\":\"/system/lib64/\",\"version\":0}]}";
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr.c_str(), nullptr, false);
    HiviewListener listener;
    listener.filterInstallOrUpdateContent(0x818800800, jsonObject);
}

HWTEST_F(HiviewListenerTest, TestHiviewListener002, testing::ext::TestSize.Level1)
{
    std::string jsonStr = "{\"moduleList\":[],\"modules\":[{\"moduleId\":\"0\",";
    jsonStr += "\"moduleName\":\"libaudit_window_collector.z.so\",\"modulePath\":\"/system/lib64/\",\"version\":0}]}";
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr.c_str(), nullptr, false);
    HiviewListener listener;
    EXPECT_TRUE(listener.filterHashValue(jsonObject));
}
}