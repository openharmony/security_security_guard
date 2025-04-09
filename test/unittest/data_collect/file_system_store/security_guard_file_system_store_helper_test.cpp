/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "security_guard_file_system_store_helper_test.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <dirent.h>
#include <zlib.h>
#include <sys/stat.h>
#include <algorithm>
#include "gmock/gmock.h"
#include "security_event_query_callback_proxy.h"
#include "security_event_info.h"
#define private public
#define protected public
#include "file_system_store_helper.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};
}

namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr int SUCCESS = 0;
}

void SecurityGuardFileSystemStoreHelperTest::SetUpTestCase()
{
}

void SecurityGuardFileSystemStoreHelperTest::TearDownTestCase()
{
}

void SecurityGuardFileSystemStoreHelperTest::SetUp()
{
}

void SecurityGuardFileSystemStoreHelperTest::TearDown()
{
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, QuerySecurityEventTest001, TestSize.Level1)
{
    int64_t eventId = 111;
    SecurityCollector::SecurityEventRuler ruler{eventId};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto proxy = iface_cast<ISecurityEventQueryCallback>(obj);
    EXPECT_EQ(FileSystemStoreHelper::GetInstance().QuerySecurityEvent(ruler, proxy), SUCCESS);
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, QuerySecurityEventTest002, TestSize.Level1)
{
    int64_t eventId = 111;
    std::string startTime = "20250228150000";
    std::string endTime = "20250228150100";
    SecurityCollector::SecurityEventRuler ruler{eventId};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto proxy = iface_cast<ISecurityEventQueryCallback>(obj);
    EXPECT_EQ(FileSystemStoreHelper::GetInstance().QuerySecurityEvent(ruler, proxy), SUCCESS);
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, QuerySecurityEventCallBackTest001, TestSize.Level1)
{
    std::vector<SecurityCollector::SecurityEvent> events;
    for (size_t i = 0; i < 2; i++) {
        int64_t eventId = 111;
        SecurityCollector::SecurityEvent event(eventId);
        events.push_back(event);
    }
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto proxy = iface_cast<ISecurityEventQueryCallback>(obj);
    FileSystemStoreHelper::GetInstance().QuerySecurityEventCallBack(proxy, events);
    for (size_t i = 0; i < 200; i++) {
        int64_t eventId = 111;
        SecurityCollector::SecurityEvent event(eventId);
        events.push_back(event);
    }
    FileSystemStoreHelper::GetInstance().QuerySecurityEventCallBack(proxy, events);
    nlohmann::json jsonEvent {
        {EVENT_ID, 111},
        {VERSION, "1.0"},
        {CONTENT, "{\"aaa\": \"111\"}"},
        {TIMESTAMP, "20250228150000"}
    };
    SecurityCollector::SecurityEvent parseEvent =
        FileSystemStoreHelper::GetInstance().SecurityEventFromJson(jsonEvent);
    EXPECT_EQ(parseEvent.GetEventId(), 111);
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, InsertEventTest001, TestSize.Level1)
{
    SecEvent event {
        .eventId = 111,
        .version = "1.0",
        .date = "20250228150000",
        .content = "{\"aaa\": \"111\"}"
    };
    EXPECT_EQ(FileSystemStoreHelper::GetInstance().InsertEvent(event), SUCCESS);
}

}