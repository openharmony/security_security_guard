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

class MockFileSystemStorHelper : public FileSystemStoreHelper {
public:
    MOCK_METHOD1(GetStoreFileList, int32_t(std::vector<std::string>& storeFiles));
    MOCK_METHOD1(GetFileSize, size_t(const std::string& filepath));
    MOCK_METHOD1(GetTimestampFromFileName, std::string(const std::string& filename));
};

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, GetLatestStoreFile01, TestSize.Level1)
{
    MockFileSystemStorHelper helper {};
    EXPECT_CALL(helper, GetStoreFileList).WillOnce(Return(1)).WillOnce(Return(SUCCESS)).WillOnce(
        Return(1)).WillOnce(Return(SUCCESS));
    helper.DeleteOldestStoreFile();
    helper.DeleteOldestStoreFile();
    EXPECT_EQ(helper.GetLatestStoreFile(), "");
    EXPECT_EQ(helper.GetLatestStoreFile(), "");
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, GetLatestStoreFile02, TestSize.Level1)
{
    MockFileSystemStorHelper helper {};
    EXPECT_CALL(helper, GetStoreFileList).WillRepeatedly([](std::vector<std::string>& storeFiles) {
        for (size_t i = 0; i < MAX_STORE_FILE_COUNT + 1; i++) {
            storeFiles.emplace_back("test");
        }
        return SUCCESS;
    });
    EXPECT_CALL(helper, GetFileSize).WillRepeatedly(Return(SINGLE_FILE_SIZE));
    EXPECT_CALL(helper, GetTimestampFromFileName).WillOnce([] (const std::string& filename) {
        return "test_test";
    });
    helper.DeleteOldestStoreFile();
    EXPECT_EQ(helper.GetLatestStoreFile(), "");
}

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, InsertEvents01, TestSize.Level1)
{
    MockFileSystemStorHelper helper {};
    EXPECT_EQ(helper.InsertEvents({}), SUCCESS);
}

class MockFileSystemStorHelper01 : public FileSystemStoreHelper {
public:
    MOCK_METHOD1(GetFileSize, size_t(const std::string& filepath));
    MOCK_METHOD1(GetTimestampFromFileName, std::string(const std::string& filename));
    MOCK_METHOD0(GetLatestStoreFile, std::string());
};

HWTEST_F(SecurityGuardFileSystemStoreHelperTest, InsertEvents02, TestSize.Level1)
{
    MockFileSystemStorHelper01 helper {};
    EXPECT_CALL(helper, GetLatestStoreFile).WillRepeatedly(Return(""));
    EXPECT_CALL(helper, GetFileSize).WillOnce(Return(0)).WillOnce(Return(SINGLE_FILE_SIZE));
    helper.currentGzFile_ = nullptr;
    SecEvent event {
        .eventId = 111,
        .version = "1.0",
        .date = "20250228150000",
        .content = "{\"aaa\": \"111\"}"
    };
    std::vector<SecEvent> events;
    events.emplace_back(event);
    EXPECT_EQ(helper.InsertEvents({events}), SUCCESS);
    EXPECT_EQ(helper.InsertEvents({events}), SUCCESS);
}

}