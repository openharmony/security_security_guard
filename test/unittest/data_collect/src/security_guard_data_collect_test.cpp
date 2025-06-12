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

#include "security_guard_data_collect_test.h"
#include <fstream>
#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "store_define.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "database.h"
#include "database_manager.h"
#include "device_manager.h"
#include "os_account_manager.h"
#include "preferences_helper.h"
#include "risk_event_rdb_helper.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
    std::mutex AccountSA::OsAccountManager::mutex_ {};
    std::mutex NativePreferences::PreferencesHelper::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr int SUCCESS = 0;
    constexpr int FAILED = -1;
}

void SecurityGuardDataCollectTest::SetUpTestCase()
{
}

void SecurityGuardDataCollectTest::TearDownTestCase()
{
}

void SecurityGuardDataCollectTest::SetUp()
{
}

void SecurityGuardDataCollectTest::TearDown()
{
}

HWTEST_F(SecurityGuardDataCollectTest, InitCleanup, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    DatabaseHelper helper1("");
    EXPECT_EQ(helper1.Init(), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, InsertSpecCharContent, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    SecEvent event{};
    event.content = "invalid";
    EXPECT_EQ(helper.InsertEvent(event), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, FullFieldQuery, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    helper.QueryAllEvent(results);
    EXPECT_FALSE(results.empty());
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryRecentEventByEventId, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    SecEvent event{};
    int64_t eventId = 0;
    EXPECT_EQ(helper.QueryRecentEventByEventId(eventId, event), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryRecentEventByEventIds, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    std::vector<int64_t> eventIds;
    eventIds.push_back(1);
    eventIds.push_back(0);
    EXPECT_EQ(helper.QueryRecentEventByEventId(eventIds, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByEventId, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    int64_t eventId = 0;
    EXPECT_EQ(helper.QueryEventByEventId(eventId, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByEventIdS, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    std::vector<int64_t> eventIds;
    eventIds.push_back(1);
    eventIds.push_back(0);
    EXPECT_EQ(helper.QueryEventByEventId(eventIds, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByDate, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    std::vector<int64_t> eventIds;
    std::string date{"111"};
    EXPECT_EQ(helper.QueryEventByEventIdAndDate(eventIds, results, date, date), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByType, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    EXPECT_EQ(helper.QueryEventByEventType(0, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByLevel, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    EXPECT_EQ(helper.QueryEventByLevel(0, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryByOwner, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    std::vector<SecEvent> results;
    std::string owner;
    EXPECT_EQ(helper.QueryEventByOwner(owner, results), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestCountAllEvent, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    EXPECT_EQ(helper.CountAllEvent(), 0);
}

HWTEST_F(SecurityGuardDataCollectTest, TestCountEventByID, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    EXPECT_EQ(helper.CountEventByEventId(0), 0);
}

HWTEST_F(SecurityGuardDataCollectTest, TestDeleteOldEvent, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    EXPECT_NE(helper.DeleteOldEventByEventId(0, 0), SUCCESS);
    EXPECT_EQ(helper.DeleteOldEventByEventId(0, 1), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestDeleteAllEvent, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    EXPECT_NE(helper.DeleteAllEventByEventId(-1), SUCCESS);
    EXPECT_EQ(helper.DeleteAllEventByEventId(0), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestFlushAllEvent, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    EXPECT_EQ(helper.FlushAllEvent(), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestQueryEventBase, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    GenericValues conditions;
    std::vector<SecEvent> events;
    EXPECT_EQ(helper.QueryEventBase(conditions, events), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestCreateTable, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_TRUE(!helper.CreateTable().empty());
}

HWTEST_F(SecurityGuardDataCollectTest, TestSetValueBucket, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    EXPECT_EQ(helper.Init(), SUCCESS);
    SecEvent event{};
    event.content = "11111";
    GenericValues value;
    helper.SetValuesBucket(event, value);
}

HWTEST_F(SecurityGuardDataCollectTest, TestJoin, TestSize.Level1)
{
    RiskEventRdbHelper helper;
    std::vector<std::string> vec;
    EXPECT_TRUE(helper.Join(vec, "").empty());

    vec.push_back("1111,1111,1111,1111");
    EXPECT_FALSE(helper.Join(vec, ",").empty());

    std::vector<int64_t> nums;
    EXPECT_TRUE(helper.Join(nums, "").empty());

    nums.push_back(11111);
    nums.push_back(22222);
    EXPECT_FALSE(helper.Join(nums, ",").empty());
    EXPECT_FALSE(helper.FilterSpecialChars("11111").empty());
}

HWTEST_F(SecurityGuardDataCollectTest, StrToULL001, TestSize.Level1)
{
    std::string test = "abc";
    unsigned long long value = 0;
    EXPECT_FALSE(SecurityGuardUtils::StrToULL(test, value));
    test = "1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToULL(test, value));
    test = "abc111";
    EXPECT_FALSE(SecurityGuardUtils::StrToULL(test, value));
    test = "111aaa";
    EXPECT_FALSE(SecurityGuardUtils::StrToULL(test, value));
    test = "aaa";
    EXPECT_FALSE(SecurityGuardUtils::StrToULL(test, value));
    test = "111";
    EXPECT_TRUE(SecurityGuardUtils::StrToULL(test, value));
}

HWTEST_F(SecurityGuardDataCollectTest, StrToLL001, TestSize.Level1)
{
    std::string test = "abc";
    long long value = 0;
    int32_t dec = 10;
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, dec));
    test = "1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, dec));
    test = "abc111";
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, dec));
    test = "111aaa";
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, dec));
    test = "aaa";
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, dec));
    test = "111";
    EXPECT_TRUE(SecurityGuardUtils::StrToLL(test, value, dec));
}

HWTEST_F(SecurityGuardDataCollectTest, StrToLL002, TestSize.Level1)
{
    std::string test = "zzz";
    long long value = 0;
    int32_t hec = 16;
    EXPECT_FALSE(SecurityGuardUtils::StrToLL(test, value, hec));
}

HWTEST_F(SecurityGuardDataCollectTest, StrToU32001, TestSize.Level1)
{
    std::string test = "123";
    uint32_t value = 0;
    EXPECT_TRUE(SecurityGuardUtils::StrToU32(test, value));
    test = "1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToU32(test, value));
    test = "111bac";
    EXPECT_FALSE(SecurityGuardUtils::StrToU32(test, value));
}

HWTEST_F(SecurityGuardDataCollectTest, StrToI64001, TestSize.Level1)
{
    std::string test = "123";
    int64_t value = 0;
    EXPECT_TRUE(SecurityGuardUtils::StrToI64(test, value));
    test = "1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64(test, value));
    test = "-1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64(test, value));
    test = "111bac";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64(test, value));
}

HWTEST_F(SecurityGuardDataCollectTest, StrToI64Hex001, TestSize.Level1)
{
    std::string test = "abc";
    int64_t value = 0;
    EXPECT_FALSE(SecurityGuardUtils::StrToI64Hex(test, value));
    test = "1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64Hex(test, value));
    test = "-1844674407370955161511111";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64Hex(test, value));
    test = "111bac";
    EXPECT_FALSE(SecurityGuardUtils::StrToI64Hex(test, value));
    test = "0x111";
    EXPECT_TRUE(SecurityGuardUtils::StrToI64Hex(test, value));
}

HWTEST_F(SecurityGuardDataCollectTest, TestCopyFile001, TestSize.Level1)
{
    const std::string CONFIG_CACHE_FILE = "${sg_root_dir}/oem_property/hos/security_guard_event.json";
    const std::string CONFIG_UPTATE_FILE = "/data/service/el1/public/security_guard/security_guard_event.json";
    std::ifstream src(CONFIG_CACHE_FILE, std::ios::binary);
    EXPECT_FALSE(SecurityGuardUtils::CopyFile(CONFIG_CACHE_FILE, CONFIG_UPTATE_FILE));
}

HWTEST_F(SecurityGuardDataCollectTest, TestGetDate001, TestSize.Level1)
{
    std::string date = SecurityGuardUtils::GetDate();
    EXPECT_TRUE(!date.empty());
}

}