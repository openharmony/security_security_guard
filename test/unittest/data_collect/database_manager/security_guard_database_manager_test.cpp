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

#include "security_guard_database_manager_test.h"

#include "file_ex.h"
#include "gmock/gmock.h"
#include "security_event_info.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "database_manager.h"
#include "device_manager.h"
#include "i_db_listener.h"
#include "os_account_manager.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "risk_event_rdb_helper.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "data_format.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
    std::shared_ptr<NativeRdb::MockRdbHelperInterface> NativeRdb::RdbHelper::instance_ = nullptr;
    std::shared_ptr<AccountSA::MockOsAccountManagerInterface> AccountSA::OsAccountManager::instance_ = nullptr;
    std::mutex NativeRdb::RdbHelper::mutex_ {};
    std::mutex AccountSA::OsAccountManager::mutex_ {};
    constexpr uint32_t MAX_CONTENT_SIZE = 1500;
}

namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr int SUCCESS = 0;
}

class MockDbListener : public IDbListener {
public:
    ~MockDbListener() override = default;
    MOCK_METHOD3(OnChange, void(uint32_t optType, const SecEvent &events,
        const std::set<std::string> &eventSubscribes));
};

void SecurityGuardDatabaseManagerTest::SetUpTestCase()
{
}

void SecurityGuardDatabaseManagerTest::TearDownTestCase()
{
}

void SecurityGuardDatabaseManagerTest::SetUp()
{
}

void SecurityGuardDatabaseManagerTest::TearDown()
{
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock006, TestSize.Level1)
{
    uint32_t source = 0;
    SecEvent event{};
    event.eventId = 1011015001;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(
        Return(false)).WillOnce(
            [] (int64_t eventId, EventCfg &config) {
                config.source = 1;
                return true;
            }
        ).WillRepeatedly(
            [] (int64_t eventId, EventCfg &config) {
                config.source = 0;
                return true;
            });
    int ret = DatabaseManager::GetInstance().InsertEvent(source, event);
    EXPECT_EQ(ret, NOT_FOUND);
    ret = DatabaseManager::GetInstance().InsertEvent(source, event);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("audit_event"));
    ret = DatabaseManager::GetInstance().InsertEvent(source, event);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock008, TestSize.Level1)
{
    uint32_t source = 0;
    SecEvent event{};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
            config.source = 0;
            config.storageRomNums = 1;
            return true;
        });
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillRepeatedly(Return("risk_event"));
    EXPECT_CALL(*(AccountSA::OsAccountManager::GetInterface()), QueryActiveOsAccountIds).WillRepeatedly(
        Return(SUCCESS));
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), CountEventByEventId).WillOnce(Return(0)).WillOnce(Return(1));
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), InsertEvent).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), DeleteOldEventByEventId).WillOnce(Return(SUCCESS));
    int ret = DatabaseManager::GetInstance().InsertEvent(source, event);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().InsertEvent(source, event);
    EXPECT_EQ(ret, SUCCESS);
    AccountSA::OsAccountManager::DelInterface();
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock009, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryAllEvent).WillOnce(Return(SUCCESS));
    std::vector<SecEvent> events;
    int ret = DatabaseManager::GetInstance().QueryAllEvent("risk_event", events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryAllEvent("", events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock011, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryRecentEventByEventId(
        An<int64_t>(), An<SecEvent &>())).WillOnce(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("audit_event")).WillOnce(
        Return("risk_event")).WillOnce(Return(""));
    int64_t eventId = 0;
    SecEvent event;
    int ret = DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock012, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryRecentEventByEventId(
        An<const std::vector<int64_t> &>(), An<std::vector<SecEvent> &>())).WillOnce(Return(SUCCESS));
    std::vector<int64_t> eventIds{};
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryRecentEventByEventId("audit_event", eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryRecentEventByEventId("risk_event", eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryRecentEventByEventId("", eventIds, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock013, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByEventIdAndDate).WillOnce(Return(SUCCESS));
    std::vector<int64_t> eventIds{};
    std::vector<SecEvent> events{};
    std::string data;
    int ret = DatabaseManager::GetInstance().QueryEventByEventIdAndDate("audit_event", eventIds, events, data, data);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventIdAndDate("risk_event", eventIds, events, data, data);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventIdAndDate("", eventIds, events, data, data);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock014, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByEventId(
        An<int64_t>(), An<std::vector<SecEvent> &>())).WillOnce(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("audit_event")).WillOnce(
        Return("risk_event")).WillOnce(Return(""));
    int64_t eventId = 0;
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryEventByEventId(eventId, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventId(eventId, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventId(eventId, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock015, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByEventId(
        An<std::vector<int64_t> &>(), An<std::vector<SecEvent> &>())).WillOnce(Return(SUCCESS));
    std::vector<int64_t> eventIds{};
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryEventByEventId("audit_event", eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventId("risk_event", eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventId("", eventIds, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock016, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByEventType).WillOnce(Return(SUCCESS));
    int32_t eventType = 0;
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryEventByEventType("audit_event", eventType, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventType("risk_event", eventType, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByEventType("", eventType, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock017, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByLevel).WillOnce(Return(SUCCESS));
    int32_t level = 0;
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryEventByLevel("audit_event", level, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByLevel("risk_event", level, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByLevel("", level, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock018, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), QueryEventByOwner).WillOnce(Return(SUCCESS));
    std::string owner;
    std::vector<SecEvent> events{};
    int ret = DatabaseManager::GetInstance().QueryEventByOwner("audit_event", owner, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByOwner("risk_event", owner, events);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().QueryEventByOwner("", owner, events);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock019, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), CountAllEvent).WillOnce(Return(1));
    int ret = DatabaseManager::GetInstance().CountAllEvent("risk_event");
    EXPECT_EQ(ret, 1);
    ret = DatabaseManager::GetInstance().CountAllEvent("");
    EXPECT_EQ(ret, 0);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock020, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), CountEventByEventId).WillOnce(Return(1));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(
        Return("risk_event")).WillOnce(Return(""));
    int64_t eventId = 0;
    int ret = DatabaseManager::GetInstance().CountEventByEventId(eventId);
    EXPECT_EQ(ret, 1);
    ret = DatabaseManager::GetInstance().CountEventByEventId(eventId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock021, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), DeleteOldEventByEventId).WillOnce(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("audit_event")).WillOnce(
        Return("risk_event")).WillOnce(Return(""));
    int64_t eventId = 0;
    int64_t count = 0;
    int ret = DatabaseManager::GetInstance().DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock022, TestSize.Level1)
{
    EXPECT_CALL(RiskEventRdbHelper::GetInstance(), DeleteAllEventByEventId).WillOnce(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("audit_event")).WillOnce(
        Return("risk_event")).WillOnce(Return(""));
    int64_t eventId = 0;
    int ret = DatabaseManager::GetInstance().DeleteAllEventByEventId(eventId);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().DeleteAllEventByEventId(eventId);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().DeleteAllEventByEventId(eventId);
    EXPECT_EQ(ret, NOT_SUPPORT);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, TestDatabaseManagerMock023, TestSize.Level1)
{
    auto mockListener = std::make_shared<MockDbListener>();
    EXPECT_CALL(*mockListener, OnChange).Times(Exactly(2));
    std::vector<int64_t> eventIds{0, 1, 2, 3};
    int ret = DatabaseManager::GetInstance().SubscribeDb(eventIds, nullptr);
    EXPECT_EQ(ret, NULL_OBJECT);
    ret = DatabaseManager::GetInstance().SubscribeDb(eventIds, mockListener);
    EXPECT_EQ(ret, SUCCESS);
    SecEvent event{};
    event.eventId = 0;
    DatabaseManager::GetInstance().DbChanged(1, event);
    event.eventId = 1;
    DatabaseManager::GetInstance().DbChanged(1, event);
    event.eventId = 5;
    DatabaseManager::GetInstance().DbChanged(1, event);
    std::vector<int64_t> tmpEventIds{5, 6, 7, 8};
    ret = DatabaseManager::GetInstance().UnSubscribeDb(eventIds, nullptr);
    EXPECT_EQ(ret, NULL_OBJECT);
    ret = DatabaseManager::GetInstance().UnSubscribeDb(tmpEventIds, mockListener);
    EXPECT_EQ(ret, SUCCESS);
    ret = DatabaseManager::GetInstance().UnSubscribeDb(eventIds, mockListener);
    EXPECT_EQ(ret, SUCCESS);
}


HWTEST_F(SecurityGuardDatabaseManagerTest, CheckRiskContent001, TestSize.Level1)
{
    std::string content(MAX_CONTENT_SIZE, 'c');
    bool ret = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(ret);
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions001, TestSize.Level1)
{
    std::string conditions;
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions002, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":0}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions003, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":[\"t\", \"e\", \"s\", \"t\"]}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions004, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":[1, 2, 3, 4]}";
    RequestCondition reqCondition;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("risk_event"))
        .WillRepeatedly(Return("audit_event"));
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_FALSE(reqCondition.riskEvent.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions005, TestSize.Level1)
{
    std::string conditions = "{\"beginTime\":1}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.beginTime.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions006, TestSize.Level1)
{
    std::string conditions = "{\"beginTime\":\"0001\"}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.beginTime == "0001");
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions007, TestSize.Level1)
{
    std::string conditions = "{\"endTime\":1}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.endTime.empty());
}

HWTEST_F(SecurityGuardDatabaseManagerTest, ParseConditions008, TestSize.Level1)
{
    std::string conditions = "{\"endTime\":\"0001\"}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.endTime == "0001");
}

}