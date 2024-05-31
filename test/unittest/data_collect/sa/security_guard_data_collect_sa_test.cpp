/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_guard_data_collect_sa_test.h"

#include <thread>
#include <vector>

#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"
#include "system_ability_definition.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "acquire_data_subscribe_manager.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_format.h"
#include "database_manager.h"
#include "data_collect_manager_service.h"
#include "security_event_query_callback_proxy.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
namespace OHOS {
    std::shared_ptr<Security::SecurityGuard::MockDataFormatInterface> DataFormat::instance_ = nullptr;
    std::shared_ptr<Security::AccessToken::MockAccessTokenKitInterface>
        Security::AccessToken::AccessTokenKit::instance_ = nullptr;
    std::mutex Security::SecurityGuard::DataFormat::mutex_ {};
    std::mutex Security::AccessToken::AccessTokenKit::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {
DataCollectManagerService g_service(DATA_COLLECT_MANAGER_SA_ID, true);

void SecurityGuardDataCollectSaTest::SetUpTestCase()
{
}

void SecurityGuardDataCollectSaTest::TearDownTestCase()
{
    DataFormat::DelInterface();
    AccessToken::AccessTokenKit::DelInterface();
}

void SecurityGuardDataCollectSaTest::SetUp()
{
}

void SecurityGuardDataCollectSaTest::TearDown()
{
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidFd, TestSize.Level1)
{
    int fd = -1;
    std::vector<std::u16string> args;
    EXPECT_EQ(g_service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidArgs, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(g_service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithHelpCommand, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-h" };
    EXPECT_EQ(g_service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithOtherCommand, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-s" };
    EXPECT_EQ(g_service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId01, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"invalid" };
    EXPECT_EQ(g_service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId02, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i" };
    EXPECT_EQ(g_service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithValidEventId, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"12345" };
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(_, _))
        .WillOnce(Return(SUCCESS));
    EXPECT_EQ(g_service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_Success, TestSize.Level1) {
    SecEvent secEvent;
    secEvent.eventId = 1;
    secEvent.date = "2022-01-01";
    secEvent.version = "1.0";

    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(SUCCESS));

    g_service.DumpEventInfo(1, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_QueryError, TestSize.Level1) {
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(FAILED));
    g_service.DumpEventInfo(1, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, GetSecEventsFromConditions_NoTimeCondition, TestSize.Level1) {
    RequestCondition condition{};
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });

    std::vector<SecEvent> events = g_service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
    EXPECT_EQ(events[1].eventId, 0);
}

HWTEST_F(SecurityGuardDataCollectSaTest, GetSecEventsFromConditions_WithTimeCondition, TestSize.Level1) {
    RequestCondition condition;
    condition.riskEvent = {};
    condition.auditEvent = {};
    condition.beginTime = "2022-01-01";
    condition.endTime = "2022-01-31";

    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventIdAndDate(_, _, _, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });

    std::vector<SecEvent> events = g_service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
    EXPECT_EQ(events[1].eventId, 0);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_GetEventConfigError, TestSize.Level1)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    EXPECT_CALL(*obj, SendRequest).Times(1);
    EXPECT_FALSE(g_service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_QueryInDatabase, TestSize.Level1)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);

    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.eventType = 0;
        return true;
    });
    SecEvent event;
    event.eventId = 1;
    event.version = 1;
    event.content = "content";
    std::vector<SecEvent> events{event};
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _)).WillRepeatedly(Return(true));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    EXPECT_CALL(*obj, SendRequest).Times(1);
    EXPECT_TRUE(g_service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_QueryInCollector, TestSize.Level1)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.eventType = 1;
        return true;
    });
    SecurityCollector::SecurityEvent event;
    event.eventId_ = 1;
    event.version_ = 1;
    event.content_ = "content";
    std::vector<SecurityCollector::SecurityEvent> events{event};
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), QuerySecurityEvent(_, _)).WillOnce(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    EXPECT_CALL(*obj, SendRequest).Times(1);
    EXPECT_TRUE(g_service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_NotSupportType, TestSize.Level1)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.eventType = 2;
        return true;
    });
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    EXPECT_TRUE(g_service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_NullProxy, TestSize.Level1)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj = nullptr;
    g_service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_EmptyConditions, TestSize.Level1)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(mockObj != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition = {};
        });
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    ON_CALL(*mockObj, SendRequest)
        .WillByDefault([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    g_service.PushDataCollectTask(mockObj, "", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_ValidConditions01, TestSize.Level1)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition.auditEvent = {1};
        });
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    g_service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(1, promise->get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_ValidConditions02, TestSize.Level1)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(mockObj != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition.auditEvent = {1};
        });
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            return SUCCESS;
        });
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    g_service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_RiskAnalysisManagerSaId, TestSize.Level1)
{
    std::vector<int64_t> whiteList{};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds()).WillOnce(Return(whiteList));
    g_service.OnAddSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID, "deviceId");
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_SoftbusServerSaId, TestSize.Level1)
{
    EXPECT_CALL(DatabaseManager::GetInstance(), InitDeviceId()).WillOnce(Return(0));
    g_service.OnAddSystemAbility(SOFTBUS_SERVER_SA_ID, "deviceId");
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_DistributedHardwareDeviceManagerSaId, TestSize.Level1)
{
    EXPECT_CALL(DatabaseManager::GetInstance(), InitDeviceId()).WillOnce(Return(0));
    g_service.OnAddSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, "deviceId");
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_DfxSysHiviewAbilityId, TestSize.Level1)
{
    g_service.OnAddSystemAbility(DFX_SYS_HIVIEW_ABILITY_ID, "deviceId");
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_NoPermission, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t result = g_service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_BadParam, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(false));

    int32_t result = g_service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success01, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillOnce(Return(FAILED));

    int32_t result = g_service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success02, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillOnce(Return(SUCCESS));

    int32_t result = g_service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData01, TestSize.Level1)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));

    int32_t result = g_service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData02, TestSize.Level1)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));

    int32_t result = g_service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));

    int32_t result = g_service.Subscribe(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Unsubscribe01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));

    int32_t result = g_service.Unsubscribe(mockObj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeRecord_Success, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillOnce(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillOnce(Return(SUCCESS));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeRecord_Fail01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_NE(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj2);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj);
    EXPECT_EQ(result, FAILED);
    result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj2);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_WithSubscribers, TestSize.Level1)
{
    SecEvent event {
        .eventId = 1,
        .version = "version",
        .content = "content"
    };
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().Publish(event));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NullProxy, TestSize.Level1)
{
    SecEvent event {
        .eventId = 2,
        .version = "version",
        .content = "content"
    };
    SecurityCollector::Event event2 {
        .eventId = 2,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> obj = nullptr;
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_FALSE(AcquireDataSubscribeManager::GetInstance().Publish(event));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NotNullProxy, TestSize.Level1)
{
    SecEvent event {
        .eventId = SecurityCollector::FILE_EVENTID,
        .version = "version",
        .content = "content"
    };
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::FILE_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> mockObject(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*mockObject, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObject);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().Publish(event));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(mockObject);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId01, TestSize.Level1)
{
    SecEvent event {
        .eventId = 1,
        .version = "version",
        .content = "content"
    };
    SecurityCollector::Event event2 {
        .eventId = 1,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*mockObj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().Publish(event));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(mockObj);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId02, TestSize.Level1)
{
    SecEvent event {
        .eventId = SecurityCollector::PROCESS_EVENTID,
        .version = "version",
        .content = "content"
    };
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::PROCESS_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> object(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*object, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, object);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().Publish(event));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(object);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId03, TestSize.Level1)
{
    SecEvent event {
        .eventId = SecurityCollector::NETWORK_EVENTID,
        .version = "version",
        .content = "content"
    };
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::NETWORK_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().Publish(event));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(obj);
    EXPECT_EQ(result, SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd01, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_REQUEST);
    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd02, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_REQUEST);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_REQUEST, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd03, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_SUBSCRIBE);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_SUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd04, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd05, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd06, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt64(0);
    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd07, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt64(0);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_REQUEST, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd08, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    SecurityCollector::Event event {
        .eventId = 0,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(obj);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_SUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd09, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    data.WriteRemoteObject(obj);

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd10, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(MAX_QUERY_EVENT_SIZE + 1);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd11, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(1);
    SecurityCollector::SecurityEventRuler ruler;
    data.WriteParcelable(&ruler);

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithInvalidCmd, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(100);

    int32_t result = g_service.OnRemoteRequest(100, data, reply, option);

    EXPECT_EQ(result, 305);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithInvalidToken, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(u"InvalidToken");

    int32_t result = g_service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);

    EXPECT_EQ(result, 305);
}
}
