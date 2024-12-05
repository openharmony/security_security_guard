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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"
#include "system_ability_definition.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "security_config_update_info.h"
#include "security_event_info.h"
#include "config_define.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "acquire_data_subscribe_manager.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager.h"
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
    std::shared_ptr<Security::AccessToken::MockTokenIdKitInterface>
        Security::AccessToken::TokenIdKit::instance_ = nullptr;
    std::mutex Security::SecurityGuard::DataFormat::mutex_ {};
    std::mutex Security::AccessToken::AccessTokenKit::mutex_ {};
    std::mutex Security::AccessToken::TokenIdKit::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {

#ifndef SECURITY_GUARD_ENABLE_EXT
    const std::string &SECURITY_GUARD_EVENT_CFG_FILE = "security_guard_event.json";
#else
    const std::string &SECURITY_GUARD_EVENT_CFG_FILE = "security_guard_event_ext.json";
#endif

void SecurityGuardDataCollectSaTest::SetUpTestCase()
{
}

void SecurityGuardDataCollectSaTest::TearDownTestCase()
{
    DataFormat::DelInterface();
    AccessToken::AccessTokenKit::DelInterface();
    AccessToken::TokenIdKit::DelInterface();
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);

    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidArgs, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithHelpCommand, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-h" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithOtherCommand, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-s" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId01, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"invalid" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId02, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithValidEventId, TestSize.Level1)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"12345" };
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(_, _))
        .WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_Success, TestSize.Level1) {
    SecEvent secEvent;
    secEvent.eventId = 1;
    secEvent.date = "2022-01-01";
    secEvent.version = "1.0";

    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.DumpEventInfo(1, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_QueryError, TestSize.Level1) {
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.DumpEventInfo(1, 1);
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<SecEvent> events = service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<SecEvent> events = service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_GetEventConfigError001, TestSize.Level1)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_GetEventConfigError002, TestSize.Level1)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*obj, SendRequest).Times(1);
    mockProxy->OnError("123");
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_NotSupportType, TestSize.Level1)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([] (
        int64_t eventId, EventCfg &config) {
        config.eventType = 2;
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    EXPECT_CALL(*obj, SendRequest).Times(1);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_BeginTimeEmpty, TestSize.Level1)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([] (
        int64_t eventId, EventCfg &config) {
        config.eventType = 2;
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler(2, "", "11", "tt");
    EXPECT_CALL(*obj, SendRequest).Times(1);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_NullProxy, TestSize.Level1)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj = nullptr;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    ON_CALL(*mockObj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    service.PushDataCollectTask(mockObj, "", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(1, promise->get_future().get());
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_RiskAnalysisManagerSaId, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.OnAddSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID, "deviceId");
}

HWTEST_F(SecurityGuardDataCollectSaTest, OnAddSystemAbility_DfxSysHiviewAbilityId, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.OnAddSystemAbility(DFX_SYS_HIVIEW_ABILITY_ID, "deviceId");
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_NoPermission, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
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
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
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
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillRepeatedly(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success02, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillRepeatedly(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success03, TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillRepeatedly(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content, false);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData01, TestSize.Level1)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData02, TestSize.Level1)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    service.OnRemoveSystemAbility(0, "dd");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData03, TestSize.Level1)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Subscribe(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Unsubscribe01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Unsubscribe(subscribeInfo, mockObj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe02, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Subscribe(subscribeInfo, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Unsubscribe02, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Unsubscribe(subscribeInfo, mockObj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe03, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IPCObjectProxy::DeathRecipient> rec = nullptr;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&rec] (const sptr<IPCObjectProxy::DeathRecipient> &recipient) {
            rec = recipient;
            return true;
        });
    int32_t result = service.Subscribe(subscribeInfo, obj);
    EXPECT_NE(result, SUCCESS);

    EXPECT_CALL(*obj, RemoveDeathRecipient).Times(1);
    result = service.Unsubscribe(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeRecord_Success, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillOnce(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillOnce(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeRecord_Fail01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_NE(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj2);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj2);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_WithSubscribers, TestSize.Level1)
{
    SecurityCollector::Event event {
        .eventId = 1,
        .version = "version",
        .content = "content"
    };
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NullProxy, TestSize.Level1)
{
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
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NotNullProxy, TestSize.Level1)
{
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*mockObject, SendRequest)
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObject);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId,
        mockObject);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId01, TestSize.Level1)
{
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*mockObj, SendRequest)
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId,
        mockObj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId02, TestSize.Level1)
{
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*object, SendRequest)
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, object);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, object);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId03, TestSize.Level1)
{
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().BatchPublish(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc01, TestSize.Level1)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    adsm.scSubscribeMap_.insert({111,
        std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(event)});
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc02, TestSize.Level1)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, FAILED);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc03, TestSize.Level1)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return true;
    });
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe(_)).WillOnce(Return(FAILED));
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, FAILED);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc04, TestSize.Level1)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return true;
    });
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe(_)).WillOnce(Return(SUCCESS));
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Unsubscribe(_)).WillOnce(Return(SUCCESS));
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrUnsubscribeSc01, TestSize.Level1)
{
    AcquireDataSubscribeManager adsm {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return false;
    });
    int result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd01, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_REQUEST);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd02, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_REQUEST);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_REQUEST, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd03, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_SUBSCRIBE);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_SUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd04, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd05, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt32(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd07, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteInt64(0);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_REQUEST, data, reply, option);
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_SUBSCRIBE, data, reply, option);
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

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_UNSUBSCRIBE, data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd10, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(MAX_QUERY_EVENT_SIZE + 1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_EVENT_QUERY,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd12, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_COLLECTOR_START,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd13, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollector::Event event {};
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event, -1, false);
    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    data.WriteRemoteObject(obj);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_COLLECTOR_START,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd14, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_COLLECTOR_START,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd15, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteFileDescriptor(-1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_CONFIG_UPDATE,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd16, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteString("test");
    data.WriteFileDescriptor(-1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_CONFIG_UPDATE,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd17, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteString("test");
    data.WriteFileDescriptor(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_CONFIG_UPDATE,
        data, reply, option);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd19, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollector::Event event {};
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event, -1, false);
    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    data.WriteRemoteObject(obj);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_COLLECTOR_STOP,
        data, reply, option);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithDataRequestCmd20, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    data.WriteUint32(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_SECURITY_COLLECTOR_STOP,
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
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(100, data, reply, option);

    EXPECT_EQ(result, 305);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestOnRemoteRequestWithInvalidToken, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"InvalidToken");
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.OnRemoteRequest(DataCollectManagerService::CMD_DATA_COLLECT, data, reply, option);

    EXPECT_EQ(result, 305);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent, TestSize.Level1)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent01, TestSize.Level1)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj);
    EXPECT_CALL(*obj, SendRequest).Times(2);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent02, TestSize.Level1)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent03, TestSize.Level1)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj);
    EXPECT_EQ(result, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart02, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart03, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStart(_)).WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart04, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStart(_)).WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop01, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop02, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop03, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStop(_)).WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop04, TestSize.Level1)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStop(_)).WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, IsApiHasPermission01, TestSize.Level1)
{
    const std::string api = "testString";
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.IsApiHasPermission(api);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate01, TestSize.Level1)
{
    SecurityGuard::SecurityConfigUpdateInfo  subscribeInfo{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(subscribeInfo);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate02, TestSize.Level1)
{
    SecurityGuard::SecurityConfigUpdateInfo subscribeInfo{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(subscribeInfo);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate03, TestSize.Level1)
{
    SecurityGuard::SecurityConfigUpdateInfo subscribeInfo{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(subscribeInfo);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate04, TestSize.Level1)
{
    SecurityGuard::SecurityConfigUpdateInfo subscribeInfo(-1,
        SECURITY_GUARD_EVENT_CFG_FILE);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(subscribeInfo);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, WriteRemoteFileToLocal01, TestSize.Level1)
{
    std::ofstream out("/data/test/unittest/resource/test.json");
    std::string errtmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errtmp << std::endl;
    int32_t fd = open("/data/test/unittest/resource/test.json", O_RDONLY);
    SecurityGuard::SecurityConfigUpdateInfo subscribeInfo(fd, "test.json");

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string toPath = "/data/test/unittest/resource/";
    int32_t result = service.WriteRemoteFileToLocal(subscribeInfo, toPath + "testFile.json");
    close(fd);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, WriteRemoteFileToLocal02, TestSize.Level1)
{
    std::ofstream out("/data/test/unittest/resource/test.json");
    std::string errtmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errtmp << std::endl;
    int32_t fd = 0;
    SecurityGuard::SecurityConfigUpdateInfo subscribeInfo(fd, "test.json");

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string toPath = "/data/test/unittest/resource/";
    int32_t result = service.WriteRemoteFileToLocal(subscribeInfo, toPath + "testFile.json");
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventConfig001, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string queryInfo;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t ret = service.QuerySecurityEventConfig(queryInfo);
    EXPECT_EQ(ret, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventConfig002, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string queryInfo;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    std::vector<EventCfg> vector{0};
    std::vector<EventCfg> emptyVector{};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventConfigs).WillOnce(Return(emptyVector))
        .WillRepeatedly(Return(vector));
    int32_t ret = service.QuerySecurityEventConfig(queryInfo);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ParseTrustListFile001, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_FALSE(service.ParseTrustListFile(""));
}
}
