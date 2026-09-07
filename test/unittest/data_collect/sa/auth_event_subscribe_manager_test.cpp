/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "security_guard_define.h"
#include "system_ability_definition.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "acquire_data_subscribe_manager.h"
#include "auth_event_subscribe_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager_service.h"
#include "i_auth_event_callback.h"
#include "security_event_query_callback_proxy.h"
#undef private
#undef protected

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security;
using namespace OHOS::Security::SecurityGuard;

namespace {
class AuthEventSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        auto &manager = AuthEventSubscribeManager::GetInstance();
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        manager.sessionsMap_.clear();
        manager.authResults_.clear();
        manager.pendingResults_.clear();
        manager.allowedUids_.clear();
    }
    void TearDown() override {}
};

sptr<MockRemoteObject> CreateRemoteObject()
{
    auto obj = sptr<MockRemoteObject>(new (std::nothrow) MockRemoteObject());
    if (obj != nullptr) {
        ON_CALL(*obj, AddDeathRecipient(_)).WillByDefault(Return(true));
        ON_CALL(*obj, RemoveDeathRecipient(_)).WillByDefault(Return(true));
    }
    return obj;
}
}

HWTEST_F(AuthEventSubscribeManagerTest, IsUidAllowed001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 空清单占位：具体 uid 值待产品提供后补入，补值前所有 native uid 均被拒绝
    EXPECT_FALSE(manager.IsUidAllowed(0));
    EXPECT_FALSE(manager.IsUidAllowed(getuid()));
    // 补值后即生效
    manager.allowedUids_ = {12345};
    EXPECT_TRUE(manager.IsUidAllowed(12345));
    EXPECT_FALSE(manager.IsUidAllowed(12346));
    manager.allowedUids_.clear();
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck001, TestSize.Level0)
{
    // native token + uid 不在清单 -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_NATIVE));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    std::string clientId;
    int32_t result = service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject());
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck002, TestSize.Level0)
{
    // native token + uid 在清单 -> SUCCESS（注入测试进程 uid，验证清单放行路径）
    auto &manager = AuthEventSubscribeManager::GetInstance();
    manager.allowedUids_ = {getuid()};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_NATIVE));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    std::string clientId;
    int32_t result = service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject());
    EXPECT_EQ(result, SUCCESS);
    EXPECT_FALSE(clientId.empty());
    manager.allowedUids_.clear();
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck003, TestSize.Level0)
{
    // HAP token + 权限 GRANTED -> SUCCESS 且 clientId 服务端生成非空
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    std::string clientId;
    int32_t result = service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject());
    EXPECT_EQ(result, SUCCESS);
    EXPECT_FALSE(clientId.empty());
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck004, TestSize.Level0)
{
    // HAP token + 权限 DENIED -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    std::string clientId;
    int32_t result = service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject());
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck005, TestSize.Level0)
{
    // 非 native/HAP token -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_INVALID));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    std::string clientId;
    int32_t result = service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject());
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultPermission001, TestSize.Level0)
{
    // 服务层 SetAuthResult 权限校验：HAP + DENIED -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    AuthEvent event(4001, "content", "metadata");
    EXPECT_EQ(service.SetAuthResult(event, true, "client"), NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultPermission002, TestSize.Level0)
{
    // 服务层 SetAuthResult 权限校验：HAP + GRANTED -> SUCCESS（当前进程有会话）
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    ASSERT_EQ(service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject()), SUCCESS);
    AuthEvent event(4002, "content", "metadata");
    EXPECT_EQ(service.SetAuthResult(event, true, "svc_test_client"), SUCCESS);
    bool allowFlag = false;
    EXPECT_EQ(AuthEventSubscribeManager::GetInstance().GetAuthResult(4002, allowFlag), SUCCESS);
    EXPECT_TRUE(allowFlag);
}

HWTEST_F(AuthEventSubscribeManagerTest, CreatAuthEventClient001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // clientId 由客户端生成传入：正常创建
    EXPECT_EQ(manager.CreatAuthEventClient("client_9001", true, 9001, 9001 + 100, CreateRemoteObject()),
        SUCCESS);
    // 同一 clientId 重复创建 -> BAD_PARAM
    EXPECT_EQ(manager.CreatAuthEventClient("client_9001", true, 9001, 9001 + 100, CreateRemoteObject()),
        BAD_PARAM);
    // 空 clientId -> BAD_PARAM
    EXPECT_EQ(manager.CreatAuthEventClient("", true, 9001, 9001 + 100, CreateRemoteObject()), BAD_PARAM);
    // 空回调 -> NULL_OBJECT
    EXPECT_EQ(manager.CreatAuthEventClient("client_9001b", true, 9001, 9001 + 100, nullptr), NULL_OBJECT);
}

HWTEST_F(AuthEventSubscribeManagerTest, QuotaLimit001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::string clientId;
    EXPECT_EQ(manager.CreatAuthEventClient("client_9101a", true, 9101, 9101 + 100, CreateRemoteObject()),
        SUCCESS);
    EXPECT_EQ(manager.CreatAuthEventClient("client_9101b", true, 9101, 9101 + 100, CreateRemoteObject()),
        SUCCESS);
    // 同一进程第 3 个客户端
    EXPECT_EQ(manager.CreatAuthEventClient("client_9101c", true, 9101, 9101 + 100, CreateRemoteObject()),
        CLIENT_EXCEED_PROCESS_LIMIT);
    // 其他进程不受影响
    EXPECT_EQ(manager.CreatAuthEventClient("client_9102", true, 9102, 9102 + 100, CreateRemoteObject()),
        SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, QuotaLimit002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    for (pid_t pid = 9200; pid < 9208; pid++) {
        EXPECT_EQ(manager.CreatAuthEventClient("quota_" + std::to_string(pid) + "_a", true, pid, pid + 100,
            CreateRemoteObject()), SUCCESS);
        EXPECT_EQ(manager.CreatAuthEventClient("quota_" + std::to_string(pid) + "_b", true, pid, pid + 100,
            CreateRemoteObject()), SUCCESS);
    }
    // 会话表已满 16，新进程创建 -> GLOBAL_LIMIT
    EXPECT_EQ(manager.CreatAuthEventClient("client_9300", true, 9300, 9300 + 100, CreateRemoteObject()),
        CLIENT_EXCEED_GLOBAL_LIMIT);
    // 销毁后可重新创建
    EXPECT_EQ(manager.DestoryAuthEventClient("quota_9207_b", 9207), SUCCESS);
    EXPECT_EQ(manager.CreatAuthEventClient("client_9300", true, 9300, 9300 + 100, CreateRemoteObject()),
        SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscribeAndNotify001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(IAuthEventCallback::CMD_ON_AUTH_EVENT, _, _, _)).Times(1);
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9401", true, 9401, 9401 + 100, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1001, "client_9401", 9401), SUCCESS);
    // 重复订阅幂等
    EXPECT_EQ(manager.SubscribeAuthEvent(1001, "client_9401", 9401), SUCCESS);
    AuthEvent event(1001);
    manager.NotifyAuthEvent(event);
    // 未订阅的 eventId 不推送
    AuthEvent otherEvent(2002);
    manager.NotifyAuthEvent(otherEvent);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, UnsubscribeAndNotify002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(0);
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9402", true, 9402, 9402 + 100, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1002, "client_9402", 9402), SUCCESS);
    EXPECT_EQ(manager.UnsubscribeAuthEvent(1002, "client_9402", 9402), SUCCESS);
    AuthEvent event(1002);
    manager.NotifyAuthEvent(event);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, InvalidClientId003, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 空/伪造 clientId
    EXPECT_EQ(manager.SubscribeAuthEvent(1003, "", 9403), BAD_PARAM);
    EXPECT_EQ(manager.SubscribeAuthEvent(1003, "forged_client", 9403), BAD_PARAM);
    EXPECT_EQ(manager.UnsubscribeAuthEvent(1003, "forged_client", 9403), BAD_PARAM);
    EXPECT_EQ(manager.DestoryAuthEventClient("forged_client", 9403), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, PidBound004, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 会话操作按调用方进程绑定：其他进程持有效 clientId 也无法操作
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9411", true, 9411, 9411 + 100, CreateRemoteObject()), SUCCESS);
    EXPECT_EQ(manager.SubscribeAuthEvent(1006, "client_9411", 9412), BAD_PARAM);
    EXPECT_EQ(manager.UnsubscribeAuthEvent(1006, "client_9411", 9412), BAD_PARAM);
    EXPECT_EQ(manager.DestoryAuthEventClient("client_9411", 9412), BAD_PARAM);
    // 归属进程操作正常
    EXPECT_EQ(manager.SubscribeAuthEvent(1006, "client_9411", 9411), SUCCESS);
    EXPECT_EQ(manager.DestoryAuthEventClient("client_9411", 9411), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, DestoryClient005, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9403", true, 9403, 9403 + 100, obj), SUCCESS);
    EXPECT_EQ(manager.DestoryAuthEventClient("client_9403", 9403), SUCCESS);
    // 会话移除后再订阅 -> BAD_PARAM
    EXPECT_EQ(manager.SubscribeAuthEvent(1004, "client_9403", 9403), BAD_PARAM);
    EXPECT_EQ(manager.DestoryAuthEventClient("client_9403", 9403), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResult001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    AuthEvent event(3001, "content", "metadata");
    // 调用方进程无会话 -> BAD_PARAM
    EXPECT_EQ(manager.SetAuthResult(9501, 9601, "client_9501", event, true), BAD_PARAM);

    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9502", true, 9502, 9502 + 100, CreateRemoteObject()), SUCCESS);
    EXPECT_EQ(manager.SetAuthResult(9502, 9602, "client_9502", event, true), SUCCESS);
    bool allowFlag = false;
    EXPECT_EQ(manager.GetAuthResult(3001, allowFlag), SUCCESS);
    EXPECT_TRUE(allowFlag);
    // 覆盖更新
    EXPECT_EQ(manager.SetAuthResult(9502, 9602, "client_9502", event, false), SUCCESS);
    EXPECT_EQ(manager.GetAuthResult(3001, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag);
    // 未设置过的 eventId
    EXPECT_EQ(manager.GetAuthResult(9999, allowFlag), NOT_FOUND);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultTooLong002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9503", true, 9503, 9503 + 100, CreateRemoteObject()), SUCCESS);
    std::string tooLong(MAX_AUTH_EVENT_STR_LEN + 1, 'a');
    AuthEvent longContent(3002, tooLong, "");
    EXPECT_EQ(manager.SetAuthResult(9503, 9603, "client_9503", longContent, true), BAD_PARAM);
    AuthEvent longMetadata(3003, "", tooLong);
    EXPECT_EQ(manager.SetAuthResult(9503, 9603, "client_9503", longMetadata, true), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, CollectionSizeLimit001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9510", true, 9510, 9510 + 100, CreateRemoteObject()), SUCCESS);
    for (int64_t eventId = 1; eventId <= static_cast<int64_t>(MAX_AUTH_EVENT_SUBSCRIBE_SIZE); eventId++) {
        ASSERT_EQ(manager.SubscribeAuthEvent(eventId, "client_9510", 9510), SUCCESS);
    }
    // 单会话订阅数超限
    EXPECT_EQ(manager.SubscribeAuthEvent(MAX_AUTH_EVENT_SUBSCRIBE_SIZE + 1, "client_9510", 9510),
        FILTER_EXCEED_LIMIT);
}

HWTEST_F(AuthEventSubscribeManagerTest, CollectionSizeLimit002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9511", true, 9511, 9511 + 100, CreateRemoteObject()), SUCCESS);
    for (int64_t eventId = 1; eventId <= static_cast<int64_t>(MAX_AUTH_EVENT_RESULT_SIZE); eventId++) {
        AuthEvent event(eventId);
        ASSERT_EQ(manager.SetAuthResult(9511, 9611, "result_9511", event, true), SUCCESS);
    }
    // 结果状态表容量超限
    AuthEvent overflow(MAX_AUTH_EVENT_RESULT_SIZE + 1);
    EXPECT_EQ(manager.SetAuthResult(9511, 9611, "result_9511", overflow, true), FILTER_EXCEED_LIMIT);
}

HWTEST_F(AuthEventSubscribeManagerTest, SessionApiPermission001, TestSize.Level0)
{
    // 会话操作（Destory/Subscribe/Unsubscribe）前置权限校验：
    // 无权限调用方（HAP+DENIED）在参数校验前即被拦截 -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    AuthEvent event(5001, "content", "metadata");
    EXPECT_EQ(service.SubscribeAuthEvent(5001, "client"), NO_PERMISSION);
    EXPECT_EQ(service.UnsubscribeAuthEvent(5001, "client"), NO_PERMISSION);
    EXPECT_EQ(service.DestoryAuthEventClient("client"), NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SessionApiPermission002, TestSize.Level0)
{
    // 有权限调用方（HAP+GRANTED）通过权限校验，进入参数/会话校验（伪造 clientId -> BAD_PARAM）
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.SubscribeAuthEvent(5002, "forged_client"), BAD_PARAM);
    EXPECT_EQ(service.UnsubscribeAuthEvent(5002, "forged_client"), BAD_PARAM);
    EXPECT_EQ(service.DestoryAuthEventClient("forged_client"), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscribeEventIdNotInConfig001, TestSize.Level0)
{
    // 订阅的 eventId 必须在事件配置中（GetEventConfig 未命中 -> BAD_PARAM）
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &config) {
            if (eventId == 6001) { // 仅 6001 在配置中
                config.eventId = eventId;
                return true;
            }
            return false;
        });
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    ASSERT_EQ(service.CreatAuthEventClient("svc_test_client", true, CreateRemoteObject()), SUCCESS);
    // 配置中的 eventId 通过配置校验（伪造 clientId 按会话校验拦截 -> BAD_PARAM）
    EXPECT_EQ(service.SubscribeAuthEvent(6001, "forged_client"), BAD_PARAM);
    // 不在配置中的 eventId -> BAD_PARAM（配置校验前置拦截）
    EXPECT_EQ(service.SubscribeAuthEvent(6002, "svc_test_client"), BAD_PARAM);
    // 退订不做配置校验（配置可能在运行中被移除，退订按会话数据操作）
    EXPECT_EQ(service.UnsubscribeAuthEvent(6002, "svc_test_client"), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscriberDied006, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(0);
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9601", true, 9601, 9701, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1005, clientId, 9601), SUCCESS);
    // 经真实 DeathRecipient 回调链路触发清理
    ASSERT_NE(manager.deathRecipient_, nullptr);
    manager.deathRecipient_->OnRemoteDied(obj);
    EXPECT_EQ(manager.SubscribeAuthEvent(1005, clientId, 9601), BAD_PARAM);
    AuthEvent event(1005);
    manager.NotifyAuthEvent(event);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeout001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 分发按 (clientId, eventIndex) 独立登记超时跟踪；超时未回填 -> 消费 pending
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9701", true, 9701, 9801, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1101, "client_9701", 9701), SUCCESS);
    AuthEvent event(1101, "content", "metadata");
    manager.NotifyAuthEvent(event);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_EQ(manager.pendingResults_.size(), static_cast<size_t>(1));
        auto iter = manager.pendingResults_.begin();
        EXPECT_EQ(iter->first.clientId, "client_9701");
        EXPECT_EQ(iter->first.eventIndex, static_cast<int64_t>(1));
        // 事件副本 metadata 已含 seqNum 键（JSON）
        EXPECT_NE(iter->second->event.GetMetadata().find("\"seqNum\":1"), std::string::npos);
    }
    // 超时检查（打点路径在无 HA 环境下仅告警不崩溃）
    manager.CheckAuthResultTimeout("client_9701", 1);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_TRUE(manager.pendingResults_.empty());
    }
    // 重复检查幂等
    manager.CheckAuthResultTimeout("client_9701", 1);
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeout002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 回填携带 eventIndex：仅取消该客户端该次分发的跟踪
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9702", true, 9702, 9802, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1102, "client_9702", 9702), SUCCESS);
    AuthEvent event(1102, "content", "metadata");
    manager.NotifyAuthEvent(event); // index 1
    manager.NotifyAuthEvent(event); // index 2（同一事件二次分发）
    AuthEvent replied = event;
    replied.SetMetadata("{\"seqNum\":1}");
    EXPECT_EQ(manager.SetAuthResult(9702, 9802, "client_9702", replied, true), SUCCESS);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_EQ(manager.pendingResults_.size(), static_cast<size_t>(1)); // 仅 index 2 待回填
    }
    // index 1 已回填，超时检查不触发；index 2 未回填，检查后消费
    manager.CheckAuthResultTimeout("client_9701", 1);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_EQ(manager.pendingResults_.size(), static_cast<size_t>(1));
    }
    manager.CheckAuthResultTimeout(clientId, 2);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_TRUE(manager.pendingResults_.empty());
    }
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeout003, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 多客户端订阅同一 eventId：各自独立 eventIndex 与跟踪，一端回填不影响另一端
    sptr<MockRemoteObject> obj1 = CreateRemoteObject();
    sptr<MockRemoteObject> obj2 = CreateRemoteObject();
    ASSERT_EQ(manager.CreatAuthEventClient("client_9703", true, 9703, 9803, obj1), SUCCESS);
    ASSERT_EQ(manager.CreatAuthEventClient("client_9704", true, 9704, 9804, obj2), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1103, "client_9703", 9703), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1103, "client_9704", 9704), SUCCESS);
    AuthEvent event(1103, "content", "metadata");
    manager.NotifyAuthEvent(event);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_EQ(manager.pendingResults_.size(), static_cast<size_t>(2));
    }
    // 客户端1 回填阻断：仅清自己的 pending，客户端2 超时跟踪不受影响
    AuthEvent replied = event;
    replied.SetMetadata("{\"seqNum\":1}");
    EXPECT_EQ(manager.SetAuthResult(9703, 9803, "client_9703", replied, false), SUCCESS);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_EQ(manager.pendingResults_.size(), static_cast<size_t>(1));
    }
    // 客户端2 超时检查 -> 消费
    manager.CheckAuthResultTimeout("client_9704", 1);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_TRUE(manager.pendingResults_.empty());
    }
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeoutAction001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 超时处置策略：创建时设置阻断(false) -> 超时未回填时结果表按阻断落值
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    ASSERT_EQ(manager.CreatAuthEventClient("timeout_block_client", false, 9705, 9805, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1105, "timeout_block_client", 9705), SUCCESS);
    AuthEvent event(1105, "content", "metadata");
    manager.NotifyAuthEvent(event);
    manager.CheckAuthResultTimeout("timeout_block_client", 1);
    bool allowFlag = true;
    EXPECT_EQ(manager.GetAuthResult(1105, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag); // 超时默认处置：阻断
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeoutAction002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 超时处置策略：默认放行(true) -> 超时未回填时结果表按放行落值；已回填结果不被覆盖
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    ASSERT_EQ(manager.CreatAuthEventClient("timeout_allow_client", true, 9706, 9806, obj), SUCCESS);
    ASSERT_EQ(manager.SubscribeAuthEvent(1106, "timeout_allow_client", 9706), SUCCESS);
    AuthEvent event(1106, "content", "metadata");
    manager.NotifyAuthEvent(event);
    manager.CheckAuthResultTimeout("timeout_allow_client", 1);
    bool allowFlag = false;
    EXPECT_EQ(manager.GetAuthResult(1106, allowFlag), SUCCESS);
    EXPECT_TRUE(allowFlag); // 超时默认处置：放行

    // 已回填的结果不被后续超时处置覆盖
    AuthEvent event2(1107, "content", "metadata");
    manager.NotifyAuthEvent(event2);
    AuthEvent replied = event2;
    replied.SetMetadata("{\"seqNum\":1}");
    EXPECT_EQ(manager.SetAuthResult(9706, 9806, "timeout_allow_client", replied, false), SUCCESS);
    manager.CheckAuthResultTimeout("timeout_allow_client", 1);
    allowFlag = true;
    EXPECT_EQ(manager.GetAuthResult(1107, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag); // 保留回填的阻断结果
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthResultTimeout004, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 未订阅任何会话的事件分发：不登记超时跟踪
    AuthEvent event(1104, "content", "metadata");
    manager.NotifyAuthEvent(event);
    {
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        EXPECT_TRUE(manager.pendingResults_.empty());
    }
    manager.CheckAuthResultTimeout("no_such_client", 1);
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthBlockResultReport001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 阻断结果回填：打点路径在无 HiAppEvent 环境下仅告警，不影响返回值
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    std::string clientId;
    ASSERT_EQ(manager.CreatAuthEventClient("client_9703", true, 9703, 9803, obj), SUCCESS);
    AuthEvent event(1104, "content", "metadata");
    EXPECT_EQ(manager.SetAuthResult(9703, 9803, clientId, event, false), SUCCESS);
    bool allowFlag = true;
    EXPECT_EQ(manager.GetAuthResult(1104, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag);
}

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
