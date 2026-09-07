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

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
#ifndef SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H
#define SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H

#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>

#include "auth_event.h"
#include "auth_event_callback_service.h"
#include "iremote_object.h"

namespace OHOS::Security::SecurityGuard {
using AuthEventCallback = std::function<void(const AuthEvent &event)>;
class AuthEventSubscribeClient {
public:
    // timeoutAllowFlag：回填超时处置策略（超时未回填时框架按该策略落结果），默认放行
    static int32_t CreatClient(AuthEventCallback callback,
        std::shared_ptr<AuthEventSubscribeClient> &client, bool timeoutAllowFlag = true);
    int32_t Subscribe(int64_t eventId);
    int32_t Unsubscribe(int64_t eventId);
    int32_t SetAuthResult(const AuthEvent &event, bool allowFlag);
    // 断开已注册的回调，并排空 stub 上所有在途的 OnAuthEvent，
    // 随后销毁服务端会话。返回后框架不会再触发用户回调，
    // 此时销毁回调所捕获的状态是安全的。
    // 把 client 作为对象成员的调用方无需显式调用本接口；
    // 最后一个 shared_ptr 释放时 Deleter 会自动执行该操作。
    void DeleteClient();
private:
    AuthEventSubscribeClient() = default;
    ~AuthEventSubscribeClient() = default;
    AuthEventSubscribeClient(const AuthEventSubscribeClient&) = delete;
    AuthEventSubscribeClient& operator= (const AuthEventSubscribeClient&) = delete;
    static int32_t SetDeathRecipient(std::shared_ptr<AuthEventSubscribeClient> client,
        const sptr<IRemoteObject> &remote);
    static std::string ConstructClientId(const AuthEventCallbackService *serviceCallback);
    static void Deleter(AuthEventSubscribeClient *client);
    void HandleDeath();
    sptr<IRemoteObject> ReconnectService();
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipient(std::weak_ptr<AuthEventSubscribeClient> client) : client_(std::move(client)) {}
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        std::weak_ptr<AuthEventSubscribeClient> client_;
    };
    sptr<AuthEventCallbackService> callback_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::string clientId_{}; // 服务端生成并回传，CreatClient 时填充
    std::set<int64_t> subscribedEventIds_{};
    bool deleted_ {false}; // 已显式销毁标记：阻止 HandleDeath 自动重建已删除的会话
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
