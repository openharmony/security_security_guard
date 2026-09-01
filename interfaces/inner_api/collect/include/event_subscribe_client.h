/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_EVENT_SUBSCRIBE_CLIENT_H
#define SECURITY_GUARD_EVENT_SUBSCRIBE_CLIENT_H

#include <memory>
#include <mutex>
#include <set>
#include <utility>
#include <vector>
#include "acquire_data_manager_callback_service.h"
#include "event_info.h"

namespace OHOS::Security::SecurityGuard {
using EventCallback = std::function<void(const SecurityCollector::Event &event)>;
class EventSubscribeClient {
public:
    int32_t Subscribe(int64_t eventId);
    int32_t Unsubscribe(int64_t eventId);
    int32_t AddFilter(const std::shared_ptr<EventMuteFilter> &filter);
    int32_t RemoveFilter(const std::shared_ptr<EventMuteFilter> &filter);
    static int32_t CreatClient(const std::string &eventGroup, EventCallback callback,
        std::shared_ptr<EventSubscribeClient> &client);
    // 断开已注册的回调，并排空stub上所有在途的OnNotify。
    // 返回后框架不会再触发用户回调，此时销毁回调所捕获的状态时安全的。
    // 把 client_作为对象成员的调用方无需显示调用本接口；
    // 最后一个shared_ptr 释放时Deleter会自动执行该被操作。
    void ClearCallBack();
private:
    EventSubscribeClient() = default;
    ~EventSubscribeClient() = default;
    EventSubscribeClient(const EventSubscribeClient&) = delete;
    EventSubscribeClient& operator= (const EventSubscribeClient&) = delete;
    static std::string ConstructClientId(const AcquireDataManagerCallbackService *serviceCallback);
    static int32_t SetDeathRecipient(std::shared_ptr<EventSubscribeClient> client,
        const sptr<IRemoteObject> &remote);
    static void Deleter(EventSubscribeClient *client);
    void HandleDeath();
    sptr<IRemoteObject> ReconnectService();
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipient(std::weak_ptr<EventSubscribeClient> client) : client_(std::move(client)) {}
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        std::weak_ptr<EventSubscribeClient> client_;
    };
    sptr<AcquireDataManagerCallbackService> callback_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::string eventGroup_{};
    std::string clientId_{};
    std::set<int64_t> subscribedEventIds_{};
    std::vector<std::shared_ptr<EventMuteFilter>> filters_{};
};
}
#endif
