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

#include "acquire_data_manager_callback_service.h"
#include "event_info.h"

namespace OHOS::Security::SecurityGuard {
using EventCallback = std::function<void(const SecurityCollector::Event &event)>;
class EventSubscribeClient {
public:
    int32_t Subscribe(int64_t eventid);
    int32_t Unsubscribe(int64_t eventid);
    int32_t AddFilter(const std::shared_ptr<EventMuteFilter> &subscribeMute);
    int32_t RemoveFilter(const std::shared_ptr<EventMuteFilter> &subscribeMute);
    static int32_t CreatClient(const std::string &eventGroup, EventCallback callback,
        std::shared_ptr<EventSubscribeClient> &client);
    static int32_t DestoryClient(const std::shared_ptr<EventSubscribeClient> &client);
private:
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient() = default;
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override {};
    };
    sptr<AcquireDataManagerCallbackService> callback_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::string eventGroup_{};
    std::string clientId_{};
};
}
 #endif
