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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_MANAGER_H
#define SECURITY_GUARD_ACQUIRE_DATA_MANAGER_H

#include <map>
#include <mutex>
#include "acquire_data_manager_callback_service.h"
#include "i_collector_subscriber.h"
#include "event_info.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataManager {
public:
    static AcquireDataManager& GetInstance();
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient() = default;
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    int32_t Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
    int32_t Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
private:
    AcquireDataManager();
    ~AcquireDataManager() = default;
    void HandleDecipient();
    bool IsCurrentSubscriberEventIdExist(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &sub);
    std::mutex mutex_{};
    sptr<AcquireDataManagerCallbackService> callback_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::set<std::shared_ptr<SecurityCollector::ICollectorSubscriber>> subscribers_ {};
    uint32_t count_ = 0;
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_H