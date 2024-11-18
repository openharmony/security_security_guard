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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H
#define SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H
#include <mutex>
#include "acquire_data_manager_callback_stub.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataManagerCallbackService : public AcquireDataManagerCallbackStub {
public:
    explicit AcquireDataManagerCallbackService() = default;
    ~AcquireDataManagerCallbackService() override = default;

    int32_t OnNotify(const SecurityCollector::Event &event) override;
    int32_t BatchOnNotify(const std::vector<SecurityCollector::Event> &events) override;
    void InserSubscriberCache(std::shared_ptr<SecurityCollector::ICollectorSubscriber> sub)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers.insert(sub);
    }
    bool IsCurrentSubscriberExist(std::shared_ptr<SecurityCollector::ICollectorSubscriber> sub)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return (subscribers.count(sub) != 0);
    }
    void EraseSubscriber(std::shared_ptr<SecurityCollector::ICollectorSubscriber> sub)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = subscribers.find(sub);
        if (it == subscribers.end()) {
            return;
        }
        subscribers.erase(it);
    }
    void ClearSubscriber()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers.clear();
    }
private:
    std::set<std::shared_ptr<SecurityCollector::ICollectorSubscriber>> subscribers;
    std::mutex mutex_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H