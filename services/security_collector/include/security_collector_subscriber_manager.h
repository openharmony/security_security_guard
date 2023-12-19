/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H

#include <map>
#include <set>
#include <mutex>
#include <memory>
#include "singleton.h"
#include "timer.h"

#include "i_collector_fwk.h"
#include "security_collector_subscriber.h"


namespace OHOS::Security::SecurityCollector {

class SecurityCollectorSubscriberManager : public Singleton<SecurityCollectorSubscriberManager> {
public:
    using UnsubscribeHandler = std::function<void (const sptr<IRemoteObject> &remote)>;
    SecurityCollectorSubscriberManager();
    bool SubscribeCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber);
    bool UnsubscribeCollector(const sptr<IRemoteObject> &remote);
    void SetUnsubscribeHandler(UnsubscribeHandler handler) { unsubscribeHandler_ = handler; }

private:
    auto FindSecurityCollectorSubscribers(const sptr<IRemoteObject> &remote);
    std::set<int64_t> FindEventIds(const sptr<IRemoteObject> &remote);
    int32_t GetAppSubscribeCount(const std::string &appName);
    int32_t GetAppSubscribeCount(const std::string &appName, int64_t eventId);
    void CleanSubscriber(const sptr<IRemoteObject> &remote) { unsubscribeHandler_(remote); }
    void NotifySubscriber(const Event &event);

    class CollectorListenner : public ICollectorFwk {
    public:
        CollectorListenner(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) : subscriber_(subscriber) {}
        std::string GetExtraInfo() override;
        void OnNotify(const Event &event) override;
    private:
        std::shared_ptr<SecurityCollectorSubscriber> subscriber_;
    };
    
    class CleanupTimer {
    public:
        CleanupTimer() = default;
        ~CleanupTimer() { Shutdown(); }
        void StopCollector(const sptr<IRemoteObject> &remote)
        {
            // avoid dead lock
            std::thread work([this, remote] () {
                SecurityCollectorSubscriberManager::GetInstance().CleanSubscriber(remote);
            });
            work.detach();
        }
        void Start(const sptr<IRemoteObject> &remote, int64_t duration)
        {
            timer_.Setup();
            timerId_ = timer_.Register([this, remote] { this->StopCollector(remote); }, duration);
        }
        void Shutdown()
        {
            if (timerId_ != 0) {
                timer_.Unregister(timerId_);
            }
            timer_.Shutdown();
            timerId_ = 0;
        }
    private:
        Utils::Timer timer_{"cleanup_collector"};
        uint32_t timerId_{};
    };

    UnsubscribeHandler unsubscribeHandler_{};
    std::mutex collectorMutex_{};
    std::map<int64_t, std::set<std::shared_ptr<SecurityCollectorSubscriber>>> eventToSubscribers_{};
    std::map<sptr<IRemoteObject>, std::shared_ptr<CleanupTimer>> timers_{};
    std::map<int64_t, std::shared_ptr<ICollectorFwk>> eventToListenner_;
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H