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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H
#define SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H

#include <map>
#include <mutex>
#include <set>

#include "iremote_object.h"
#include "timer.h"
#include "i_db_listener.h"
#include "security_collector_subscribe_info.h"
#include "i_collector_subscriber.h"
#include "i_collector_fwk.h"
namespace OHOS::Security::SecurityGuard {
class AcquireDataSubscribeManager {
public:
    static AcquireDataSubscribeManager& GetInstance();
    int InsertSubscribeRecord(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback);
    int RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback);
    bool BatchPublish(const SecurityCollector::Event &event);
    void RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback);
    class CleanupTimer {
    public:
        CleanupTimer() = default;
        ~CleanupTimer() { Shutdown(); }
        void ClearEventCache(const sptr<IRemoteObject> &remote);
        void Start(const sptr<IRemoteObject> &remote, int64_t duration)
        {
            timer_.Setup();
            timerId_ = timer_.Register([this, remote] { this->ClearEventCache(remote); }, duration);
        }
        void Shutdown()
        {
            if (timerId_ != 0) {
                timer_.Unregister(timerId_);
            }
            timer_.Shutdown();
            timerId_ = 0;
        }
        uint32_t GetTimeId()
        {
            return timerId_;
        }
    private:
        Utils::Timer timer_{"cleanup_subscriber"};
        uint32_t timerId_{};
    };
    using SubscriberInfo = struct {
        std::shared_ptr<CleanupTimer> timer;
        std::vector<SecurityCollector::Event> events;
        size_t eventsBuffSize;
        std::vector<SecurityCollector::SecurityCollectorSubscribeInfo> subscribe;
    };
    void BatchUpload(sptr<IRemoteObject> obj, const std::vector<SecurityCollector::Event> &events);
private:
    AcquireDataSubscribeManager();
    ~AcquireDataSubscribeManager() = default;
    int SubscribeSc(int64_t eventId);
    int UnSubscribeSc(int64_t eventId);
    int UnSubscribeScAndDb(int64_t eventId);
    class DbListener : public IDbListener {
    public:
        DbListener() = default;
        ~DbListener() override = default;
        void OnChange(uint32_t optType, const SecEvent &events) override;
    };
    class CollectorListenner : public SecurityCollector::ICollectorFwk {
    public:
        CollectorListenner() = default;
        ~CollectorListenner() override = default;
        void OnNotify(const SecurityCollector::Event &event) override;
    };
    class SecurityCollectorSubscriber : public SecurityCollector::ICollectorSubscriber {
    public:
        explicit SecurityCollectorSubscriber(
            SecurityCollector::Event event) : SecurityCollector::ICollectorSubscriber(event) {};
        ~SecurityCollectorSubscriber() override = default;
        int32_t OnNotify(const SecurityCollector::Event &event) override;
    };
    std::shared_ptr<IDbListener> listener_{};
    std::shared_ptr<SecurityCollector::ICollectorFwk> collectorListenner_{};
    std::unordered_map<int64_t, std::shared_ptr<SecurityCollectorSubscriber>> scSubscribeMap_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H