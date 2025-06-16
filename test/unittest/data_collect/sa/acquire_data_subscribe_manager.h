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
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#include "i_db_listener.h"
#include "security_collector_subscribe_info.h"
#include "i_collector_subscriber.h"
#include "i_collector_fwk.h"
#include "i_event_filter.h"
#include "security_event_filter.h"
#include "security_event_info.h"
namespace OHOS::Security::SecurityGuard {
typedef SecurityCollector::IEventFilter* (*GetEventFilterFunc)();
class AcquireDataSubscribeManager {
public:
    static AcquireDataSubscribeManager& GetInstance();
    int InsertSubscribeRecord(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback, const std::string &clientId);
    int RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback, const std::string &clientId);
    bool BatchPublish(const SecurityCollector::Event &event);
    void RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback);
    int InsertSubscribeMute(const EventMuteFilter &filter, const std::string &clientId);
    int RemoveSubscribeMute(const EventMuteFilter &filter, const std::string &clientId);
    int CreatClient(const std::string &eventGroup, const std::string &clientId, const sptr<IRemoteObject> &cb);
    int DestoryClient(const std::string &eventGroup, const std::string &clientId);
    void SubscriberEventOnSgStart();
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
        std::string clientId;
    };
    void BatchUpload(sptr<IRemoteObject> obj, const std::vector<SecurityCollector::Event> &events);
    void UploadEvent(const SecurityCollector::Event &event);
private:
    AcquireDataSubscribeManager();
    ~AcquireDataSubscribeManager() = default;
    int SubscribeSc(int64_t eventId, const sptr<IRemoteObject> &callback);
    int UnSubscribeSc(int64_t eventId);
    int UnSubscribeScAndDb(int64_t eventId);
    int SubscribeScInSg(int64_t eventId, const sptr<IRemoteObject> &callback);
    int SubscribeScInSc(int64_t eventId, const sptr<IRemoteObject> &callback);
    SecurityCollector::SecurityCollectorEventMuteFilter ConvertFilter(const SecurityGuard::EventMuteFilter &sgFilter,
        const std::string &clientId);
    int RemoveSubscribeMuteToSub(const SecurityCollector::SecurityCollectorEventMuteFilter &collectorFilter,
        const EventCfg &config);
    size_t GetSecurityCollectorEventBufSize(const SecurityCollector::Event &event);
    int IsExceedLimited(const std::string &clientId, AccessToken::AccessTokenID callerToken);
    bool IsFindFlag(const std::set<std::string> &eventSubscribes, int64_t eventId, const std::string &clientId);
    class DbListener : public IDbListener {
    public:
        DbListener() = default;
        ~DbListener() override = default;
        void OnChange(uint32_t optType, const SecEvent &events, const std::set<std::string> &eventSubscribes) override;
    };
    class SecurityCollectorSubscriber : public SecurityCollector::ICollectorSubscriber {
    public:
        explicit SecurityCollectorSubscriber(
            SecurityCollector::Event event) : SecurityCollector::ICollectorSubscriber(event) {};
        ~SecurityCollectorSubscriber() override = default;
        int32_t OnNotify(const SecurityCollector::Event &event) override;
    };
    class CollectorListener : public SecurityCollector::ICollectorFwk {
    public:
        void OnNotify(const SecurityCollector::Event &event) override;
    private:
    };
    class ClientSession {
    public:
        AccessToken::AccessTokenID tokenId {};
        sptr<IRemoteObject> callback {};
        std::string clientId {};
        std::map<int64_t, std::vector<EventMuteFilter>> eventFilters {};
        std::set<int64_t> subEvents{};
    };
    std::shared_ptr<IDbListener> listener_{};
    std::shared_ptr<SecurityCollector::ICollectorFwk> collectorListener_{};
    std::unordered_map<int64_t, std::shared_ptr<SecurityCollectorSubscriber>> scSubscribeMap_{};
    std::map<int64_t, std::shared_ptr<SecurityCollector::ICollectorFwk>> eventToListenner_;
    std::map<std::string, std::shared_ptr<ClientSession>> sessionsMap_ {};
    void *handle_ = nullptr;
    GetEventFilterFunc eventFilter_ = nullptr;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H