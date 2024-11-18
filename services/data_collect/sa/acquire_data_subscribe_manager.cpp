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

#include "acquire_data_subscribe_manager.h"
#include <cinttypes>
#include "acquire_data_callback_proxy.h"
#include "database_manager.h"
#include "security_guard_define.h"
#include "security_collector_subscribe_info.h"
#include "security_guard_log.h"
#include "ffrt.h"
#include "event_define.h"
#include "i_model_info.h"
#include "config_data_manager.h"
#include "collector_manager.h"
#include "data_collection.h"
namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr size_t MAX_CACHE_EVENT_SIZE = 64 * 1024;
    constexpr int64_t MAX_DURATION_TEN_SECOND = 10 * 1000;
}
std::mutex AcquireDataSubscribeManager::mutex_{};
std::map<sptr<IRemoteObject>, AcquireDataSubscribeManager::SubscriberInfo> subscriberInfoMap_{};

AcquireDataSubscribeManager& AcquireDataSubscribeManager::GetInstance()
{
    static AcquireDataSubscribeManager instance;
    return instance;
}

AcquireDataSubscribeManager::AcquireDataSubscribeManager() : listener_(std::make_shared<DbListener>()) {}

int AcquireDataSubscribeManager::InsertSubscribeRecord(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback)
{
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(subscribeInfo.GetEvent().eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    int64_t event = subscribeInfo.GetEvent().eventId;
    std::lock_guard<std::mutex> lock(mutex_);

    SubscriberInfo subInfo {};
    if (subscriberInfoMap_.count(callback) == 0) {
        subInfo.subscribe.emplace_back(subscribeInfo);
        subInfo.timer = std::make_shared<CleanupTimer>();
        subInfo.timer->Start(callback, MAX_DURATION_TEN_SECOND);
        subscriberInfoMap_[callback] = subInfo;
    } else {
        subscriberInfoMap_.at(callback).subscribe.emplace_back(subscribeInfo);
    }

    int32_t code = DatabaseManager::GetInstance().SubscribeDb({subscribeInfo.GetEvent().eventId}, listener_);
    if (code != SUCCESS) {
        SGLOGE("SubscribeDb error");
        return code;
    }
    code = SubscribeSc(subscribeInfo.GetEvent().eventId);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeSc(int64_t eventId)
{
    if (scSubscribeMap_.count(eventId)) {
        return SUCCESS;
    }
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.dbTable == "risk_event" && config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        SecurityCollector::Event scEvent;
        scEvent.eventId = eventId;
        auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(scEvent);
        // 订阅SG
        if (config.prog == "security_guard") {
            if (!SecurityCollector::DataCollection::GetInstance().SecurityGuardSubscribeCollector({eventId})) {
                SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64, eventId);
                return FAILED;
            }
        } else {
            // 订阅SC
            int code = SecurityCollector::CollectorManager::GetInstance().Subscribe(subscriber);
            if (code != SUCCESS) {
                SGLOGI("Subscribe SC failed, code=%{public}d", code);
                return code;
            }
        }
        scSubscribeMap_[scEvent.eventId] = subscriber;
    }
    SGLOGI("SubscribeSc scSubscribeMap_size  %{public}zu", scSubscribeMap_.size());
    return SUCCESS;
}

int AcquireDataSubscribeManager::UnSubscribeSc(int64_t eventId)
{
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.dbTable == "risk_event" && config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        auto it = scSubscribeMap_.find(eventId);
        if (it == scSubscribeMap_.end()) {
            return FAILED;
        }
        // 解订阅SG
        if (config.prog == "security_guard") {
            if (!SecurityCollector::DataCollection::GetInstance().StopCollectors({eventId})) {
                SGLOGE("UnSubscribe SG failed, eventId=%{public}" PRId64, eventId);
                return FAILED;
            }
        } else {
            // 解订阅SC
            int ret = SecurityCollector::CollectorManager::GetInstance().Unsubscribe(it->second);
            if (ret != SUCCESS) {
                SGLOGE("UnSubscribe SC failed, ret=%{public}d", ret);
                return ret;
            }
        }
        it->second = nullptr;
        scSubscribeMap_.erase(it);
    }
    SGLOGI("UnSubscribeSc scSubscribeMap_size  %{public}zu", scSubscribeMap_.size());
    return SUCCESS;
}

int AcquireDataSubscribeManager::UnSubscribeScAndDb(int64_t eventId)
{
    int ret = DatabaseManager::GetInstance().UnSubscribeDb({eventId}, listener_);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribeDb error");
        return ret;
    }
    ret = UnSubscribeSc(eventId);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribeSc error");
        return ret;
    }
    return ret;
}

int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = subscriberInfoMap_.find(callback);
    if (iter == subscriberInfoMap_.end()) {
        SGLOGI("not find caller in subscriberInfoMap_");
        return SUCCESS;
    }
    // first erase current callback subscribed info
    for (auto it = subscriberInfoMap_.at(callback).subscribe.begin();
        it != subscriberInfoMap_.at(callback).subscribe.end(); it++) {
        if (it->GetEvent().eventId == eventId) {
            subscriberInfoMap_.at(callback).subscribe.erase(it);
            break;
        }
    }
    // second erase current callback  when subscribed member is empty
    if (subscriberInfoMap_.at(callback).subscribe.empty()) {
        subscriberInfoMap_.erase(iter);
    }
    
    for (auto it : subscriberInfoMap_) {
        for (auto i : it.second.subscribe) {
            if (i.GetEvent().eventId == eventId) {
                return SUCCESS;
            }
        }
    }
    return UnSubscribeScAndDb(eventId);
}

void AcquireDataSubscribeManager::RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = subscriberInfoMap_.find(callback);
    if (iter == subscriberInfoMap_.end()) {
        SGLOGI("not find caller in subscriberInfoMap_");
        return;
    }
    std::set<int64_t> eventIdNeedUnSub {};
    std::set<int64_t> currentEventId {};
    for (auto i : subscriberInfoMap_.at(callback).subscribe) {
        eventIdNeedUnSub.insert(i.GetEvent().eventId);
    }
    subscriberInfoMap_.erase(iter);
    for (auto i : subscriberInfoMap_) {
        for (auto iter : i.second.subscribe) {
            currentEventId.insert(iter.GetEvent().eventId);
        }
    }
    for (auto i : eventIdNeedUnSub) {
        if (currentEventId.count(i) == 0) {
            (void)UnSubscribeScAndDb(i);
        }
    }
}

void AcquireDataSubscribeManager::CleanupTimer::ClearEventCache(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriberInfoMap_.count(remote) == 0) {
        return;
    }
    std::vector<SecurityCollector::Event> tmp = subscriberInfoMap_.at(remote).events;
    if (tmp.empty()) {
        return;
    }
    auto proxy = iface_cast<IAcquireDataCallback>(remote);
    if (proxy == nullptr) {
        return;
    }
    auto task = [proxy, tmp] () {
        proxy->BatchOnNotify(tmp);
    };
    subscriberInfoMap_.at(remote).events.clear();
    subscriberInfoMap_.at(remote).eventsBuffSize = 0;
}

bool AcquireDataSubscribeManager::BatchPublish(const SecEvent &events)
{
    for (auto it : subscriberInfoMap_) {
        for (auto i : it.second.subscribe) {
            if (i.GetEvent().eventId != events.eventId) {
                continue;
            }
            SecurityCollector::Event event {
                .eventId = events.eventId,
                .version = events.version,
                .content = events.content,
                .timestamp = events.date
            };
            if (i.GetEventGroup() == "" || i.GetEventGroup() == "security_event") {
                auto proxy = iface_cast<IAcquireDataCallback>(it.first);
                auto task = [proxy, event] () {
                    proxy->OnNotify(event);
                };
                if (event.eventId == SecurityCollector::FILE_EVENTID ||
                    event.eventId == SecurityCollector::PROCESS_EVENTID ||
                    event.eventId == SecurityCollector::NETWORK_EVENTID) {
                    ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt::qos_background));
                } else {
                    ffrt::submit(task);
                }
                continue;
            }
            it.second.events.emplace_back(event);
            it.second.eventsBuffSize += sizeof(event);
            if (it.second.eventsBuffSize >= MAX_CACHE_EVENT_SIZE) {
                auto proxy = iface_cast<IAcquireDataCallback>(it.first);
                if (proxy == nullptr) {
                    return false;
                }
                std::vector<SecurityCollector::Event> tmp = it.second.events;
                auto task = [proxy, tmp] () {
                    proxy->BatchOnNotify(tmp);
                };
                ffrt::submit(task);
                it.second.events.clear();
                it.second.eventsBuffSize = 0;
            }
            // 只处理第一个相同的eventid
            break;
        }
    }
    return true;
}

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AcquireDataSubscribeManager::GetInstance().BatchPublish(events);
}
}