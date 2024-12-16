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
#include <functional>
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
#include "security_event_filter.h"
namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr size_t MAX_CACHE_EVENT_SIZE = 64 * 1024;
    constexpr int64_t MAX_DURATION_TEN_SECOND = 10 * 1000;
    std::mutex g_mutex{};
    std::map<sptr<IRemoteObject>, AcquireDataSubscribeManager::SubscriberInfo> g_subscriberInfoMap{};
}

AcquireDataSubscribeManager& AcquireDataSubscribeManager::GetInstance()
{
    static AcquireDataSubscribeManager instance;
    return instance;
}

AcquireDataSubscribeManager::AcquireDataSubscribeManager() : listener_(std::make_shared<DbListener>()),
    collectorListenner_(std::make_shared<CollectorListenner>()) {}

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

    std::lock_guard<std::mutex> lock(g_mutex);
    SubscriberInfo subInfo {};
    if (g_subscriberInfoMap.count(callback) == 0) {
        subInfo.subscribe.emplace_back(subscribeInfo);
        subInfo.timer = std::make_shared<CleanupTimer>();
        subInfo.timer->Start(callback, MAX_DURATION_TEN_SECOND);
        g_subscriberInfoMap[callback] = subInfo;
    } else {
        g_subscriberInfoMap.at(callback).subscribe.emplace_back(subscribeInfo);
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
    SGLOGI("InsertSubscribeRecord subscriberInfoMap_size  %{public}zu", g_subscriberInfoMap.size());
    for (const auto &i : g_subscriberInfoMap) {
        SGLOGI("InsertSubscribeRecord subscriberInfoMap_subscribe_size  %{public}zu", i.second.subscribe.size());
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeSc(int64_t eventId)
{
    EventCfg config {};
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        return SUCCESS;
    }
    // 订阅SG
    if (config.prog == "security_guard") {
        SGLOGI("start collector, eventId:%{public}" PRId64, eventId);
        if (!SecurityCollector::DataCollection::GetInstance().StartCollectors({eventId}, collectorListenner_)) {
            SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64, eventId);
            return FAILED;
        }
        return SUCCESS;
    }
    // 订阅SC
    SecurityCollector::Event scEvent;
    scEvent.eventId = eventId;
    auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(scEvent);
    int code = SecurityCollector::CollectorManager::GetInstance().Subscribe(subscriber);
    if (code != SUCCESS) {
        SGLOGI("Subscribe SC failed, code=%{public}d", code);
        return code;
    }
    scSubscribeMap_[eventId] = subscriber;
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
    if (config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        return SUCCESS;
    }
    // 解订阅SG
    if (config.prog == "security_guard") {
        if (!SecurityCollector::DataCollection::GetInstance().StopCollectors({eventId})) {
            SGLOGE("UnSubscribe SG failed, eventId=%{public}" PRId64, eventId);
            return FAILED;
        }
        SGLOGI("UnSubscribeSc scSubscribeMap_size  %{public}zu", scSubscribeMap_.size());
        return SUCCESS;
    }
    // 解订阅SC
    auto it = scSubscribeMap_.find(eventId);
    if (it == scSubscribeMap_.end()) {
        SGLOGE("event not subscribe eventId=%{public}" PRId64, eventId);
        return FAILED;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().Unsubscribe(it->second);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribe SC failed, ret=%{public}d", ret);
        return ret;
    }
    it->second = nullptr;
    scSubscribeMap_.erase(it);
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
    std::lock_guard<std::mutex> lock(g_mutex);
    auto iter = g_subscriberInfoMap.find(callback);
    if (iter == g_subscriberInfoMap.end()) {
        SGLOGI("not find caller in g_subscriberInfoMap");
        return SUCCESS;
    }
    // first erase current callback subscribed info
    for (auto it = g_subscriberInfoMap.at(callback).subscribe.begin();
        it != g_subscriberInfoMap.at(callback).subscribe.end(); it++) {
        if (it->GetEvent().eventId == eventId) {
            g_subscriberInfoMap.at(callback).subscribe.erase(it);
            break;
        }
    }
    // second erase current callback  when subscribed member is empty
    if (g_subscriberInfoMap.at(callback).subscribe.empty()) {
        g_subscriberInfoMap.erase(iter);
    }
    
    for (const auto &it : g_subscriberInfoMap) {
        for (const auto &i : it.second.subscribe) {
            if (i.GetEvent().eventId == eventId) {
                return SUCCESS;
            }
        }
    }
    SGLOGI("RemoveSubscribeRecord subscriberInfoMap__size %{public}zu", g_subscriberInfoMap.size());
    for (const auto &i : g_subscriberInfoMap) {
        SGLOGI("RemoveSubscribeRecord subscriberInfoMap_subscribe_size  %{public}zu", i.second.subscribe.size());
    }
    return UnSubscribeScAndDb(eventId);
}

void AcquireDataSubscribeManager::RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    auto iter = g_subscriberInfoMap.find(callback);
    if (iter == g_subscriberInfoMap.end()) {
        SGLOGI("not find caller in g_subscriberInfoMap");
        return;
    }
    std::set<int64_t> eventIdNeedUnSub {};
    std::set<int64_t> currentEventId {};
    for (const auto &i : g_subscriberInfoMap.at(callback).subscribe) {
        eventIdNeedUnSub.insert(i.GetEvent().eventId);
    }
    g_subscriberInfoMap.erase(iter);
    for (const auto &i : g_subscriberInfoMap) {
        for (const auto &iter : i.second.subscribe) {
            currentEventId.insert(iter.GetEvent().eventId);
        }
    }
    for (const auto &i : eventIdNeedUnSub) {
        if (currentEventId.count(i) == 0) {
            (void)UnSubscribeScAndDb(i);
        }
    }
    SGLOGI("RemoveSubscribeRecordOnRemoteDied subscriberInfoMap__size %{public}zu", g_subscriberInfoMap.size());
    for (const auto &i : g_subscriberInfoMap) {
        SGLOGI("RemoveSubscribeRecordOnRemoteDied subscriberInfoMap_subscribe_size  %{public}zu",
            i.second.subscribe.size());
    }
    callbackHashMap_.erase(callback);
}
void AcquireDataSubscribeManager::CleanupTimer::ClearEventCache(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGD("timer running");
    if (g_subscriberInfoMap.count(remote) == 0) {
        SGLOGI("not found callback");
        return;
    }
    std::vector<SecurityCollector::Event> tmp = g_subscriberInfoMap.at(remote).events;
    if (tmp.empty()) {
        return;
    }
    auto proxy = iface_cast<IAcquireDataCallback>(remote);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return;
    }
    auto task = [proxy, tmp] () {
        proxy->OnNotify(tmp);
    };
    ffrt::submit(task);
    g_subscriberInfoMap.at(remote).events.clear();
    g_subscriberInfoMap.at(remote).eventsBuffSize = 0;
}

void AcquireDataSubscribeManager::BatchUpload(sptr<IRemoteObject> obj,
    const std::vector<SecurityCollector::Event> &events)
{
    auto proxy = iface_cast<IAcquireDataCallback>(obj);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return;
    }
    auto task = [proxy, events] () {
        proxy->OnNotify(events);
    };
    SGLOGI("upload event to subscribe");
    ffrt::submit(task);
}

bool AcquireDataSubscribeManager::BatchPublish(const SecurityCollector::Event &event)
{
    for (auto &it : g_subscriberInfoMap) {
        for (const auto &i : it.second.subscribe) {
            if (i.GetEvent().eventId != event.eventId) {
                continue;
            }
            // has set mute, but this event not belong the sub, means the filter of this sub set has work
            if (callbackHashMap_.count(it.first) != 0 &&
                event.eventSubscribes.count(callbackHashMap_.at(it.first)) == 0) {
                continue;
            }
            if (!ConfigDataManager::GetInstance().GetIsBatchUpload(i.GetEventGroup())) {
                BatchUpload(it.first, {event});
                continue;
            }
            it.second.events.emplace_back(event);
            it.second.eventsBuffSize += sizeof(event);
            SGLOGD("cache batch upload event to subscribe %{public}zu", it.second.eventsBuffSize);
            if (it.second.eventsBuffSize >= MAX_CACHE_EVENT_SIZE) {
                BatchUpload(it.first, it.second.events);
                SGLOGI("upload events to batch subscribe, size is %{public}zu", it.second.eventsBuffSize);
                it.second.events.clear();
                it.second.eventsBuffSize = 0;
            }
            break;
        }
    }
    return true;
}

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SecurityCollector::Event event {
        .eventId = events.eventId,
        .version = events.version,
        .content = events.content,
        .timestamp = events.date
    };
    AcquireDataSubscribeManager::GetInstance().BatchPublish(event);
}

void AcquireDataSubscribeManager::CollectorListenner::OnNotify(const SecurityCollector::Event &event)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    AcquireDataSubscribeManager::GetInstance().BatchPublish(event);
}
int32_t AcquireDataSubscribeManager::SecurityCollectorSubscriber::OnNotify(const SecurityCollector::Event &event)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    AcquireDataSubscribeManager::GetInstance().BatchPublish(event);
    return 0;
}

int AcquireDataSubscribeManager::InsertSubscribeMutue(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    SecurityGuard::EventMuteFilter sgFilter = subscribeMute.GetMuteFilter();
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = static_cast<SecurityCollector::SecurityCollectorEventMuteType>(sgFilter.type);
    if (scSubscribeMap_.count(sgFilter.eventId) == 0 || g_subscriberInfoMap.count(callback) == 0) {
        SGLOGE("event id not support set mute 0x%{public}" PRIx64, sgFilter.eventId);
        return BAD_PARAM;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().SetSubscribeMute(collectorFilter, sdkFlag);
    if (ret != SUCCESS) {
        SGLOGE("InsertSubscribeMutue failed, ret=%{public}d", ret);
        return ret;
    }
    callbackHashMap_[callback] = sdkFlag;
    return SUCCESS;
}
int AcquireDataSubscribeManager::RemoveSubscribeMutue(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (callbackHashMap_.count(callback) == 0) {
        SGLOGI("not find caller in callbackHashMap_");
        return FAILED;
    }
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    SecurityGuard::EventMuteFilter sgFilter = subscribeMute.GetMuteFilter();
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = static_cast<SecurityCollector::SecurityCollectorEventMuteType>(sgFilter.type);
    if (scSubscribeMap_.count(sgFilter.eventId) == 0 || g_subscriberInfoMap.count(callback) == 0) {
        SGLOGE("event id not support set unmute 0x%{public}" PRIx64, sgFilter.eventId);
        return BAD_PARAM;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().SetSubscribeUnMute(collectorFilter, sdkFlag);
    if (ret != SUCCESS) {
        SGLOGE("RemoveSubscribeMutue failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
}