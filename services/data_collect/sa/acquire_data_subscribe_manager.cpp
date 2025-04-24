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
#include "data_format.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr size_t MAX_CACHE_EVENT_SIZE = 64 * 1024;
    constexpr int64_t MAX_DURATION_TEN_SECOND = 10 * 1000;
    constexpr int64_t MAX_FILTER_SIZE = 256;
    constexpr size_t MAX_SUBS_SIZE = 10;
    std::mutex g_mutex{};
    std::map<sptr<IRemoteObject>, AcquireDataSubscribeManager::SubscriberInfo> g_subscriberInfoMap{};
}

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

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_subscriberInfoMap.size() >= MAX_SUBS_SIZE) {
        SGLOGE("has been max subscriber size");
        return BAD_PARAM;
    }

    int32_t code = DatabaseManager::GetInstance().SubscribeDb({subscribeInfo.GetEvent().eventId}, listener_);
    if (code != SUCCESS) {
        SGLOGE("SubscribeDb error");
        return code;
    }
    code = SubscribeSc(subscribeInfo.GetEvent().eventId, callback);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
    }

    if (g_subscriberInfoMap.count(callback) == 0) {
        SubscriberInfo subInfo {};
        subInfo.subscribe.emplace_back(subscribeInfo);
        subInfo.timer = std::make_shared<CleanupTimer>();
        subInfo.timer->Start(callback, MAX_DURATION_TEN_SECOND);
        g_subscriberInfoMap[callback] = subInfo;
    } else {
        g_subscriberInfoMap.at(callback).subscribe.emplace_back(subscribeInfo);
    }
    SGLOGI("InsertSubscribeRecord subscriberInfoMap_size  %{public}zu", g_subscriberInfoMap.size());

    for (const auto &i : g_subscriberInfoMap) {
        SGLOGI("InsertSubscribeRecord subscriberInfoMap_subscribe_size  %{public}zu", i.second.subscribe.size());
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSg(int64_t eventId, const sptr<IRemoteObject> &callback)
{
    SecurityCollector::Event event {};
    event.eventId = eventId;
    auto collectorListenner = std::make_shared<CollectorListenner>(event);
    SGLOGI("Scheduling start collector, eventId:%{public}" PRId64, eventId);
    if (eventToListenner_.count(eventId) != 0) {
        return SUCCESS;
    }
    if (!SecurityCollector::DataCollection::GetInstance().SubscribeCollectors({eventId}, collectorListenner)) {
        SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64, eventId);
        return FAILED;
    }
    eventToListenner_.emplace(eventId, collectorListenner);
    if (muteCache_.count(eventId) == 0) {
        return SUCCESS;
    }
    for (const auto &iter : muteCache_.at(eventId)) {
        for (const auto &it : iter.second) {
            if (it.eventId == eventId && it.isSetMute == true &&
                !SecurityCollector::DataCollection::GetInstance().AddFilter(
                    it, callbackHashMapNotSetMute_[iter.first])) {
                SGLOGE("AddFilter SG failed, eventId=%{public}" PRId64, eventId);
            }
            callbackHashMap_[iter.first] = callbackHashMapNotSetMute_[iter.first];
            if (it.eventId == eventId && it.isSetMute == false &&
                !SecurityCollector::DataCollection::GetInstance().RemoveFilter(
                    it, callbackHashMapNotSetMute_[iter.first])) {
                SGLOGE("RemoveFilter SG failed, eventId=%{public}" PRId64, eventId);
            }
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSc(int64_t eventId, const sptr<IRemoteObject> &callback)
{
    if (scSubscribeMap_.count(eventId) != 0) {
        return SUCCESS;
    }
    SecurityCollector::Event scEvent;
    scEvent.eventId = eventId;
    auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(scEvent);
    int code = SecurityCollector::CollectorManager::GetInstance().Subscribe(subscriber);
    if (code != SUCCESS) {
        SGLOGI("Subscribe SC failed, code=%{public}d", code);
        return code;
    }
    scSubscribeMap_[eventId] = subscriber;
    if (muteCache_.count(eventId) == 0) {
        return SUCCESS;
    }
    SGLOGI("Subscribe SC muteCache_ size, code=%{public}zu  eventId=%{public}" PRId64,
        muteCache_.at(eventId).size(), eventId);
    for (const auto &iter : muteCache_.at(eventId)) {
        for (auto it : iter.second) {
            if (it.eventId == eventId && it.isSetMute == true) {
                code = SecurityCollector::CollectorManager::GetInstance().AddFilter(
                    it, callbackHashMapNotSetMute_[iter.first]);
            }
            callbackHashMap_[iter.first] = callbackHashMapNotSetMute_[iter.first];
            if (it.eventId == eventId && it.isSetMute == false) {
                code = SecurityCollector::CollectorManager::GetInstance().RemoveFilter(
                    it, callbackHashMapNotSetMute_[iter.first]);
            }
        }
    }
    if (code != SUCCESS) {
        SGLOGE("mute or unmute has some err code=%{public}d", code);
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeSc(int64_t eventId, const sptr<IRemoteObject> &callback)
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
        return SubscribeScInSg(eventId, callback);
    }

    // 订阅SC
    return SubscribeScInSc(eventId, callback);
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
        if (eventToListenner_.count(eventId) == 0) {
            SGLOGE("not find evenId in linstener, eventId=%{public}" PRId64, eventId);
            return FAILED;
        }
        if (!SecurityCollector::DataCollection::GetInstance().UnsubscribeCollectors({eventId})) {
            SGLOGE("UnSubscribe SG failed, eventId=%{public}" PRId64, eventId);
            return FAILED;
        }
        eventToListenner_.erase(eventId);
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
    std::set<int64_t> eventIdNeedUnSub {};
    std::set<int64_t> currentEventId {};
    for (const auto &i : g_subscriberInfoMap[callback].subscribe) {
        eventIdNeedUnSub.insert(i.GetEvent().eventId);
    }
    g_subscriberInfoMap.erase(callback);
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
    callbackHashMapNotSetMute_.erase(callback);
    for (auto &iter : muteCache_) {
        auto it = iter.second.find(callback);
        if (it != iter.second.end()) {
            it = iter.second.erase(it);
            SGLOGI("erase callback muteCache_ %{public}zu", iter.second.size());
            continue;
        }
    }
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
    SGLOGD("upload event to subscribe");
    ffrt::submit(task);
}

void AcquireDataSubscribeManager::UploadEvent(const SecurityCollector::Event &event)
{
    if (!DataFormat::CheckRiskContent(event.content)) {
        SGLOGE("CheckRiskContent error");
        return;
    }
    SecEvent secEvent {
        .eventId = event.eventId,
        .version = event.version,
        .date = event.timestamp,
        .content = event.content
    };
    auto task = [secEvent, event] () mutable {
        int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, secEvent, event.eventSubscribes);
        if (code != SUCCESS) {
            SGLOGE("insert event error, %{public}d", code);
        }
    };
    ffrt::submit(task);
}

size_t AcquireDataSubscribeManager::GetSecurityCollectorEventBufSize(const SecurityCollector::Event &event)
{
    size_t res = sizeof(event.eventId);
    res += event.version.length();
    res += event.content.length();
    res += event.extra.length();
    res += event.timestamp.length();
    for (const auto &i : event.eventSubscribes) {
        res += i.length();
    }
    return res;
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
            SGLOGD("publish eventid=%{public}" PRId64, event.eventId);
            for (auto iter : event.eventSubscribes) {
                SGLOGD("publish eventSubscribes =%{public}s", iter.c_str());
            }
            it.second.events.emplace_back(event);
            it.second.eventsBuffSize += GetSecurityCollectorEventBufSize(event);
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

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events,
    const std::set<std::string> &eventSubscribes)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SecurityCollector::Event event {
        .eventId = events.eventId,
        .version = events.version,
        .content = events.content,
        .timestamp = events.date,
        .eventSubscribes = eventSubscribes
    };
    AcquireDataSubscribeManager::GetInstance().BatchPublish(event);
}

void AcquireDataSubscribeManager::CollectorListenner::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
}
int32_t AcquireDataSubscribeManager::SecurityCollectorSubscriber::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    return 0;
}

int64_t AcquireDataSubscribeManager::CollectorListenner::GetEventId()
{
    return event_.eventId;
}

int AcquireDataSubscribeManager::InsertSubscribeMute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGI("in AcquireDataSubscribeManager InsertSubscribeMute");
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    SecurityGuard::EventMuteFilter sgFilter = subscribeMute.GetMuteFilter();
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = sgFilter.type;
    collectorFilter.isInclude = sgFilter.isInclude;
    collectorFilter.isSetMute = true;
    EventCfg config {};
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (muteCache_[subscribeMute.GetMuteFilter().eventId][callback].size() >= MAX_FILTER_SIZE) {
        SGLOGI("current callback eventid size err, eventId=%{public}" PRId64, collectorFilter.eventId);
        return BAD_PARAM;
    }

    if (config.prog == "security_guard") {
        if (eventToListenner_.count(sgFilter.eventId) == 0) {
            SGLOGI("current collector not start eventId=%{public}" PRId64, sgFilter.eventId);
            muteCache_[subscribeMute.GetMuteFilter().eventId][callback].emplace_back(collectorFilter);
            callbackHashMapNotSetMute_[callback] = sdkFlag;
            return SUCCESS;
        }
        if (!SecurityCollector::DataCollection::GetInstance().AddFilter(collectorFilter, sdkFlag)) {
            SGLOGI("AddFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
            return FAILED;
        }
        callbackHashMap_[callback] = sdkFlag;
        return SUCCESS;
    }
    if (scSubscribeMap_.count(sgFilter.eventId) == 0) {
        SGLOGI("current sc collector not start eventId=%{public}" PRId64, sgFilter.eventId);
        muteCache_[subscribeMute.GetMuteFilter().eventId][callback].emplace_back(collectorFilter);
        callbackHashMapNotSetMute_[callback] = sdkFlag;
        return SUCCESS;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().AddFilter(collectorFilter, sdkFlag);
    if (ret != SUCCESS) {
        SGLOGE("InsertSubscribeMute failed, ret=%{public}d", ret);
        return ret;
    }
    callbackHashMap_[callback] = sdkFlag;
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeMute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGI("in AcquireDataSubscribeManager RemoveSubscribeMute");
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    SecurityGuard::EventMuteFilter sgFilter = subscribeMute.GetMuteFilter();
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = sgFilter.type;
    collectorFilter.isInclude = sgFilter.isInclude;
    collectorFilter.isSetMute = false;
    EventCfg config {};
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (muteCache_[sgFilter.eventId][callback].size() >= MAX_FILTER_SIZE) {
        SGLOGI("current callback eventid size err, eventId=%{public}" PRId64, collectorFilter.eventId);
        return BAD_PARAM;
    }

    if (config.prog == "security_guard") {
        if (eventToListenner_.count(sgFilter.eventId) == 0) {
            SGLOGI("current collector not start eventId=%{public}" PRId64, sgFilter.eventId);
            muteCache_[subscribeMute.GetMuteFilter().eventId][callback].emplace_back(collectorFilter);
            callbackHashMapNotSetMute_[callback] = sdkFlag;
            return SUCCESS;
        }
        if (!SecurityCollector::DataCollection::GetInstance().RemoveFilter(collectorFilter, sdkFlag)) {
            SGLOGI("RemoveFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
            return FAILED;
        }
        return SUCCESS;
    }
    if (scSubscribeMap_.count(sgFilter.eventId) == 0) {
        SGLOGI("current sc collector not start eventId=%{public}" PRId64, sgFilter.eventId);
        muteCache_[subscribeMute.GetMuteFilter().eventId][callback].emplace_back(collectorFilter);
        callbackHashMapNotSetMute_[callback] = sdkFlag;
        return SUCCESS;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().RemoveFilter(collectorFilter, sdkFlag);
    if (ret != SUCCESS) {
        SGLOGE("RemoveSubscribeMute failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
}