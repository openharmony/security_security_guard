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
#include "file_ex.h"
#include "ipc_skeleton.h"
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
#include "security_event_info.h"
#include "data_format.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr size_t MAX_CACHE_EVENT_SIZE = 64 * 1024;
    constexpr int64_t MAX_DURATION_TEN_SECOND = 10 * 1000;
    constexpr int64_t MAX_FILTER_SIZE = 256;
    constexpr size_t MAX_SUBS_SIZE = 10;
    constexpr size_t MAX_SESSION_SIZE = 16;
    constexpr size_t MAX_SESSION_SIZE_ONE_PROCESS = 2;
    std::mutex g_mutex{};
    constexpr int64_t PROCESS_ID_IN_KERNEL_MONITOR = 0x01C000004;
    constexpr int64_t FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR = 1011015020;
    std::map<int64_t, std::map<sptr<IRemoteObject>,
        std::shared_ptr<AcquireDataSubscribeManager::SubscriberInfo>>> g_subscriberInfoMap{};
    std::map<int64_t, std::string> g_eventGroupMap{};
}

AcquireDataSubscribeManager& AcquireDataSubscribeManager::GetInstance()
{
    static AcquireDataSubscribeManager instance;
    return instance;
}

AcquireDataSubscribeManager::AcquireDataSubscribeManager() : listener_(std::make_shared<DbListener>()),
    collectorListener_(std::make_shared<CollectorListener>())
{
    handle_ = dlopen(SECURITY_GUARD_EVENT_FILTER_PATH, RTLD_LAZY);
    if (handle_ != nullptr) {
        eventFilter_ = reinterpret_cast<GetEventFilterFunc>(dlsym(handle_, "GetEventFilter"));
    }
}

int AcquireDataSubscribeManager::InsertSubscribeRecord(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t code = IsExceedLimited(clientId, callerToken);
    if (code != SUCCESS) {
        SGLOGE("IsExceedLimited error");
        return code;
    }
    int64_t eventId = subscribeInfo.GetEvent().eventId;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (sessionsMap_.find(clientId) != sessionsMap_.end() && sessionsMap_.at(clientId) != nullptr &&
        sessionsMap_.at(clientId)->subEvents.find(eventId) != sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGE("not need subscribe again");
        return SUCCESS;
    }
    code = DatabaseManager::GetInstance().SubscribeDb({eventId}, listener_);
    if (code != SUCCESS) {
        SGLOGE("SubscribeDb error");
        return code;
    }
    code = SubscribeSc(eventId, callback);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
    }
    g_subscriberInfoMap[eventId][callback] = ConstructSubInfo(callback, clientId);
    g_eventGroupMap[eventId] = subscribeInfo.GetEventGroup();
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        auto session = std::make_shared<ClientSession>();
        session->clientId = clientId;
        session->callback = callback;
        session->tokenId = callerToken;
        sessionsMap_[clientId] = session;
    }
    sessionsMap_[clientId]->subEvents.insert(eventId);
    if (sessionsMap_.at(clientId)->eventFilters.find(eventId) == sessionsMap_.at(clientId)->eventFilters.end()) {
        return SUCCESS;
    }
    for (auto iter : sessionsMap_.at(clientId)->eventFilters.at(eventId)) {
        InsertMute(iter, clientId);
    }
    return SUCCESS;
}

std::shared_ptr<AcquireDataSubscribeManager::SubscriberInfo> AcquireDataSubscribeManager::ConstructSubInfo(
    const sptr<IRemoteObject> &callback, const std::string &clientId)
{
    std::shared_ptr<SubscriberInfo> ptr = nullptr;
    for (auto iter : g_subscriberInfoMap) {
        auto it = iter.second.find(callback);
        if (it != iter.second.end()) {
            ptr = it->second;
            break;
        }
    }
    if (ptr == nullptr) {
        ptr = std::make_shared<SubscriberInfo> ();
        ptr->clientId = clientId;
    }
    return ptr;
}

int AcquireDataSubscribeManager::InsertMute(const EventMuteFilter &filter, const std::string &clientId)
{
    int ret = SUCCESS;
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        ret = AddSubscribeMuteToSub(collectorFilter, config);
    } else {
        if (eventFilter_ == nullptr) {
            SGLOGE("eventFilter_ is null");
            return NULL_OBJECT;
        }
        ret = eventFilter_()->SetEventFilter(collectorFilter);
    }
    if (ret != SUCCESS) {
        SGLOGE("SetEventFilter failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSg(int64_t eventId, const sptr<IRemoteObject> &callback)
{
    SecurityCollector::Event event {};
    event.eventId = eventId;
    SGLOGI("Scheduling start collector, eventId:%{public}" PRId64, eventId);
    if (eventToListenner_.count(eventId) != 0) {
        return SUCCESS;
    }
    if (collectorListener_ == nullptr) {
        SGLOGE("collectorListener is nullptr");
        return NULL_OBJECT;
    }
    if (!SecurityCollector::DataCollection::GetInstance().SubscribeCollectors({eventId}, collectorListener_)) {
        SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64, eventId);
        return FAILED;
    }
    eventToListenner_.emplace(eventId, collectorListener_);
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

int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    auto iter = g_subscriberInfoMap.find(eventId);
    if (iter == g_subscriberInfoMap.end()) {
        SGLOGW("not find eventId in g_subscriberInfoMap");
        return SUCCESS;
    }
    g_subscriberInfoMap.at(eventId).erase(callback);
    if (g_subscriberInfoMap.at(eventId).empty()) {
        g_subscriberInfoMap.erase(eventId);
    }
    int ret = UnSubscribeScAndDb(eventId);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribeScAndDb fail");
        return ret;
    }
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return SUCCESS;
    }
    if (sessionsMap_.at(clientId) == nullptr) {
        sessionsMap_.erase(clientId);
    }
    if (sessionsMap_.at(clientId)->eventFilters.find(eventId) == sessionsMap_.at(clientId)->eventFilters.end()) {
        return SUCCESS;
    }
    for (auto iter : sessionsMap_.at(clientId)->eventFilters.at(eventId)) {
        RemoveSubscribeMute(iter, clientId);
    }
    return ret;
}

void AcquireDataSubscribeManager::RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::set<int64_t> eventIdNeedUnSub {};
    std::set<int64_t> currentEventId {};
    for (const auto &iter : g_subscriberInfoMap) {
        auto i = iter.second.find(callback);
        if (i != iter.second.end()) {
            eventIdNeedUnSub.insert(iter.first);
        }
    }
    for (const auto &iter : eventIdNeedUnSub) {
        if (g_subscriberInfoMap.find(iter) == g_subscriberInfoMap.end()) {
            continue;
        }
        g_subscriberInfoMap.at(iter).erase(callback);
        if (g_subscriberInfoMap.at(iter).empty()) {
            g_subscriberInfoMap.erase(iter);
            (void)UnSubscribeScAndDb(iter);
        }
    }
    auto finder = [callback](std::pair<std::string, std::shared_ptr<ClientSession>> iter) {
        return callback == iter.second->callback;
    };
    auto iter = find_if(sessionsMap_.begin(), sessionsMap_.end(), finder);
    if (iter != sessionsMap_.end()) {
        if (eventFilter_ != nullptr) {
            eventFilter_()->RemoveSdkAllEventFilter(iter->first);
        }
        sessionsMap_.erase(iter);
    }
}

void AcquireDataSubscribeManager::StartClearEventCache()
{
    auto task = [this]() {
        while (true) {
            this->ClearEventCache();
            ffrt::this_task::sleep_for(std::chrono::milliseconds(MAX_DURATION_TEN_SECOND));
        }
    };
    ffrt::submit(task);
}

// LCOV_EXCL_START
void AcquireDataSubscribeManager::ClearEventCache()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGD("timer running");
    for (const auto &iter : g_subscriberInfoMap) {
        for (auto &i : iter.second) {
            if (i.second == nullptr) {
                SGLOGW("SubscriberInfo is null");
                continue;
            }
            auto proxy = iface_cast<IAcquireDataCallback>(i.first);
            if (proxy == nullptr) {
                SGLOGE("proxy is null");
                return;
            }
            auto tmp = i.second->events;
            auto task = [proxy, tmp] () {
                proxy->OnNotify(tmp);
            };
            ffrt::submit(task);
            i.second->events.clear();
            i.second->eventsBuffSize = 0;
        }
    }
}
// LCOV_EXCL_STOP

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
    SGLOGD("UploadEvent eventid = %{public}" PRId64, event.eventId);
    SGLOGD("UploadEvent event conetnt = %{private}s", event.content.c_str());
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

bool AcquireDataSubscribeManager::IsFindFlag(const std::set<std::string> &eventSubscribes, int64_t eventId,
    const std::string &clientId)
{
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return false;
    }
    if (sessionsMap_.at(clientId)->eventFilters.find(eventId) == sessionsMap_.at(clientId)->eventFilters.end() ||
        sessionsMap_.at(clientId)->eventFilters.at(eventId).empty()) {
        return true;
    }
    if (eventSubscribes.find(clientId) != eventSubscribes.end()) {
        return true;
    }
    return false;
}

bool AcquireDataSubscribeManager::BatchPublish(const SecurityCollector::Event &event)
{
    SecurityCollector::Event eventTmp = event;
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, eventTmp.eventId);
        return false;
    }
    eventTmp.eventId = config.eventId;
    if (eventFilter_ != nullptr && config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        eventFilter_()->GetFlagsEventNeedToUpload(eventTmp);
    }
    auto iter = g_subscriberInfoMap.find(eventTmp.eventId);
    if (iter == g_subscriberInfoMap.end()) {
        SGLOGW("not sub eventId=%{public}" PRId64, eventTmp.eventId);
        return true;
    }
    for (auto &it : iter->second) {
        if (!IsFindFlag(eventTmp.eventSubscribes, eventTmp.eventId, it.second->clientId)) {
            SGLOGW("IsFindFlag eventId=%{public}" PRId64, eventTmp.eventId);
            continue;
        }
        if (!ConfigDataManager::GetInstance().GetIsBatchUpload(g_eventGroupMap[eventTmp.eventId])) {
            BatchUpload(it.first, {eventTmp});
            continue;
        }
        SGLOGD("publish eventid=%{public}" PRId64, eventTmp.eventId);
        for (auto iter : eventTmp.eventSubscribes) {
            SGLOGD("publish eventSubscribes =%{public}s", iter.c_str());
        }
        it.second->events.emplace_back(eventTmp);
        it.second->eventsBuffSize += GetSecurityCollectorEventBufSize(eventTmp);
        SGLOGD("cache batch upload event to subscribe %{public}zu", it.second->eventsBuffSize);
        if (it.second->eventsBuffSize >= MAX_CACHE_EVENT_SIZE) {
            BatchUpload(it.first, it.second->events);
            SGLOGI("upload events to batch subscribe, size is %{public}zu", it.second->eventsBuffSize);
            it.second->events.clear();
            it.second->eventsBuffSize = 0;
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

void AcquireDataSubscribeManager::CollectorListener::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
}

int32_t AcquireDataSubscribeManager::SecurityCollectorSubscriber::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    return 0;
}

int AcquireDataSubscribeManager::CheckInsertMute(const EventMuteFilter &filter, const std::string &clientId)
{
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGE("clientId not creat");
        return BAD_PARAM;
    }
    auto finder = [filter](const EventMuteFilter &it) {
        return filter.eventGroup == it.eventGroup && filter.eventId == it.eventId && filter.isInclude == it.isInclude &&
        filter.type == it.type && filter.mutes.size() == it.mutes.size() && filter.mutes == it.mutes;
    };
    if (sessionsMap_.at(clientId)->eventFilters.find(filter.eventId) != sessionsMap_.at(clientId)->eventFilters.end() &&
        find_if(sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).begin(),
        sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).end(), finder) !=
        sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).end()) {
        SGLOGE("filter exist");
        return BAD_PARAM;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::InsertSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    int ret = CheckInsertMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("CheckInsertMute failed, ret=%{public}d", ret);
        return ret;
    }
    if (sessionsMap_.at(clientId)->subEvents.find(filter.eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGW("current event not subscribe, cache filter now evetid= %{public}" PRId64, filter.eventId);
        sessionsMap_.at(clientId)->eventFilters[filter.eventId].emplace_back(filter);
        return SUCCESS;
    }
    ret = InsertMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("RemoveMute failed, ret=%{public}d", ret);
        return ret;
    }
    sessionsMap_.at(clientId)->eventFilters[filter.eventId].emplace_back(filter);
    return SUCCESS;
}

// LCOV_EXCL_START
void AcquireDataSubscribeManager::SubscriberEventOnSgStart()
{
    std::vector<int64_t> eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    std::vector<int64_t> onStartEventList;
    for (int64_t eventId : eventIds) {
        EventCfg eventCfg;
        bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, eventCfg);
        if (!isSuccess) {
            SGLOGI("GetEventConfig error");
        } else if (eventCfg.collectOnStart == 1) {
            onStartEventList.push_back(eventId);
        }
    }
    if (listener_ == nullptr || collectorListener_ == nullptr) {
        SGLOGI("listener or collectorListener is nullptr");
        return;
    }
    if (DatabaseManager::GetInstance().SubscribeDb(onStartEventList, listener_) != SUCCESS) {
        SGLOGE("SubscribeDb error");
    }
    if (!SecurityCollector::DataCollection::GetInstance().SubscribeCollectors(onStartEventList, collectorListener_)) {
        SGLOGE("subscribe sg failed");
    }
}
// LCOV_EXCL_STOP

int AcquireDataSubscribeManager::RemoveSubscribeMuteToSub(
    const SecurityCollector::SecurityCollectorEventMuteFilter &collectorFilter, const EventCfg &config)
{
    if (config.prog == "security_guard") {
        int32_t ret = SecurityCollector::DataCollection::GetInstance().RemoveFilter(collectorFilter);
        if (ret != SUCCESS) {
            SGLOGI("RemoveFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
            return ret;
        }
    } else {
        int ret = SecurityCollector::CollectorManager::GetInstance().RemoveFilter(collectorFilter);
        if (ret != SUCCESS) {
            SGLOGE("RemoveSubscribeMute failed, ret=%{public}d", ret);
            return ret;
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::AddSubscribeMuteToSub(
    const SecurityCollector::SecurityCollectorEventMuteFilter &collectorFilter, const EventCfg &config)
{
    if (config.prog == "security_guard") {
        int32_t ret = SecurityCollector::DataCollection::GetInstance().AddFilter(collectorFilter);
        if (ret != SUCCESS) {
            SGLOGI("AddFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
            return ret;
        }
    } else {
        int32_t ret = SecurityCollector::CollectorManager::GetInstance().AddFilter(collectorFilter);
        if (ret != SUCCESS) {
            SGLOGE("InsertSubscribeMute failed, ret=%{public}d", ret);
            return ret;
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveMute(const EventMuteFilter &filter, const std::string &clientId)
{
    EventCfg config {};
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    int ret = SUCCESS;
    if (config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        ret = RemoveSubscribeMuteToSub(collectorFilter, config);
    } else {
        if (eventFilter_ == nullptr) {
            SGLOGE("eventFilter_ is null");
            return NULL_OBJECT;
        }
        ret = eventFilter_()->RemoveEventFilter(collectorFilter);
    }
    if (ret != SUCCESS) {
        SGLOGE("RemoveSubscribeMuteToSub failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGI("in AcquireDataSubscribeManager RemoveSubscribeMute");
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGE("clientId not creat");
        return BAD_PARAM;
    }
    auto finder = [filter](const EventMuteFilter &it) {
        return filter.eventGroup == it.eventGroup && filter.eventId == it.eventId && filter.isInclude == it.isInclude &&
        filter.type == it.type && filter.mutes.size() == it.mutes.size() && filter.mutes == it.mutes;
    };
    if (sessionsMap_.at(clientId)->eventFilters.find(filter.eventId) == sessionsMap_.at(clientId)->eventFilters.end()) {
        SGLOGE("filter event id not exist");
        return BAD_PARAM;
    }
    auto iter = find_if(sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).begin(),
        sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).end(), finder);
    if (iter == sessionsMap_.at(clientId)->eventFilters.at(filter.eventId).end()) {
        SGLOGE("filter not exist");
        return BAD_PARAM;
    }
    if (sessionsMap_.at(clientId)->subEvents.find(filter.eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGW("current event not subscribe, erase filter now evetid= %{public}" PRId64, filter.eventId);
        iter = sessionsMap_.at(clientId)->eventFilters[filter.eventId].erase(iter);
        if (sessionsMap_.at(clientId)->eventFilters[filter.eventId].empty()) {
            sessionsMap_.at(clientId)->eventFilters.erase(filter.eventId);
        }
        return SUCCESS;
    }
    int ret = RemoveMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("RemoveMute failed, ret=%{public}d", ret);
        return ret;
    }
    iter = sessionsMap_.at(clientId)->eventFilters[filter.eventId].erase(iter);
    if (sessionsMap_.at(clientId)->eventFilters[filter.eventId].empty()) {
        sessionsMap_.at(clientId)->eventFilters.erase(filter.eventId);
    }
    return SUCCESS;
}

SecurityCollector::SecurityCollectorEventMuteFilter AcquireDataSubscribeManager::ConvertFilter(
    const SecurityGuard::EventMuteFilter &sgFilter, const std::string &clientId)
{
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = sgFilter.type;
    collectorFilter.isInclude = sgFilter.isInclude;
    collectorFilter.isSetMute = false;
    collectorFilter.instanceFlag = clientId;
    return collectorFilter;
}

int AcquireDataSubscribeManager::CreatClient(const std::string &eventGroup, const std::string &clientId,
    const sptr<IRemoteObject> &cb)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int ret = IsExceedLimited(clientId, callerToken);
    if (ret != SUCCESS) {
        SGLOGE("IsExceedLimited error");
        return ret;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    if (sessionsMap_.find(clientId) != sessionsMap_.end()) {
        SGLOGE("current clientId exist");
        return BAD_PARAM;
    }
    auto session = std::make_shared<ClientSession>();
    session->clientId = clientId;
    session->callback = cb;
    session->tokenId = callerToken;
    sessionsMap_[clientId] = session;
    return SUCCESS;
}

int AcquireDataSubscribeManager::DestoryClient(const std::string &eventGroup, const std::string &clientId)
{
    auto iter = sessionsMap_.find(clientId);
    if (iter == sessionsMap_.end()) {
        SGLOGE("current clientId not exist");
        return BAD_PARAM;
    }
    auto callBack = sessionsMap_.at(clientId)->callback;
    for (auto iter : sessionsMap_.at(clientId)->subEvents) {
        RemoveSubscribeRecord(iter, callBack, clientId);
    }
    for (auto iter : sessionsMap_.at(clientId)->eventFilters) {
        for (auto it : iter.second) {
            RemoveSubscribeMute(it, clientId);
        }
    }
    sessionsMap_.erase(clientId);
    return SUCCESS;
}


int AcquireDataSubscribeManager::IsExceedLimited(const std::string &clientId, AccessToken::AccessTokenID callerToken)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (sessionsMap_.size() >= MAX_SESSION_SIZE) {
        SGLOGE("max instance limited");
        return CLIENT_EXCEED_GLOBAL_LIMIT;
    }
    size_t sessionSize = 0;
    std::set<std::string> clients {};
    for (auto iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->tokenId == callerToken) {
            clients.insert(iter.first);
        }
    }
    if (clients.find(clientId) == clients.end() && clients.size() >= MAX_SESSION_SIZE_ONE_PROCESS) {
        SGLOGE("max instance one process limited");
        return CLIENT_EXCEED_PROCESS_LIMIT;
    }
    return SUCCESS;
}
}
