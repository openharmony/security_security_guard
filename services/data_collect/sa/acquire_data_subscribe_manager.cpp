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
    std::mutex g_mutex{};
    constexpr int64_t PROCESS_ID_IN_KERNEL_MONITOR = 0x01C000004;
    constexpr int64_t FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR = 1011015020;
    std::map<sptr<IRemoteObject>, AcquireDataSubscribeManager::SubscriberInfo> g_subscriberInfoMap{};
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
    if ((eventId == SecurityCollector::PROCESS_EVENTID || eventId == SecurityCollector::FILE_EVENTID) &&
        FileExists("/dev/hkids")) {
        SGLOGI("current eventId not need to start collector");
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
    if (callbackHashMap_.find(callback) != callbackHashMap_.end() && !callbackHashMap_.at(callback).empty() &&
        eventFilter_ != nullptr) {
        eventFilter_()->RemoveSdkAllEventFilter(callbackHashMap_.at(callback)[0]);
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

bool AcquireDataSubscribeManager::FindSdkFlag(const std::set<std::string> &eventSubscribes,
    const std::vector<std::string> &sdkFlags)
{
    if (sdkFlags.empty()) {
        return false;
    }
    std::string sdkFlag = sdkFlags[0];
    auto sdkFlagFinder = [sdkFlag] (const std::string &flag) {
        std::string subStr = flag.substr(0, flag.find_first_of("+"));
        return subStr == sdkFlag;
    };
    return std::find_if(eventSubscribes.begin(), eventSubscribes.end(), sdkFlagFinder) ==
        eventSubscribes.end();
}

bool AcquireDataSubscribeManager::BatchPublish(const SecurityCollector::Event &event)
{
    SecurityCollector::Event eventTmp = event;
    EventCfg config {};
    if (eventFilter_ != nullptr && ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config) &&
        config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        eventFilter_()->GetFlagsEventNeedToUpload(eventTmp);
    }
    for (auto &it : g_subscriberInfoMap) {
        for (const auto &i : it.second.subscribe) {
            if (i.GetEvent().eventId != eventTmp.eventId) {
                continue;
            }
            // has set mute, but this event not belong the sub, means the filter of this sub set has work
            if (callbackHashMap_.count(it.first) != 0 &&
                FindSdkFlag(eventTmp.eventSubscribes, callbackHashMap_.at(it.first))) {
                continue;
            }
            if (!ConfigDataManager::GetInstance().GetIsBatchUpload(i.GetEventGroup())) {
                BatchUpload(it.first, {eventTmp});
                continue;
            }
            SGLOGD("publish eventid=%{public}" PRId64, eventTmp.eventId);
            for (auto iter : eventTmp.eventSubscribes) {
                SGLOGD("publish eventSubscribes =%{public}s", iter.c_str());
            }
            it.second.events.emplace_back(eventTmp);
            it.second.eventsBuffSize += GetSecurityCollectorEventBufSize(eventTmp);
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

void AcquireDataSubscribeManager::CollectorListener::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
}
int32_t AcquireDataSubscribeManager::SecurityCollectorSubscriber::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    return 0;
}

int AcquireDataSubscribeManager::InsertSubscribeMute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(subscribeMute.GetMuteFilter());
    int64_t eventId = collectorFilter.eventId;
    if (FileExists("/dev/hkids")) {
        if (collectorFilter.eventId == SecurityCollector::PROCESS_EVENTID) {
            eventId = PROCESS_ID_IN_KERNEL_MONITOR;
        }
        if (collectorFilter.eventId == SecurityCollector::FILE_EVENTID) {
            eventId = FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR;
            collectorFilter.eventId = FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR;
        }
    }
    EventCfg config {};
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        if (config.prog == "security_guard") {
            int32_t ret = SecurityCollector::DataCollection::GetInstance().AddFilter(collectorFilter, sdkFlag);
            if (ret != SUCCESS) {
                SGLOGI("AddFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
                return ret;
            }
        } else {
            int32_t ret = SecurityCollector::CollectorManager::GetInstance().AddFilter(collectorFilter, sdkFlag);
            if (ret != SUCCESS) {
                SGLOGE("InsertSubscribeMute failed, ret=%{public}d", ret);
                return ret;
            }
        }
    } else {
        if (eventFilter_ == nullptr) {
            SGLOGE("eventFilter_ is null");
            return NULL_OBJECT;
        }
        int32_t ret = eventFilter_()->SetEventFilter(sdkFlag, collectorFilter);
        if (ret != SUCCESS) {
            SGLOGE("SetEventFilter failed, ret=%{public}d", ret);
            return ret;
        }
    }
    callbackHashMap_[callback].emplace_back(sdkFlag);
    return SUCCESS;
}

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

int AcquireDataSubscribeManager::RemoveSubscribeMuteToSub(
    const SecurityCollector::SecurityCollectorEventMuteFilter &collectorFilter, const EventCfg &config,
    const std::string &sdkFlag)
{
    if (config.prog == "security_guard") {
        int32_t ret = SecurityCollector::DataCollection::GetInstance().RemoveFilter(collectorFilter, sdkFlag);
        if (ret != SUCCESS) {
            SGLOGI("RemoveFilter SG failed, eventId=%{public}" PRId64, collectorFilter.eventId);
            return ret;
        }
    } else {
        int ret = SecurityCollector::CollectorManager::GetInstance().RemoveFilter(collectorFilter, sdkFlag);
        if (ret != SUCCESS) {
            SGLOGE("RemoveSubscribeMute failed, ret=%{public}d", ret);
            return ret;
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeMute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    SGLOGI("in AcquireDataSubscribeManager RemoveSubscribeMute");
    EventCfg config {};
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(subscribeMute.GetMuteFilter());
    int64_t eventId = collectorFilter.eventId;
    if (FileExists("/dev/hkids")) {
        if (collectorFilter.eventId == SecurityCollector::PROCESS_EVENTID) {
            eventId = PROCESS_ID_IN_KERNEL_MONITOR;
        }
        if (collectorFilter.eventId == SecurityCollector::FILE_EVENTID) {
            eventId = FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR;
            collectorFilter.eventId = FILE_EVENT_CHANGE_ID_IN_KERNEL_MONITOR;
        }
    }
    if (callbackHashMap_.find(callback) == callbackHashMap_.end() || callbackHashMap_.at(callback).empty()) {
        SGLOGE("not found current callback");
        return NOT_FOUND;
    }
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType == static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        int32_t ret = RemoveSubscribeMuteToSub(collectorFilter, config, sdkFlag);
        if (ret != SUCCESS) {
            SGLOGE("RemoveSubscribeMuteToSub failed, ret=%{public}d", ret);
            return ret;
        }
    } else {
        if (eventFilter_ == nullptr) {
            SGLOGE("eventFilter_ is null");
            return NULL_OBJECT;
        }
        int32_t ret = eventFilter_()->RemoveEventFilter(sdkFlag, collectorFilter);
        if (ret != SUCCESS) {
            SGLOGE("RemoveEventFilter failed, ret=%{public}d", ret);
            return ret;
        }
    }
    auto iter = callbackHashMap_.at(callback).begin();
    iter = callbackHashMap_.at(callback).erase(iter);
    if (callbackHashMap_.at(callback).empty()) {
        callbackHashMap_.erase(callback);
    }
    return SUCCESS;
}

SecurityCollector::SecurityCollectorEventMuteFilter AcquireDataSubscribeManager::ConvertFilter(
    const SecurityGuard::EventMuteFilter &sgFilter)
{
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = sgFilter.type;
    collectorFilter.isInclude = sgFilter.isInclude;
    collectorFilter.isSetMute = false;
    collectorFilter.instanceFlag = sgFilter.instanceFlag;
    return collectorFilter;
}
}
