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
#include "device_manager.h"
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
    constexpr const char *PKG_NAME = "ohos.security.securityguard";
}

class InitCallback : public DistributedHardware::DmInitCallback {
public:
    ~InitCallback() override = default;
    void OnRemoteDied() override {};
};


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
    wrapperHandle_ = dlopen(SECURITY_GUARD_EVENT_WRAPPER_PATH, RTLD_LAZY);
    if (wrapperHandle_ != nullptr) {
        eventWrapper_ = reinterpret_cast<GetEventWrapperFunc>(dlsym(wrapperHandle_, "GetEventWrapper"));
    }
    if (eventFilter_ == nullptr) {
        SGLOGI("eventFilter_ is nullptr");
    }
    if (eventWrapper_ == nullptr) {
        SGLOGI("eventWrapper_ is nullptr");
    }
}

AcquireDataSubscribeManager::~AcquireDataSubscribeManager()
{
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    if (wrapperHandle_ != nullptr) {
        dlclose(wrapperHandle_);
        wrapperHandle_ = nullptr;
    }
}

int AcquireDataSubscribeManager::InsertSubscribeRecord(int64_t eventId, const std::string &clientId)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AcquireDataSubscribeManager::GetInstance().InitUserId();
    AcquireDataSubscribeManager::GetInstance().InitDeviceId();
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGI("not find current clientId");
        return BAD_PARAM;
    }
    if (sessionsMap_.at(clientId)->subEvents.find(eventId) != sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGE("not need subscribe again");
        return SUCCESS;
    }
    int32_t code = SubscribeSc(eventId);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
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

int AcquireDataSubscribeManager::InsertSubscribeRecord(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int64_t eventId = subscribeInfo.GetEvent().eventId;
    AcquireDataSubscribeManager::GetInstance().InitUserId();
    AcquireDataSubscribeManager::GetInstance().InitDeviceId();
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) != sessionsMap_.end() && sessionsMap_.at(clientId) != nullptr &&
        sessionsMap_.at(clientId)->subEvents.find(eventId) != sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGE("not need subscribe again");
        return SUCCESS;
    }
    int32_t code = SubscribeSc(eventId);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
    }
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        auto session = std::make_shared<ClientSession>();
        session->clientId = clientId;
        session->callback = callback;
        session->tokenId = callerToken;
        session->eventGroup = subscribeInfo.GetEventGroup();
        sessionsMap_[clientId] = session;
    }
    sessionsMap_[clientId]->subEvents.insert(eventId);
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGI("not find current clientId");
        return SUCCESS;
    }
    if (sessionsMap_.at(clientId)->subEvents.find(eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGI("not find current eventid");
        return SUCCESS;
    }
    sessionsMap_.at(clientId)->subEvents.erase(eventId);
    bool isFind = false;
    for (const auto &iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->subEvents.find(eventId) != iter.second->subEvents.end()) {
            isFind = true;
            break;
        }
    }
    if (!isFind) {
        int ret = UnSubscribeSc(eventId);
        if (ret != SUCCESS) {
            SGLOGE("UnSubscribeSc fail");
            sessionsMap_.at(clientId)->subEvents.insert(eventId);
            return ret;
        }
    }
    if (sessionsMap_.at(clientId)->subEvents.empty()) {
        sessionsMap_.erase(clientId);
    }
    return SUCCESS;
}
// LCOV_EXCL_START
int AcquireDataSubscribeManager::InsertMute(const EventMuteFilter &filter, const std::string &clientId)
{
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (eventFilter_ == nullptr) {
        SGLOGE("eventFilter_ is null");
        return NULL_OBJECT;
    }
    int ret = eventFilter_()->SetEventFilter(collectorFilter);
    if (ret != SUCCESS) {
        SGLOGE("SetEventFilter failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSg(int64_t eventId)
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

int AcquireDataSubscribeManager::SubscribeScInSc(int64_t eventId)
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
        return SubscribeScInSg(eventId);
    }
    // 订阅SC
    return SubscribeScInSc(eventId);
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
// LCOV_EXCL_STOP
int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGI("not find current clientId");
        return BAD_PARAM;
    }
    if (sessionsMap_.at(clientId)->subEvents.find(eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
        SGLOGI("not find current eventid");
        return BAD_PARAM;
    }
    sessionsMap_.at(clientId)->subEvents.erase(eventId);
    bool isFind = false;
    for (const auto &iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->subEvents.find(eventId) != iter.second->subEvents.end()) {
            isFind = true;
            break;
        }
    }
    if (!isFind) {
        int ret = UnSubscribeSc(eventId);
        if (ret != SUCCESS) {
            SGLOGE("UnSubscribeSc fail");
            sessionsMap_.at(clientId)->subEvents.insert(eventId);
            return ret;
        }
    }
    return SUCCESS;
}
// LCOV_EXCL_START
void AcquireDataSubscribeManager::RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    std::set<int64_t> allSubEventId {};
    std::set<int64_t> currentEventId {};
    auto finder = [callback](std::pair<std::string, std::shared_ptr<ClientSession>> iter) {
        return callback == iter.second->callback;
    };
    auto iter = find_if(sessionsMap_.begin(), sessionsMap_.end(), finder);
    if (iter != sessionsMap_.end()) {
        currentEventId = iter->second->subEvents;
        if (eventFilter_ != nullptr) {
            eventFilter_()->RemoveSdkAllEventFilter(iter->first);
        }
        sessionsMap_.erase(iter);
    }
    for (const auto &iter : sessionsMap_) {
        for (const auto &it : iter.second->subEvents) {
            allSubEventId.insert(it);
        }
    }
    for (const auto &iter : currentEventId) {
        // no one subscribed id
        if (allSubEventId.find(iter) == allSubEventId.end()) {
            (void)UnSubscribeSc(iter);
        }
    }
}

void AcquireDataSubscribeManager::StartClearEventCache()
{
    auto task = [this]() {
        while (true) {
            this->ClearEventCache();
            {
                std::lock_guard<ffrt::mutex> lock(clearCachemutex_);
                if (isStopClearCache_ == true) {
                    break;
                }
            }
            ffrt::this_task::sleep_for(std::chrono::milliseconds(MAX_DURATION_TEN_SECOND));
        }
    };
    ffrt::submit(task);
}

sptr<IRemoteObject> AcquireDataSubscribeManager::GetCurrentClientCallback(const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return nullptr;
    }
    auto session = sessionsMap_.at(clientId);
    if (session == nullptr) {
        return nullptr;
    }
    return sessionsMap_.at(clientId)->callback;
}

std::string AcquireDataSubscribeManager::GetCurrentClientGroup(const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return "";
    }
    auto session = sessionsMap_.at(clientId);
    if (session == nullptr) {
        return "";
    }
    return sessionsMap_.at(clientId)->eventGroup;
}

void AcquireDataSubscribeManager::StopClearEventCache()
{
    std::lock_guard<ffrt::mutex> lock(clearCachemutex_);
    isStopClearCache_ = true;
}

void AcquireDataSubscribeManager::InitUserId()
{
    int32_t id = -1;
    int32_t code = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (code != ERR_OK) {
        SGLOGE("GetForegroundOsAccountLocalId Fail");
        return;
    }
    std::lock_guard<std::mutex> lock(userIdMutex_);
    userId_ = id;
}

void AcquireDataSubscribeManager::InitDeviceId()
{
    auto callback = std::make_shared<InitCallback>();
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, callback);
    if (ret != SUCCESS) {
        SGLOGI("init device manager failed, result is %{public}d", ret);
        return;
    }
    DistributedHardware::DmDeviceInfo deviceInfo;
    ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, deviceInfo);
    if (ret != SUCCESS) {
        SGLOGI("get local device into error, code=%{public}d", ret);
        return;
    }
    std::lock_guard<std::mutex> lock(userIdMutex_);
    deviceId_ = deviceInfo.deviceId;
}

void AcquireDataSubscribeManager::DeInitDeviceId()
{
    int ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(PKG_NAME);
    if (ret != SUCCESS) {
        SGLOGE("UnInitDeviceManager fail, code =%{public}d", ret);
    }
}

void AcquireDataSubscribeManager::ClearEventCache()
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    SGLOGD("timer running");
    for (const auto &iter : sessionsMap_) {
        if (iter.second->callback == nullptr) {
            SGLOGW("SubscriberInfo is null");
            continue;
        }
        auto proxy = iface_cast<IAcquireDataCallback>(iter.second->callback);
        if (proxy == nullptr) {
            SGLOGE("proxy is null");
            return;
        }
        auto tmp = iter.second->events;
        if (tmp.empty()) {
            continue;
        }
        auto task = [proxy, tmp] () {
            proxy->OnNotify(tmp);
        };
        ffrt::submit(task);
        iter.second->events.clear();
        iter.second->eventsBuffSize = 0;
    }
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
    SecurityCollector::Event retEvent  = event;
    EventCfg config {};
    SecEvent secEvent {};
    {
        std::lock_guard<std::mutex> lock(userIdMutex_);
        retEvent.userId = userId_;
        retEvent.deviceId = deviceId_;
    }
    if (!ConfigDataManager::GetInstance().GetEventConfig(retEvent.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, event.eventId);
        return;
    }
    // change old event id to new eventid
    retEvent.eventId = config.eventId;
    if (eventWrapper_ != nullptr) {
        eventWrapper_()->WrapperEvent(retEvent);
    }
    if (eventFilter_ != nullptr) {
        eventFilter_()->GetFlagsEventNeedToUpload(retEvent);
    }
    // upload to subscriber
    AcquireDataSubscribeManager::GetInstance().BatchPublish(retEvent);
    secEvent.eventId = retEvent.eventId;
    secEvent.version = retEvent.version;
    secEvent.date = retEvent.timestamp;
    secEvent.content = retEvent.content;
    secEvent.userId = retEvent.userId;
    // upload to store
    auto task = [secEvent] () mutable {
        int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, secEvent, {});
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
    std::lock_guard<std::mutex> lock(sessionMutex_);
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, event.eventId);
        return false;
    }
    for (auto &it : sessionsMap_) {
        if (it.second->subEvents.find(event.eventId) == it.second->subEvents.end()) {
            continue;
        }
        if (!IsFindFlag(event.eventSubscribes, event.eventId, it.second->clientId)) {
            SGLOGW("IsFindFlag eventId=%{public}" PRId64, event.eventId);
            continue;
        }
        if (!config.isBatchUpload) {
            BatchUpload(it.second->callback, {event});
            continue;
        }
        SGLOGD("publish eventid=%{public}" PRId64, event.eventId);
        for (auto iter : event.eventSubscribes) {
            SGLOGD("publish eventSubscribes =%{public}s", iter.c_str());
        }
        it.second->events.emplace_back(event);
        it.second->eventsBuffSize += GetSecurityCollectorEventBufSize(event);
        SGLOGD("cache batch upload event to subscribe %{public}zu", it.second->eventsBuffSize);
        if (it.second->eventsBuffSize >= MAX_CACHE_EVENT_SIZE) {
            BatchUpload(it.second->callback, it.second->events);
            SGLOGI("upload events to batch subscribe, size is %{public}zu", it.second->eventsBuffSize);
            it.second->events.clear();
            it.second->eventsBuffSize = 0;
        }
    }
    return true;
}

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events,
    const std::set<std::string> &eventSubscribes)
{}

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
        return filter.eventId == it.eventId && filter.isInclude == it.isInclude &&
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
// LCOV_EXCL_STOP
int AcquireDataSubscribeManager::InsertSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    SGLOGI("in AcquireDataSubscribeManager InsertSubscribeMute, clientId %{public}s", clientId.c_str());
    std::lock_guard<std::mutex> lock(sessionMutex_);
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

int AcquireDataSubscribeManager::RemoveMute(const EventMuteFilter &filter, const std::string &clientId)
{
    EventCfg config {};
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (eventFilter_ == nullptr) {
        SGLOGE("eventFilter_ is null");
        return NULL_OBJECT;
    }
    int ret = eventFilter_()->RemoveEventFilter(collectorFilter);
    if (ret != SUCCESS) {
        SGLOGE("RemoveEventFilter failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
// LCOV_EXCL_STOP
int AcquireDataSubscribeManager::RemoveSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    SGLOGI("in AcquireDataSubscribeManager RemoveSubscribeMute, clientId %{public}s", clientId.c_str());
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGE("clientId not creat");
        return BAD_PARAM;
    }
    auto finder = [filter](const EventMuteFilter &it) {
        return filter.eventId == it.eventId && filter.isInclude == it.isInclude &&
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
// LCOV_EXCL_START
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
// LCOV_EXCL_STOP
int AcquireDataSubscribeManager::CreatClient(const std::string &eventGroup, const std::string &clientId,
    const sptr<IRemoteObject> &cb)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int ret = IsExceedLimited(clientId, callerToken);
    if (ret != SUCCESS) {
        SGLOGE("IsExceedLimited error");
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        if (sessionsMap_.find(clientId) != sessionsMap_.end()) {
            SGLOGE("current clientId exist");
            return BAD_PARAM;
        }
    }
    auto session = std::make_shared<ClientSession>();
    session->clientId = clientId;
    session->callback = cb;
    session->tokenId = callerToken;
    session->eventGroup = eventGroup;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        sessionsMap_[clientId] = session;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::DestoryClient(const std::string &eventGroup, const std::string &clientId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    auto iter = sessionsMap_.find(clientId);
    if (iter == sessionsMap_.end()) {
        SGLOGE("current clientId not exist");
        return BAD_PARAM;
    }
    for (auto iter : sessionsMap_.at(clientId)->subEvents) {
        UnSubscribeSc(iter);
    }
    for (auto iter : sessionsMap_.at(clientId)->eventFilters) {
        for (auto it : iter.second) {
            RemoveMute(it, clientId);
        }
    }
    sessionsMap_.erase(clientId);
    return SUCCESS;
}

// LCOV_EXCL_START
int AcquireDataSubscribeManager::IsExceedLimited(const std::string &clientId, AccessToken::AccessTokenID callerToken)
{
    // old subscribe api no need to count
    if (clientId.find("sdk") != std::string::npos) {
        return SUCCESS;
    }
    std::lock_guard<std::mutex> lock(sessionMutex_);
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
// LCOV_EXCL_STOP
}
