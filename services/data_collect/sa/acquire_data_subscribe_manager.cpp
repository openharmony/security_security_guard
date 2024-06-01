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

#include "acquire_data_callback_proxy.h"
#include "database_manager.h"
#include "security_guard_define.h"
#include "security_collector_subscribe_info.h"
#include "security_guard_log.h"
#include "task_handler.h"
#include "event_define.h"
#include "config_define.h"
#include "config_data_manager.h"
#include "collector_manager.h"
#include "data_collection.h"
namespace OHOS::Security::SecurityGuard {
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
    if (eventIdToSubscriberMap_.count(event)) {
        eventIdToSubscriberMap_[subscribeInfo.GetEvent().eventId].insert(callback);
        return SUCCESS;
    }
    int32_t code = DatabaseManager::GetInstance().SubscribeDb({subscribeInfo.GetEvent().eventId}, listener_);
    if (code != SUCCESS) {
        SGLOGE("SubscribeDb error");
        return code;
    }
    code = SubscribeSc(event);
    if (code != SUCCESS) {
        SGLOGE("SubscribeSc error");
        return code;
    }
    eventIdToSubscriberMap_[subscribeInfo.GetEvent().eventId].insert(callback);
    SGLOGI("insert eventIdToSubscriberMap_ size %{public}zu", eventIdToSubscriberMap_.size());
    for (auto iter : eventIdToSubscriberMap_) {
        SGLOGI("insert eventIdToSubscriberMap_.callback size %{public}zu", iter.second.size());
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
                SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64 "", eventId);
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
                SGLOGE("UnSubscribe SG failed, eventId=%{public}" PRId64 "", eventId);
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

int AcquireDataSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = eventIdToSubscriberMap_.begin(); iter != eventIdToSubscriberMap_.end();) {
        auto iterSet = iter->second.find(callback);
        if (iterSet == iter->second.end()) {
            ++iter;
            continue;
        }
        iter->second.erase(iterSet);
        if (iter->second.empty()) {
            int ret = DatabaseManager::GetInstance().UnSubscribeDb({iter->first}, listener_);
            if (ret != SUCCESS) {
                SGLOGE("UnSubscribeDb error");
                return ret;
            }
            ret = UnSubscribeSc(iter->first);
            if (ret != SUCCESS) {
                SGLOGE("UnSubscribeSc error");
                return ret;
            }
            iter = eventIdToSubscriberMap_.erase(iter);
            continue;
        }
        ++iter;
    }
    SGLOGI("remove eventIdToSubscriberMap_ size %{public}zu", eventIdToSubscriberMap_.size());
    for (auto iter : eventIdToSubscriberMap_) {
        SGLOGI("remove eventIdToSubscriberMap_.callback size %{public}zu", iter.second.size());
    }
    return SUCCESS;
}

bool AcquireDataSubscribeManager::Publish(const SecEvent &events)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = eventIdToSubscriberMap_.find(events.eventId);
    if (iter == eventIdToSubscriberMap_.end()) {
        return true;
    }
    auto listerers = iter->second;
    for (const auto &listener : listerers) {
        auto proxy = iface_cast<IAcquireDataCallback>(listener);
        if (proxy == nullptr) {
            return false;
        }
        SecurityCollector::Event event {
            .eventId = events.eventId,
            .version = events.version,
            .content = events.content,
            .timestamp = events.date
        };
        SecurityGuard::TaskHandler::Task task = [proxy, event] () {
            proxy->OnNotify(event);
        };
        if (event.eventId == SecurityCollector::FILE_EVENTID ||
            event.eventId == SecurityCollector::PROCESS_EVENTID ||
            event.eventId == SecurityCollector::NETWORK_EVENTID) {
            SecurityGuard::TaskHandler::GetInstance()->AddMinorsTask(task);
        } else {
            SecurityGuard::TaskHandler::GetInstance()->AddTask(task);
        }
    }
    return true;
}

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events)
{
    AcquireDataSubscribeManager::GetInstance().Publish(events);
}
}