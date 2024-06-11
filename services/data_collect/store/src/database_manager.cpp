/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "database_manager.h"

#include "config_data_manager.h"
#include "risk_event_rdb_helper.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "store_define.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "security_guard_utils.h"
#include "bigdata.h"
#include "task_handler.h"

namespace OHOS::Security::SecurityGuard {
DatabaseManager &DatabaseManager::GetInstance()
{
    static DatabaseManager instance;
    return instance;
}

void DatabaseManager::Init()
{
    // init database
    int32_t ret = RiskEventRdbHelper::GetInstance().Init();
    SGLOGI("risk event rdb init result is %{public}d", ret);
}

int DatabaseManager::InsertEvent(uint32_t source, SecEvent& event)
{
    EventCfg config;
    bool success = ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config);
    if (!success) {
        SGLOGE("not found event, id=%{public}" PRId64 "", event.eventId);
        return NOT_FOUND;
    }

    if (config.source == source) {
        std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(event.eventId);
        SGLOGD("table=%{public}s, eventId=%{public}" PRId64 "", table.c_str(), config.eventId);
        if (table == AUDIT_TABLE) {
            SGLOGD("audit event insert");
            DbChanged(IDbListener::INSERT, event);
            return SUCCESS;
        }
        SGLOGD("risk event insert, eventId=%{public}" PRId64 "", event.eventId);
        // Check whether the upper limit is reached.
        int64_t count = RiskEventRdbHelper::GetInstance().CountEventByEventId(event.eventId);
        if (count >= config.storageRomNums) {
            (void) RiskEventRdbHelper::GetInstance().DeleteOldEventByEventId(event.eventId,
                count + 1 - config.storageRomNums);
        }
        DbChanged(IDbListener::INSERT, event);
        return RiskEventRdbHelper::GetInstance().InsertEvent(event);
    }

    // notify changed
    DbChanged(IDbListener::INSERT, event);
    return SUCCESS;
}

int DatabaseManager::QueryAllEvent(std::string table, std::vector<SecEvent> &events)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryAllEvent(events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryRecentEventByEventId(std::string table, const std::vector<int64_t> &eventId,
    std::vector<SecEvent> &event)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventIdAndDate(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events, std::string beginTime, std::string endTime)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventIdAndDate(eventIds, events, beginTime, endTime);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventId(eventId, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventId(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventId(eventIds, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventType(std::string table, int32_t eventType, std::vector<SecEvent> &events)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventType(eventType, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByLevel(std::string table, int32_t level, std::vector<SecEvent> &events)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByLevel(level, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByOwner(std::string table, std::string owner, std::vector<SecEvent> &events)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByOwner(owner, events);
    }
    return NOT_SUPPORT;
}

int64_t DatabaseManager::CountAllEvent(std::string table)
{
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().CountAllEvent();
    }
    return 0;
}

int64_t DatabaseManager::CountEventByEventId(int64_t eventId)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().CountEventByEventId(eventId);
    }
    return 0;
}

int DatabaseManager::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().DeleteOldEventByEventId(eventId, count);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::DeleteAllEventByEventId(int64_t eventId)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().DeleteAllEventByEventId(eventId);
    }
    return NOT_SUPPORT;
}

int32_t DatabaseManager::SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    if (listener == nullptr) {
        SGLOGE("listener is nullptr");
        return NULL_OBJECT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (int64_t eventId : eventIds) {
        SGLOGI("SubscribeDb EVENTID %{public}" PRId64 "", eventId);
        listenerMap_[eventId].insert(listener);
    }
    return SUCCESS;
}

int32_t DatabaseManager::UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    if (listener == nullptr) {
        return NULL_OBJECT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (int64_t eventId : eventIds) {
        listenerMap_[eventId].erase(listener);
        SGLOGI("size=%{public}u", static_cast<int32_t>(listenerMap_[eventId].size()));
        if (listenerMap_[eventId].size() == 0) {
            listenerMap_.erase(eventId);
        }
    }
    return SUCCESS;
}

void DatabaseManager::DbChanged(int32_t optType, const SecEvent &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::shared_ptr<IDbListener>> listeners = listenerMap_[event.eventId];
    if (listeners.empty()) {
        return;
    }
    SGLOGI("eventId=%{public}" PRId64 ", listener size=%{public}u",
        event.eventId, static_cast<int32_t>(listeners.size()));
    SecurityGuard::TaskHandler::Task task = [listeners, optType, event] () {
        for (auto &listener : listeners) {
            if (listener != nullptr) {
                listener->OnChange(optType, event);
            }
        }
    };
    SecurityGuard::TaskHandler::GetInstance()->AddTask(task);
    return;
}
} // namespace OHOS::Security::SecurityGuard