/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <cinttypes>
#include "config_data_manager.h"
#include "file_system_store_helper.h"
#include "risk_event_rdb_helper.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "store_define.h"
#include "security_guard_utils.h"
#include "bigdata.h"
#include "ffrt.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr uint32_t SENSITIVITY_INFO = 2;
}
DatabaseManager &DatabaseManager::GetInstance()
{
    static DatabaseManager instance;
    return instance;
}

void DatabaseManager::Init()
{
}

int DatabaseManager::InsertEvent(uint32_t source, const SecEvent& event,
    const std::set<std::string> &eventSubscribes)
{
    return SUCCESS;
}

int DatabaseManager::InsertEvent(uint32_t source, const std::vector<SecEvent>& events,
    const std::set<std::string> &eventSubscribes)
{
    return SUCCESS;
}

int DatabaseManager::QueryAllEvent(std::string table, std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseManager::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    return SUCCESS;
}

int DatabaseManager::QueryRecentEventByEventId(std::string table, const std::vector<int64_t> &eventId,
    std::vector<SecEvent> &event)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByEventIdAndDate(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events, std::string beginTime, std::string endTime)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByEventId(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByEventType(std::string table, int32_t eventType, std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByLevel(std::string table, int32_t level, std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseManager::QueryEventByOwner(std::string table, std::string owner, std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int64_t DatabaseManager::CountAllEvent(std::string table)
{
    return 0;
}

int64_t DatabaseManager::CountEventByEventId(int64_t eventId)
{
    return 0;
}

int DatabaseManager::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    return SUCCESS;
}

int DatabaseManager::DeleteAllEventByEventId(int64_t eventId)
{
    return SUCCESS;
}

int32_t DatabaseManager::SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    return SUCCESS;
}

int32_t DatabaseManager::UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    return SUCCESS;
}

void DatabaseManager::DbChanged(int32_t optType, const SecEvent &event, const std::set<std::string> &eventSubscribes)
{
    return;
}
} // namespace OHOS::Security::SecurityGuard