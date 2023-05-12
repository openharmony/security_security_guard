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

#include "db_operate.h"
#include "database_manager.h"

namespace OHOS::Security::SecurityGuard {
DbOperate::DbOperate(std::string table) : table_(table) {}

int DbOperate::InsertEvent(SecEvent& event)
{
    return DatabaseManager::GetInstance().InsertEvent(MODEL_SOURCE, event);
}

int DbOperate::QueryAllEvent(std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryAllEvent(table_, events);
}

int DbOperate::QueryAllEventFromMem(std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryAllEventFromMem(events);
}

int DbOperate::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    return DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, event);
}

int DbOperate::QueryRecentEventByEventId(const std::vector<int64_t> &eventId, std::vector<SecEvent> &event)
{
    return DatabaseManager::GetInstance().QueryRecentEventByEventId(table_, eventId, event);
}

int DbOperate::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryEventByEventId(eventId, events);
}

int DbOperate::QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryEventByEventId(table_, eventIds, events);
}

int DbOperate::QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryEventByEventType(table_, eventType, events);
}

int DbOperate::QueryEventByLevel(int32_t level, std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryEventByLevel(table_, level, events);
}

int DbOperate::QueryEventByOwner(std::string owner, std::vector<SecEvent> &events)
{
    return DatabaseManager::GetInstance().QueryEventByOwner(table_, owner, events);
}

int64_t DbOperate::CountAllEvent()
{
    return DatabaseManager::GetInstance().CountAllEvent(table_);
}

int64_t DbOperate::CountEventByEventId(int64_t eventId)
{
    return DatabaseManager::GetInstance().CountEventByEventId(eventId);
}

int DbOperate::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    return DatabaseManager::GetInstance().DeleteOldEventByEventId(eventId, count);
}

int DbOperate::DeleteAllEventByEventId(int64_t eventId)
{
    return DatabaseManager::GetInstance().DeleteAllEventByEventId(eventId);
}
} // namespace OHOS::Security::SecurityGuard