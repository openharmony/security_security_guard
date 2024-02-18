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

#include "database_helper.h"

#include <array>

#include "config_define.h"
#include "rdb_event_store_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DatabaseHelper::DatabaseHelper(std::string dbTable)
{
    dbTable_ = dbTable;
}

int DatabaseHelper::Init()
{
    return SUCCESS;
}

void DatabaseHelper::Release()
{
}

int DatabaseHelper::InsertEvent(const SecEvent& event)
{
    NativeRdb::ValuesBucket values;
    SetValuesBucket(event, values);
    int64_t rowId;
    int ret = Insert(rowId, dbTable_, values);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to add event, eventId=%{public}" PRId64 ", ret=%{public}d", event.eventId, ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int DatabaseHelper::QueryAllEvent(std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryAllEventFromMem(std::vector<SecEvent> &events)
{
    return SUCCESS;
}

int DatabaseHelper::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    std::vector<std::string> columns { EVENT_ID, VERSION, DATE, CONTENT };
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(EVENT_ID, std::to_string(eventId));
    predicates.OrderByDesc(ID);
    predicates.Limit(1);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get event");
        return DB_OPT_ERR;
    }
    SecEventTableInfo table;
    int32_t ret = GetResultSetTableInfo(resultSet, table);
    if (ret != SUCCESS) {
        return ret;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetLong(table.eventIdIndex, event.eventId);
        resultSet->GetString(table.versionIndex, event.version);
        resultSet->GetString(table.dateIndex, event.date);
        resultSet->GetString(table.contentIndex, event.content);
    }
    resultSet->Close();
    return SUCCESS;
}

int DatabaseHelper::QueryRecentEventByEventId(const std::vector<int64_t> &eventIds, std::vector<SecEvent> &events)
{
    int size = static_cast<int>(eventIds.size());
    if (size == 0) {
        return BAD_PARAM;
    }
    for (int i = 0; i < size; i++) {
        SGLOGI("eventId=%{public}" PRId64 "", eventIds[i]);
        NativeRdb::RdbPredicates predicates(dbTable_);
        predicates.EqualTo(EVENT_ID, std::to_string(eventIds[i]));
        predicates.OrderByDesc(ID);
        predicates.Limit(1);
        int ret = QueryEventBase(predicates, events);
        if (ret != SUCCESS) {
            return ret;
        }
    }
    return SUCCESS;
}

int DatabaseHelper::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(EVENT_ID, std::to_string(eventId));
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events)
{
    int size = static_cast<int>(eventIds.size());
    if (size == 0) {
        return BAD_PARAM;
    }
    NativeRdb::RdbPredicates predicates(dbTable_);
    for (int i = 0; i < size; i++) {
        if (i > 0) {
            predicates.Or();
        }
        predicates.EqualTo(EVENT_ID, std::to_string(eventIds[i]));
    }
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryEventByEventIdAndDate(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
    std::string beginTime, std::string endTime)
{
    int size = static_cast<int>(eventIds.size());
    if (size == 0) {
        return BAD_PARAM;
    }
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.BeginWrap();
    for (int i = 0; i < size; i++) {
        if (i > 0) {
            predicates.Or();
        }
        predicates.EqualTo(EVENT_ID, std::to_string(eventIds[i]));
    }
    predicates.EndWrap();
    if (!beginTime.empty()) {
        predicates.And();
        predicates.GreaterThanOrEqualTo(DATE, beginTime);
    }
    if (!endTime.empty()) {
        predicates.And();
        predicates.LessThan(DATE, endTime);
    }
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(EVENT_TYPE, std::to_string(eventType));
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryEventByLevel(int32_t level, std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(DATA_SENSITIVITY_LEVEL, std::to_string(level));
    return QueryEventBase(predicates, events);
}

int DatabaseHelper::QueryEventByOwner(std::string owner, std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.Contains(OWNER, owner);
    return QueryEventBase(predicates, events);
}

int64_t DatabaseHelper::CountAllEvent()
{
    int64_t count;
    NativeRdb::RdbPredicates predicates(dbTable_);
    int ret = Count(count, predicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to count event, ret=%{public}d", ret);
    }
    return count;
}

int64_t DatabaseHelper::CountEventByEventId(int64_t eventId)
{
    int64_t count;
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(EVENT_ID, std::to_string(eventId));
    int ret = Count(count, predicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to count event, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
    }
    return count;
}

int DatabaseHelper::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    NativeRdb::RdbPredicates queryPredicates(dbTable_);
    queryPredicates.EqualTo(EVENT_ID, std::to_string(eventId));
    queryPredicates.OrderByAsc(ID);
    queryPredicates.Limit(count);
    std::vector<std::string> columns { ID };
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(queryPredicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get event, eventId=%{public}" PRId64 "", eventId);
        return DB_OPT_ERR;
    }
    int64_t primaryKey = -1;
    std::vector<std::string> primaryKeyVec;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetLong(0, primaryKey);
        primaryKeyVec.emplace_back(std::to_string(primaryKey));
    }
    resultSet->Close();
    int rowId;
    NativeRdb::RdbPredicates deletePredicates(dbTable_);
    deletePredicates.In(ID, primaryKeyVec);
    deletePredicates.EqualTo(EVENT_ID, std::to_string(eventId));
    int ret = Delete(rowId, deletePredicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to delete event, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int DatabaseHelper::DeleteAllEventByEventId(int64_t eventId)
{
    int rowId;
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(EVENT_ID, std::to_string(eventId));
    int ret = Delete(rowId, predicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to delete event, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int DatabaseHelper::FlushAllEvent()
{
    return SUCCESS;
}

int DatabaseHelper::QueryEventBase(const NativeRdb::RdbPredicates &predicates, std::vector<SecEvent> &events)
{
    std::vector<std::string> columns { EVENT_ID, VERSION, DATE, CONTENT, USER_ID, DEVICE_ID };
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get event");
        return DB_OPT_ERR;
    }
    SecEventTableInfo table;
    table.userIdIndex = INVALID_INDEX;
    table.deviceIdIndex = INVALID_INDEX;
    int32_t ret = GetResultSetTableInfo(resultSet, table);
    if (ret != SUCCESS) {
        return ret;
    }
    SecEvent event;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetLong(table.eventIdIndex, event.eventId);
        resultSet->GetString(table.versionIndex, event.version);
        resultSet->GetString(table.dateIndex, event.date);
        resultSet->GetString(table.contentIndex, event.content);
        if (table.deviceIdIndex != INVALID_INDEX) {
            resultSet->GetString(table.deviceIdIndex, event.deviceId);
        }
        if (table.userIdIndex != INVALID_INDEX) {
            resultSet->GetInt(table.userIdIndex, event.userId);
        }
        events.emplace_back(event);
    }
    resultSet->Close();
    return SUCCESS;
}

int32_t DatabaseHelper::GetResultSetTableInfo(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    SecEventTableInfo &table)
{
    int32_t rowCount = 0;
    int32_t columnCount = 0;
    std::vector<std::string> columnNames;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK ||
        resultSet->GetColumnCount(columnCount) != NativeRdb::E_OK ||
        resultSet->GetAllColumnNames(columnNames) != NativeRdb::E_OK) {
        SGLOGE("get table info failed");
        return DB_LOAD_ERR;
    }
    int32_t columnNamesCount = static_cast<int32_t>(columnNames.size());
    for (int32_t i = 0; i < columnNamesCount; i++) {
        std::string columnName = columnNames.at(i);
        if (columnName == ID) {
            table.primaryKeyIndex = i;
        }
        if (columnName == EVENT_ID) {
            table.eventIdIndex = i;
        }
        if (columnName == VERSION) {
            table.versionIndex = i;
        }
        if (columnName == DATE) {
            table.dateIndex = i;
        }
        if (columnName == CONTENT) {
            table.contentIndex = i;
        }
        if (columnName == USER_ID) {
            table.userIdIndex = i;
        }
        if (columnName == DEVICE_ID) {
            table.deviceIdIndex = i;
        }
    }
    table.rowCount = rowCount;
    table.columnCount = columnCount;
    SGLOGD("info: row=%{public}d col=%{public}d eventIdIdx=%{public}d versionIdx=%{public}d "
        "dateIdx=%{public}d contentIdx=%{public}d", rowCount, columnCount,
        table.eventIdIndex, table.versionIndex, table.dateIndex, table.contentIndex);
    return SUCCESS;
}

void DatabaseHelper::SetValuesBucket(const SecEvent &event, NativeRdb::ValuesBucket &values)
{
    values.PutLong(EVENT_ID, event.eventId);
    values.PutString(VERSION, event.version);
    values.PutString(DATE, event.date);
    values.PutString(CONTENT, event.content);
    values.PutInt(EVENT_TYPE, event.eventType);
    values.PutInt(DATA_SENSITIVITY_LEVEL, event.dataSensitivityLevel);
    values.PutString(OWNER, event.owner);
    values.PutInt(USER_ID, event.userId);
    values.PutString(DEVICE_ID, event.deviceId);
}

std::string DatabaseHelper::CreateTable()
{
    std::string table;
    table.append("CREATE TABLE IF NOT EXISTS ").append(dbTable_);
    table.append("(").append(ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT, ");
    table.append(EVENT_ID).append(" INTEGER NOT NULL, ");
    table.append(VERSION).append(" TEXT NOT NULL, ");
    table.append(DATE).append(" TEXT NOT NULL, ");
    table.append(CONTENT).append(" TEXT NOT NULL, ");
    table.append(EVENT_TYPE).append(" INTEGER NOT NULL, ");
    table.append(DATA_SENSITIVITY_LEVEL).append(" INTEGER NOT NULL, ");
    table.append(OWNER).append(" TEXT NOT NULL, ");
    table.append(USER_ID).append(" INTEGER NOT NULL, ");
    table.append(DEVICE_ID).append(" TEXT NOT NULL)");
    return table;
}
} // namespace OHOS::Security::SecurityGuard