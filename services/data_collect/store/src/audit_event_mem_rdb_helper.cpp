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

#include "audit_event_mem_rdb_helper.h"

#include "rdb_predicates.h"

#include "audit_event_rdb_helper.h"
#include "config_data_manager.h"
#include "config_define.h"
#include "rdb_event_store_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr uint32_t FLUSH_INTERVAL = 60 * 1000;
    constexpr uint32_t DELETE_INTERVAL = 10000; // 1 hour
}

DatabaseHelper &AuditEventMemRdbHelper::GetInstance()
{
    static AuditEventMemRdbHelper auditMemInstance;
    static DatabaseHelper &instance = auditMemInstance;
    return instance;
}

AuditEventMemRdbHelper::AuditEventMemRdbHelper() : DatabaseHelper("audit_event_mem")
{
    dbPath_ = FOLDER_PATH + "audit_event_mem.db";
}

AuditEventMemRdbHelper::~AuditEventMemRdbHelper()
{
    Release();
}

int AuditEventMemRdbHelper::Init()
{
    int errCode = NativeRdb::E_ERROR;
    NativeRdb::RdbStoreConfig config(dbPath_);
    config.SetStorageMode(NativeRdb::StorageMode::MODE_MEMORY);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S2);
    std::string table = CreateTable();
    std::vector<std::string> createTableVec;
    createTableVec.push_back(table);
    RdbEventStoreCallback callback(createTableVec);
    CreateRdbStore(config, DB_VERSION, callback, errCode);
    if (errCode != NativeRdb::E_OK) {
        SGLOGE("create rdb store error, code=%{public}d", errCode);
        return errCode;
    }
    errCode = Attach("audit_event_attach", FOLDER_PATH + "audit_event.db", {});
    if (errCode != NativeRdb::E_OK) {
        SGLOGE("attach audit_event error, code=%{public}d", errCode);
        return errCode;
    }

    timer_.Setup();
    timerId_ = timer_.Register([this] { this->FlushAllEvent(); }, FLUSH_INTERVAL);
    return errCode;
}

void AuditEventMemRdbHelper::Release()
{
    if (timerId_ != 0) {
        timer_.Unregister(timerId_);
    }
    timer_.Shutdown();
    (void)FlushAllEvent();
}

int AuditEventMemRdbHelper::QueryAllEvent(std::vector<SecEvent> &events)
{
    NativeRdb::RdbPredicates predicates(AUDIT_TABLE);
    int ret = QueryEventBase(predicates, events);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to query event, table=%{public}s, ret=%{public}d", AUDIT_TABLE, ret);
        return DB_OPT_ERR;
    }

    NativeRdb::RdbPredicates predicates2(dbTable_);
    ret = QueryEventBase(predicates, events);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to query event, table=%{public}s, ret=%{public}d", dbTable_.c_str(), ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int AuditEventMemRdbHelper::QueryAllEventFromMem(std::vector<SecEvent> &events)
{
    return DatabaseHelper::QueryAllEvent(events);
}

int AuditEventMemRdbHelper::QueryEventFromMemByDate(std::vector<SecEvent> &events, std::string date)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.LessThan(DATE, date);
    std::vector<std::string> columns { EVENT_ID, VERSION, DATE, CONTENT, USER_ID, DEVICE_ID };
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
        SecEvent event;
        resultSet->GetLong(table.eventIdIndex, event.eventId);
        resultSet->GetString(table.versionIndex, event.version);
        resultSet->GetString(table.dateIndex, event.date);
        resultSet->GetString(table.contentIndex, event.content);
        resultSet->GetInt(table.userIdIndex, event.userId);
        resultSet->GetString(table.deviceIdIndex, event.deviceId);
        events.emplace_back(event);
    }
    resultSet->Close();
    return SUCCESS;
}

void AuditEventMemRdbHelper::DeleteRedundantData(const std::unordered_map<int64_t, int64_t> &countMap)
{
    for (const auto &entry : countMap) {
        EventCfg config;
        (void) ConfigDataManager::GetInstance().GetEventConfig(entry.first, config);
        int64_t count = AuditEventRdbHelper::GetInstance().CountEventByEventId(entry.first);
        if (count + entry.second >= config.storageRomNums) {
            (void) AuditEventRdbHelper::GetInstance().DeleteOldEventByEventId(entry.first,
                count + entry.second - config.storageRomNums);
        }
    }
}

int AuditEventMemRdbHelper::DeleteFlushDataFromMem(std::string date)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.LessThan(DATE, date);
    int32_t deleteRows;
    int ret = Delete(deleteRows, predicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to delete event, ret=%{public}d", ret);
    }
    return ret;
}

int AuditEventMemRdbHelper::DeleteExpiredDataFromMain(std::string date)
{
    NativeRdb::RdbPredicates predicateDel(AUDIT_TABLE);
    int64_t time;
    SecurityGuardUtils::StrToI64(date, time);
    time -= DELETE_INTERVAL;
    predicateDel.LessThan(DATE, std::to_string(time));
    int32_t deleteRows;
    int ret = Delete(deleteRows, predicateDel);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to delete event, ret=%{public}d", ret);
    }
    return ret;
}

int AuditEventMemRdbHelper::FlushAllEvent()
{
    SGLOGD("begin flush event from mem to file");
    std::vector<SecEvent> events;
    std::string date = SecurityGuardUtils::GetDate();
    int ret = QueryEventFromMemByDate(events, date);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to query event, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }
    std::vector<NativeRdb::ValuesBucket> values;
    std::unordered_map<int64_t, int64_t> countMap;
    SGLOGD("flush event size is %{public}d", static_cast<int>(events.size()));
    for (const SecEvent &event : events) {
        countMap[event.eventId]++;
        NativeRdb::ValuesBucket value;
        SetValuesBucket(event, value);
        values.emplace_back(value);
    }

    DeleteRedundantData(countMap);
    countMap.clear();

    int64_t rowId;
    ret = BatchInsert(rowId, AUDIT_TABLE, values);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to batch insert event, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }

    ret = DeleteFlushDataFromMem(date);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to delete flush event, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }

    ret = DeleteExpiredDataFromMain(date);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to delete expired event, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard