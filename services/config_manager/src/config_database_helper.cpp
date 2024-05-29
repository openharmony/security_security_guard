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

#include "config_database_helper.h"
#include <vector>
#include <array>
#include "string_ex.h"
#include "config_define.h"
#include "rdb_event_store_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
ConfigDatabaseHelper::ConfigDatabaseHelper(std::string dbTable)
{
    dbTable_ = dbTable;
}

int ConfigDatabaseHelper::Init()
{
    return SUCCESS;
}

int ConfigDatabaseHelper::InsertAppInfo(const AppInfo& info)
{
    NativeRdb::ValuesBucket values {};
    SetValuesBucket(info, values);
    int64_t rowId;
    int ret = Insert(rowId, dbTable_, values);
    if (ret != NativeRdb::E_OK) {
        SGLOGI("failed to add app info, appName=%{public}s, ret=%{public}d", info.appName.c_str(), ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int ConfigDatabaseHelper::InsertAllAppInfo(const std::vector<AppInfo>& infos)
{
    SGLOGI("InsertAllAppInfo....");
    std::vector<NativeRdb::ValuesBucket> values {};
    for (auto iter : infos) {
        NativeRdb::ValuesBucket value {};
        SetValuesBucket(iter, value);
        values.emplace_back(value);
    }
    int64_t rowId;
    int ret = BatchInsert(rowId, dbTable_, values);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to batch insert event, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int ConfigDatabaseHelper::QueryAllAppInfo(std::vector<AppInfo> &infos)
{
    SGLOGI("QueryAllAppInfo....");
    NativeRdb::RdbPredicates predicates(dbTable_);
    return QueryAppInfoBase(predicates, infos);
}

int32_t ConfigDatabaseHelper::QueryAppInfoBase(const NativeRdb::RdbPredicates &predicates, std::vector<AppInfo> &infos)
{
    std::vector<std::string> columns {APP_NAME, APP_FINGERPRINT, APP_ATTRIBUTES, IS_GLOBAL_APP};
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    if (resultSet == nullptr) {
        SGLOGE("failed to get event");
        return DB_OPT_ERR;
    }
    AppInfoTableInfo table;
    int32_t ret = GetResultSetTableInfo(resultSet, table);
    if (ret != SUCCESS) {
        return ret;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AppInfo info;
        resultSet->GetString(table.appNameIndex, info.appName);
        resultSet->GetString(table.appHashIndex, info.appHash);
        std::string attrStr;
        std::vector<std::string> tmpVec;
        resultSet->GetString(table.appAttrIndex, attrStr);
        SplitStr(attrStr, ",", tmpVec);
        info.attrs = tmpVec;
        resultSet->GetInt(table.appIsGlobalAppIndex, info.isGlobalApp);
        infos.emplace_back(info);
    }
    resultSet->Close();
    return SUCCESS;
}

int32_t ConfigDatabaseHelper::GetResultSetTableInfo(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
    AppInfoTableInfo &table)
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
        if (columnName == APP_NAME) {
            table.appNameIndex = i;
        }
        if (columnName == APP_FINGERPRINT) {
            table.appHashIndex = i;
        }
        if (columnName == APP_ATTRIBUTES) {
            table.appAttrIndex = i;
        }
        if (columnName == IS_GLOBAL_APP) {
            table.appIsGlobalAppIndex = i;
        }
    }
    table.rowCount = rowCount;
    table.columnCount = columnCount;
    SGLOGD("info: row=%{public}d col=%{public}d appNameIdx=%{public}d appHashIdx=%{public}d "
        "appAttrIdx=%{public}d", rowCount, columnCount,
        table.appNameIndex, table.appHashIndex, table.appAttrIndex);
    return SUCCESS;
}

int ConfigDatabaseHelper::QueryAppInfosByName(const std::string &appName, std::vector<AppInfo> &infos)
{
    std::vector<std::string> columns {APP_NAME, APP_FINGERPRINT, APP_ATTRIBUTES, IS_GLOBAL_APP};
    NativeRdb::RdbPredicates predicates(dbTable_);
    predicates.EqualTo(APP_NAME, appName);
    predicates.OrderByDesc(ID);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get appInfo");
        return DB_OPT_ERR;
    }
    AppInfoTableInfo table;
    int32_t ret = GetResultSetTableInfo(resultSet, table);
    if (ret != SUCCESS) {
        return ret;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AppInfo info {};
        resultSet->GetString(table.appNameIndex, info.appName);
        resultSet->GetString(table.appHashIndex, info.appHash);
        std::string attrStr;
        std::vector<std::string> tmpVec;
        resultSet->GetString(table.appAttrIndex, attrStr);
        SplitStr(attrStr, ",", tmpVec);
        info.attrs = tmpVec;
        resultSet->GetInt(table.appIsGlobalAppIndex, info.isGlobalApp);
        infos.emplace_back(info);
    }
    resultSet->Close();
    return SUCCESS;
}

int ConfigDatabaseHelper::DeleteAppInfoByNameAndGlobbalFlag(const std::string &appName, int isGlobalApp)
{
    SGLOGI("DeleteAppInfoByName, appName=%{public}s", appName.c_str());
    NativeRdb::RdbPredicates queryPredicates(dbTable_);
    queryPredicates.EqualTo(APP_NAME, appName);
    queryPredicates.EqualTo(IS_GLOBAL_APP, isGlobalApp);
    queryPredicates.OrderByAsc(ID);
    std::vector<std::string> columns { ID };
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(queryPredicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get event, appName=%{public}s", appName.c_str());
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
    deletePredicates.EqualTo(APP_NAME, appName);
    deletePredicates.EqualTo(IS_GLOBAL_APP, isGlobalApp);
    int ret = Delete(rowId, deletePredicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to delete event, appName=%{public}s, ret=%{public}d", appName.c_str(), ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int ConfigDatabaseHelper::DeleteAppInfoByIsGlobalApp(int isGlobalApp)
{
    NativeRdb::RdbPredicates queryPredicates(dbTable_);
    queryPredicates.EqualTo(IS_GLOBAL_APP, isGlobalApp);
    queryPredicates.OrderByAsc(ID);
    std::vector<std::string> columns { ID };
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(queryPredicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get resultSet");
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
    deletePredicates.EqualTo(IS_GLOBAL_APP, isGlobalApp);
    int ret = Delete(rowId, deletePredicates);
    if (ret != NativeRdb::E_OK) {
        SGLOGE("failed to delete App, ret=%{public}d", ret);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}

int ConfigDatabaseHelper::QueryAppInfoByAttribute(const std::string attr, std::vector<AppInfo> &infos)
{
    NativeRdb::RdbPredicates predicates(dbTable_);
    std::vector<std::string> columns {APP_NAME, APP_FINGERPRINT, APP_ATTRIBUTES, IS_GLOBAL_APP};
    std::shared_ptr<NativeRdb::ResultSet> resultSet = Query(predicates, columns);
    if (resultSet == nullptr) {
        SGLOGI("failed to get event");
        return DB_OPT_ERR;
    }
    AppInfoTableInfo table;
    int32_t ret = GetResultSetTableInfo(resultSet, table);
    if (ret != SUCCESS) {
        return ret;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AppInfo info;
        std::string attrStr;
        std::vector<std::string> tmpVec;
        resultSet->GetString(table.appAttrIndex, attrStr);
        if (attrStr.find(attr) == std::string::npos) {
            continue;
        }
        SplitStr(attrStr, ",", tmpVec);
        info.attrs = tmpVec;
        resultSet->GetString(table.appNameIndex, info.appName);
        resultSet->GetString(table.appHashIndex, info.appHash);
        infos.emplace_back(info);
    }
    resultSet->Close();
    return SUCCESS;
}

void ConfigDatabaseHelper::SetValuesBucket(const AppInfo &event, NativeRdb::ValuesBucket &values)
{
    std::string attrStr;
    uint32_t index = 1;
    // construct attr vector to string, exp: 111,222,333
    for (auto iter : event.attrs) {
        attrStr.append(iter);
        if (index == event.attrs.size()) {
            break;
        }
        attrStr.append(",");
        index++;
    }
    values.PutString(APP_NAME, event.appName);
    values.PutString(APP_FINGERPRINT, event.appHash);
    values.PutString(APP_ATTRIBUTES, attrStr);
    values.PutInt(IS_GLOBAL_APP, event.isGlobalApp);
}

std::string ConfigDatabaseHelper::CreateTable()
{
    std::string table;
    table.append("CREATE TABLE IF NOT EXISTS ").append(dbTable_);
    table.append("(").append(ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT, ");
    table.append(APP_NAME).append(" TEXT NOT NULL, ");
    table.append(APP_FINGERPRINT).append(" TEXT NOT NULL, ");
    table.append(APP_ATTRIBUTES).append(" TEXT NOT NULL, ");
    table.append(IS_GLOBAL_APP).append(" INTEGER NOT NULL)");
    return table;
}
} // namespace OHOS::Security::SecurityGuard