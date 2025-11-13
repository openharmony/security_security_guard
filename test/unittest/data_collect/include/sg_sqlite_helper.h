/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SG_SQLITE_HELPER_H
#define SG_SQLITE_HELPER_H

#include "sqlite_helper.h"
#include "generic_values.h"
#include <vector>
#include <memory>
#include "rwlock.h"

namespace OHOS::Security::SecurityGuard {
class SgSqliteHelper : public SqliteHelper {
public:
    explicit SgSqliteHelper(const std::string &dbName, const std::string &dbPath, int version,
                        const std::vector<std::string> &createSqls);
    int Insert(int64_t &outRowId, const std::string &table, const GenericValues &values);
    int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<GenericValues> &initialBatchValues);
    int Update(int &changedRows, const std::string &table, const GenericValues &value);
    int Delete(int &deletedRows, const std::string &table, const GenericValues &conditions = {});
    int Query(const std::string &table, const GenericValues &conditions, std::vector<GenericValues> &results,
        const QueryOptions &options = {});
    int ExecuteSql(const std::string &sql);
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<std::string> &bindArgs);
    int Count(int64_t &outValue, const std::string &table,  const GenericValues &conditions = {},
         const QueryOptions &options = {});
    int Attach(const std::string &alias, const std::string &pathName,
        const std::vector<uint8_t> destEncryptKey);
    void OnCreate() override;
    void OnUpdate() override;

private:
    bool EndWith(const std::string &str, const std::string &suffix) const;
    GenericValues ExecuteRowData(Statement &stmt);
    std::vector<std::string> Split(const std::string &s, char delimiter);
    std::string Join(const std::vector<std::string> &items, const std::string &delimiter);

    std::string BuildInPlaceholders(const std::string& key, const std::string& values);
    std::string BuildSelectSql(const std::string &table, const GenericValues &conditions,
        const QueryOptions &options);
    std::string BuildInsertSql(const std::string &table, const GenericValues &values);
    std::string BuildUpdateSql(const std::string &table, const GenericValues &values,
        const std::string &where);
    std::string BuildWhereClause(const GenericValues &conditions);

    Statement PrepareCountStmt(const std::string &table, const GenericValues &conditions,
        const QueryOptions &options);
    Statement PrepareDeleteStmt(const std::string &table, const GenericValues &conditions);
    Statement PrepareBoundStateStmt(const std::string &sql, const GenericValues &conditions);

    std::vector<std::string> createSqls_;
    OHOS::Utils::RWLock rwLock_;
};

} // OHOS::Security::SecurityGuard
#endif
