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

#include "sqlite_helper.h"
#include <sys/types.h>
#include "sqlite3ext.h"
#include "security_guard_log.h"
// LCOV_EXCL_START
namespace OHOS {
namespace Security::SecurityGuard {

SqliteHelper::SqliteHelper(const std::string &dbName, const std::string &dbPath, int32_t version)
    : dbName_(dbName), dbPath_(dbPath), currentVersion_(version), db_(nullptr)
{}

SqliteHelper::~SqliteHelper()
{}

void SqliteHelper::Open() __attribute__ ((no_sanitize("cfi")))
{
    if (db_ != nullptr) {
        SGLOGW("db s already open");
        return;
    }
    if (dbName_.empty() || dbPath_.empty() || currentVersion_ < 0) {
        SGLOGE("param invalid, dbName: %{public}s, "
            "dbPath: %{public}s, currentVersion: %{public}d",
            dbName_.c_str(), dbPath_.c_str(), currentVersion_);
        return;
    }
    constexpr int32_t heapLimit = 10 * 1024;
    sqlite3_soft_heap_limit64(heapLimit);
#ifdef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    constexpr int32_t pageSize = 1024;
    constexpr int32_t pageNum = 20;
    sqlite3_config(SQLITE_CONFIG_PAGECACHE, NULL, pageSize, pageNum);
    sqlite3_config(SQLITE_CONFIG_SMALL_MALLOC, 1);
#endif
    std::string fileName = dbPath_ + dbName_;
    int32_t res = sqlite3_open(fileName.c_str(), &db_);
    if (res != SQLITE_OK) {
        SGLOGE("Failed to open db: %{public}s", sqlite3_errmsg(db_));
        return;
    }

    int32_t version = GetVersion();
    if (version == currentVersion_) {
        return;
    }

    BeginTransaction();
    if (version == 0) {
        OnCreate();
    } else {
        if (version < currentVersion_) {
            OnUpdate();
        }
    }
    SetVersion();
    CommitTransaction();
}

void SqliteHelper::Close()
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return;
    }
    int32_t ret = sqlite3_close(db_);
    if (ret != SQLITE_OK) {
        SGLOGW("sqlite3_close error, ret=%{public}d", ret);
        return;
    }
    db_ = nullptr;
}

int32_t SqliteHelper::BeginTransaction() const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t ret = sqlite3_exec(db_, "BEGIN;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        SGLOGE("failed, errorMsg: %{public}s", errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

int32_t SqliteHelper::CommitTransaction() const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t ret = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        SGLOGE("failed, errorMsg: %{public}s", errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    sqlite3_db_cacheflush(db_);
    return result;
}

int32_t SqliteHelper::RollbackTransaction() const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return GENERAL_ERROR;
    }
    int32_t result = 0;
    char* errorMessage = nullptr;
    int32_t ret = sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        SGLOGE("failed, errorMsg: %{public}s", errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

Statement SqliteHelper::Prepare(const std::string &sql) const
{
    return Statement(db_, sql);
}

int32_t SqliteHelper::ExecuteSql(const std::string &sql) const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t res = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errorMessage);
    if (res != SQLITE_OK) {
        SGLOGE("failed, errorMsg: %{public}s", errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

int32_t SqliteHelper::GetVersion() const __attribute__ ((no_sanitize("cfi")))
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return GENERAL_ERROR;
    }
    auto statement = Prepare(PRAGMA_VERSION_COMMAND);
    int32_t version = 0;
    while (statement.Step() == Statement::State::ROW) {
        version = statement.GetColumnInt(0);
    }
    SGLOGI("version: %{public}d", version);
    return version;
}

void SqliteHelper::SetVersion() const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return;
    }
    auto statement = Prepare(PRAGMA_VERSION_COMMAND + " = " + std::to_string(currentVersion_));
    statement.Step();
}

std::string SqliteHelper::SpitError() const
{
    if (db_ == nullptr) {
        SGLOGW("do open data base first!");
        return "";
    }
    return sqlite3_errmsg(db_);
}
} // namespace Security::SecurityGuard
} // namespace OHOS
// LCOV_EXCL_STOP
