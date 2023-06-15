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

#include "database.h"

#include <thread>

#include "abs_shared_result_set.h"
#include "rdb_errno.h"
#include "rdb_helper.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t MAX_TIMES = 5;
    constexpr int32_t SLEEP_INTERVAL = 500;
}

void Database::CreateRdbStore(const NativeRdb::RdbStoreConfig &config, int version,
    NativeRdb::RdbOpenCallback &openCallback, int &errCode)
{
    SGLOGI("EventStore::CreateRdbStore");
    store_ = NativeRdb::RdbHelper::GetRdbStore(config, version, openCallback, errCode);
}

int Database::Insert(int64_t &outRowId, const std::string &table, const NativeRdb::ValuesBucket &initialValues)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Insert(outRowId, table, initialValues);
    }
    return ret;
}

int Database::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<NativeRdb::ValuesBucket> &initialBatchValues)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->BatchInsert(outInsertNum, table, initialBatchValues);
    }
    return ret;
}

int Database::Update(int &changedRows, const NativeRdb::ValuesBucket &values,
    const NativeRdb::AbsRdbPredicates &predicates)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Update(changedRows, values, predicates);
    }
    return ret;
}

int Database::Delete(int &deletedRows, const NativeRdb::AbsRdbPredicates &predicates)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Delete(deletedRows, predicates);
    }
    return ret;
}

std::shared_ptr<NativeRdb::ResultSet> Database::Query(
    const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        return store_->Query(predicates, columns);
    }
    return nullptr;
}

int Database::ExecuteSql(const std::string &sql)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->ExecuteSql(sql);
    }
    return ret;
}

int Database::ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->ExecuteAndGetLong(outValue, sql, bindArgs);
    }
    return ret;
}

int Database::Count(int64_t &outValue, const NativeRdb::AbsRdbPredicates &predicates)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Count(outValue, predicates);
    }
    return ret;
}

int Database::BeginTransaction()
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->BeginTransaction();
    }
    return ret;
}

int Database::RollBack()
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->RollBack();
    }
    return ret;
}

int Database::Commit()
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Commit();
    }
    return ret;
}

int Database::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    int ret = IsExistStore();
    if (ret == NativeRdb::E_OK) {
        ret = store_->Attach(alias, pathName, destEncryptKey);
    }
    return ret;
}

int Database::IsExistStore()
{
    if (store_ != nullptr) {
        return NativeRdb::E_OK;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        if (store_ != nullptr) {
            return NativeRdb::E_OK;
        }

        SGLOGW("tryTimes = %{public}d", tryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL));
        tryTimes--;
    }
    if (store_ == nullptr) {
        SGLOGE("EventStore::IsExistStore NativeRdb::RdbStore is null!");
        return NativeRdb::E_ERROR;
    }
    return NativeRdb::E_OK;
}
}