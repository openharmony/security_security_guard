/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "result_set.h"
#include "rdb_errno.h"
#include "rdb_helper.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
void Database::CreateRdbStore(const NativeRdb::RdbStoreConfig &config, int version,
    NativeRdb::RdbOpenCallback &openCallback, int &errCode)
{
    SGLOGI("EventStore::CreateRdbStore");
}

int Database::Insert(int64_t &outRowId, const std::string &table, const NativeRdb::ValuesBucket &initialValues)
{
    return NativeRdb::E_OK;
}

int Database::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<NativeRdb::ValuesBucket> &initialBatchValues)
{
    return NativeRdb::E_OK;
}

int Database::Update(int &changedRows, const NativeRdb::ValuesBucket &values,
    const NativeRdb::AbsRdbPredicates &predicates)
{
    return NativeRdb::E_OK;
}

int Database::Delete(int &deletedRows, const NativeRdb::AbsRdbPredicates &predicates)
{
    return NativeRdb::E_OK;
}

std::shared_ptr<NativeRdb::ResultSet> Database::Query(
    const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    return nullptr;
}

int Database::ExecuteSql(const std::string &sql)
{
    return NativeRdb::E_OK;
}

int Database::ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    return NativeRdb::E_OK;
}

int Database::Count(int64_t &outValue, const NativeRdb::AbsRdbPredicates &predicates)
{
    return NativeRdb::E_OK;
}

int Database::BeginTransaction()
{
    return NativeRdb::E_OK;
}

int Database::RollBack()
{
    return NativeRdb::E_OK;
}

int Database::Commit()
{
    return NativeRdb::E_OK;
}

int Database::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    return NativeRdb::E_OK;
}

int Database::IsExistStore()
{
    return NativeRdb::E_OK;
}
}