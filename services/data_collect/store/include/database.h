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

#ifndef SECURITY_GUARD_EVENT_STORE_H
#define SECURITY_GUARD_EVENT_STORE_H

#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "rdb_store_config.h"

#include "config_define.h"
#include "store_define.h"

namespace OHOS::Security::SecurityGuard {
class Database {
public:
    Database() = default;
    ~Database() = default;
    void CreateRdbStore(const NativeRdb::RdbStoreConfig &config, int version,
        NativeRdb::RdbOpenCallback &openCallback, int &errCode);
    int Insert(int64_t &outRowId, const std::string &table, const NativeRdb::ValuesBucket &initialValues);
    int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<NativeRdb::ValuesBucket> &initialBatchValues);
    int Update(int &changedRows, const NativeRdb::ValuesBucket &values, const NativeRdb::AbsRdbPredicates &predicates);
    int Delete(int &deletedRows, const NativeRdb::AbsRdbPredicates &predicates);
    std::shared_ptr<NativeRdb::ResultSet> Query(
        const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns);
    int ExecuteSql(const std::string &sql);
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs = std::vector<NativeRdb::ValueObject>());
    int Count(int64_t &outValue, const NativeRdb::AbsRdbPredicates &predicates);
    int BeginTransaction();
    int RollBack();
    int Commit();
    int Attach(const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey);

private:
    int IsExistStore();
    std::shared_ptr<NativeRdb::RdbStore> store_;
};
}  // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_EVENT_STORE_H