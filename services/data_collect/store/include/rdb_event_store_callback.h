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
#ifndef SECURITY_GUARD_RDB_EVENT_STORE_CALLBACK_H
#define SECURITY_GUARD_RDB_EVENT_STORE_CALLBACK_H

#include <string>
#include <vector>

#include "rdb_open_callback.h"
#include "rdb_store.h"

namespace OHOS::Security::SecurityGuard {
class RdbEventStoreCallback : public NativeRdb::RdbOpenCallback {
public:
    explicit RdbEventStoreCallback(const std::vector<std::string> &createTableSqlVec)
        : createTableSqlVec_(createTableSqlVec) {}
    ~RdbEventStoreCallback() = default;
    int OnCreate(NativeRdb::RdbStore& rdbStore) override;
    int OnUpgrade(NativeRdb::RdbStore& rdbStore, int oldVersion, int newVersion) override;

private:
    std::vector<std::string> createTableSqlVec_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RDB_EVENT_STORE_CALLBACK_H