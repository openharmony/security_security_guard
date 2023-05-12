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

#include "rdb_event_store_callback.h"

#include "rdb_errno.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int RdbEventStoreCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    SGLOGI("RdbEventStoreCallback::OnCreate");
    int32_t ret = NativeRdb::E_ERROR;
    size_t size = createTableSqlVec_.size();
    if (size == 0) {
        return ret;
    }
    for (size_t i = 0; i < createTableSqlVec_.size(); i++) {
        ret = rdbStore.ExecuteSql(createTableSqlVec_[i]);
    }
    return ret;
}

int32_t RdbEventStoreCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    SGLOGI("RdbEventStoreCallback::OnUpgrade");
    (void)store;
    (void)oldVersion;
    (void)newVersion;
    return NativeRdb::E_OK;
}
} // namespace OHOS::Security::SecurityGuard
