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
#include "audit_event_rdb_helper.h"

#include "rdb_predicates.h"

#include "config_define.h"
#include "rdb_event_store_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
AuditEventRdbHelper::AuditEventRdbHelper() : DatabaseHelper(AUDIT_TABLE)
{
    dbPath_ = FOLDER_PATH + "audit_event.db";
}

DatabaseHelper &AuditEventRdbHelper::GetInstance()
{
    static AuditEventRdbHelper auditInstance;
    static DatabaseHelper &instance = auditInstance;
    return instance;
}

int AuditEventRdbHelper::Init()
{
    int errCode = NativeRdb::E_ERROR;
    NativeRdb::RdbStoreConfig config(dbPath_);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S2);
    std::string table = CreateTable();
    std::vector<std::string> createTableVec;
    createTableVec.push_back(table);
    RdbEventStoreCallback callback(createTableVec);
    CreateRdbStore(config, DB_VERSION, callback, errCode);
    return errCode;
}
} // namespace OHOS::Security::SecurityGuard