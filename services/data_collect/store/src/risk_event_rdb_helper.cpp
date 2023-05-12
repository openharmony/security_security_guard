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
#include "risk_event_rdb_helper.h"

#include "rdb_event_store_callback.h"

namespace OHOS::Security::SecurityGuard {
DatabaseHelper &RiskEventRdbHelper::GetInstance()
{
    static RiskEventRdbHelper riskInstance;
    static DatabaseHelper &instance = riskInstance;
    return instance;
}

RiskEventRdbHelper::RiskEventRdbHelper() : DatabaseHelper(RISK_TABLE)
{
    dbPath_ = FOLDER_PATH + "risk_event.db";
}

int RiskEventRdbHelper::Init()
{
    int errCode = NativeRdb::E_ERROR;
    NativeRdb::RdbStoreConfig config(dbPath_);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    std::string table = CreateTable();
    std::vector<std::string> createTableVec;
    createTableVec.push_back(table);
    RdbEventStoreCallback callback(createTableVec);
    CreateRdbStore(config, DB_VERSION, callback, errCode);
    return errCode;
}
} // namespace OHOS::Security::SecurityGuard