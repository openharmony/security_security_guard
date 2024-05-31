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

#ifndef SECURITY_GUARD_CONFIG_DATABASE_HELPER_H
#define SECURITY_GUARD_CONFIG_DATABASE_HELPER_H

#include "database.h"
#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
class ConfigDatabaseHelper : public Database {
public:
    explicit ConfigDatabaseHelper(std::string dbTable);
    ~ConfigDatabaseHelper() = default;
    virtual int Init();
    virtual int InsertAppInfo(const AppInfo& info);
    virtual int QueryAllAppInfo(std::vector<AppInfo> &infos);
    virtual int QueryAppInfosByName(const std::string &appName, std::vector<AppInfo> &infos);
    virtual int DeleteAppInfoByNameAndGlobbalFlag(const std::string &appName, int isGlobalApp);
    virtual int QueryAppInfoByAttribute(const std::string attr, std::vector<AppInfo> &infos);
    virtual int DeleteAppInfoByIsGlobalApp(int isGlobalApp);
    virtual int InsertAllAppInfo(const std::vector<AppInfo> &infos);
protected:
    int32_t QueryAppInfoBase(const NativeRdb::RdbPredicates &predicates, std::vector<AppInfo> &infos);
    int32_t GetResultSetTableInfo(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, AppInfoTableInfo &table);
    void SetValuesBucket(const AppInfo &event, NativeRdb::ValuesBucket &values);
    std::string CreateTable();
    std::string dbPath_{};
    std::string dbTable_{};
};
} // namespace OHOS::Security::SecurityGuard {
#endif // SECURITY_GUARD_DATABASE_HELPER_H