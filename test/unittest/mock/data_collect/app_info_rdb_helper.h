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

#ifndef SECURITY_GUARD_APP_INFO_RDB_HELPER_H
#define SECURITY_GUARD_APP_INFO_RDB_HELPER_H
#include <vector>

#include "gmock/gmock.h"
#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {
class BaseConfigDatabaseHelper {
public:
    virtual int Init() = 0;
    virtual int InsertAppInfo(const AppInfo& info) = 0;
    virtual int QueryAllAppInfo(std::vector<AppInfo> &infos) = 0;
    virtual int QueryAppInfosByName(const std::string &appName, std::vector<AppInfo> &infos) = 0;
    virtual int DeleteAppInfoByNameAndGlobbalFlag(const std::string &appName, int isGlobalApp) = 0;
    virtual int QueryAppInfoByAttribute(const std::string attr, std::vector<AppInfo> &infos) = 0;
    virtual int DeleteAppInfoByIsGlobalApp(int isGlobalApp) = 0;
    virtual int InsertAllAppInfo(const std::vector<AppInfo> &infos) = 0;
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_RISK_EVENT_RDB_HELPER_H