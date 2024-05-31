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

#ifndef SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H
#define SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H

#include "gmock/gmock.h"

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
class BaseConfigDataManager {
public:
    virtual std::vector<uint32_t> GetAllModelIds() = 0;
    virtual bool GetModelConfig(uint32_t modelId, ModelCfg &config) = 0;
    virtual bool GetEventConfig(int64_t eventId, EventCfg &config) = 0;
    virtual std::string GetTableFromEventId(int64_t eventId) = 0;
    virtual std::vector<int64_t> GetAllEventIds() = 0;
    virtual std::vector<AppInfo> GetAppInfosByName(const std::string &appName) = 0;
};

class ConfigDataManager : public BaseConfigDataManager {
public:
    static ConfigDataManager &GetInstance()
    {
        static ConfigDataManager instance;
        return instance;
    };
    MOCK_METHOD0(GetAllModelIds, std::vector<uint32_t>());
    MOCK_METHOD2(GetModelConfig, bool(uint32_t modelId, ModelCfg &config));
    MOCK_METHOD2(GetEventConfig, bool(int64_t eventId, EventCfg &config));
    MOCK_METHOD1(GetTableFromEventId, std::string(int64_t eventId));
    MOCK_METHOD0(GetAllEventIds, std::vector<int64_t>());
    MOCK_METHOD1(GetAppInfosByName, std::vector<AppInfo>(const std::string &appName));
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H