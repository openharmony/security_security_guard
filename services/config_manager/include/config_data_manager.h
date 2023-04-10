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

#ifndef SECURITY_GUARD_CONFIG_DATA_MANAGER_H
#define SECURITY_GUARD_CONFIG_DATA_MANAGER_H

#include <set>
#include <unordered_map>

#include "singleton.h"

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
class ConfigDataManager : public DelayedSingleton<ConfigDataManager> {
public:
    void InsertModelMap(uint32_t modelId, const ModelCfg &config);
    void InsertEventMap(int64_t eventId, const EventCfg &config);
    void InsertModelToEventMap(uint32_t modelId, std::set<int64_t> eventIds);
    void ResetModelMap();
    void ResetEventMap();
    void ResetModelToEventMap();
    std::vector<int64_t> GetEventIds(uint32_t modelId);
    std::vector<int64_t> GetAllEventIds() const;
    bool GetModelConfig(uint32_t modelId, ModelCfg &config) const;
    bool GetEventConfig(int64_t eventId, EventCfg &config) const;

private:
    std::unordered_map<uint32_t, std::set<int64_t>> modelToEventMap_;
    std::unordered_map<uint32_t, ModelCfg> modelMap_;
    std::unordered_map<int64_t, EventCfg> eventMap_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DATA_MANAGER_H