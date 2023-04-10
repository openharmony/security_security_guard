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

#include "config_data_manager.h"

#include "securec.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
void ConfigDataManager::InsertModelMap(uint32_t modelId, const ModelCfg &config)
{
    modelMap_[modelId] = config;
}

void ConfigDataManager::InsertEventMap(int64_t eventId, const EventCfg &config)
{
    eventMap_[eventId] = config;
}

void ConfigDataManager::InsertModelToEventMap(uint32_t modelId, std::set<int64_t> eventIds)
{
    modelToEventMap_[modelId] = eventIds;
}

void ConfigDataManager::ResetModelMap()
{
    modelMap_.clear();
}

void ConfigDataManager::ResetEventMap()
{
    eventMap_.clear();
}

void ConfigDataManager::ResetModelToEventMap()
{
    modelToEventMap_.clear();
}

std::vector<int64_t> ConfigDataManager::GetEventIds(uint32_t modelId)
{
    SGLOGI("modelId=%{public}u", modelId);
    std::vector<int64_t> vector;
    if (modelToEventMap_.find(modelId) != modelToEventMap_.end()) {
        SGLOGD("map contains modelId=%{public}u", modelId);
        vector.assign(modelToEventMap_[modelId].begin(), modelToEventMap_[modelId].end());
    }
    return vector;
}

std::vector<int64_t> ConfigDataManager::GetAllEventIds() const
{
    std::vector<int64_t> vector;
    for (const auto &entry : eventMap_) {
        SGLOGD("eventId=%{public}ld", entry.first);
        vector.emplace_back(entry.first);
    }
    return vector;
}

bool ConfigDataManager::GetModelConfig(uint32_t modelId, ModelCfg &config) const
{
    auto it = modelMap_.find(modelId);
    if (it != modelMap_.end()) {
        config = it->second;
        return true;
    }
    return false;
}

bool ConfigDataManager::GetEventConfig(int64_t eventId, EventCfg &config) const
{
    auto it = eventMap_.find(eventId);
    if (it != eventMap_.end()) {
        config = it->second;
        return true;
    }
    return false;
}
} // OHOS::Security::SecurityGuard