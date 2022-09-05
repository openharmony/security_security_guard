/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_MODEL_ANALYSIS_H
#define SECURITY_GUARD_MODEL_ANALYSIS_H

#include <set>
#include <unordered_map>
#include <vector>

#include "event_config.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "security_guard_define.h"
#include "threat_config.h"

namespace OHOS::Security::SecurityGuard {
class ModelAnalysis {
public:
    static ModelAnalysis &GetInstance();
    ErrorCode AnalyseModel();
    std::vector<int64_t> GetAllEventIds() const;
    std::vector<int64_t> GetEventIds(uint32_t modelId);
    ErrorCode GetModelConfig(uint32_t modelId, std::shared_ptr<ModelConfig> &config) const;
    ErrorCode GetThreatConfig(uint32_t threatId, std::shared_ptr<ThreatConfig> &config) const;
    ErrorCode GetEventConfig(int64_t eventId, std::shared_ptr<EventConfig> &config) const;

private:
    ModelAnalysis() = default;
    void MapModelToEvent(const std::unordered_map<uint32_t, std::set<uint32_t>> &modelToThreatMap,
        std::unordered_map<uint32_t, std::set<int64_t>> threatToEventMap);
    ErrorCode InitDataMgrCfg();
    void MapModelToThreat(const std::vector<ModelCfgSt> &modelCfgs,
        std::unordered_map<uint32_t, std::set<uint32_t>> &map);
    void MapThreatToEvent(const std::vector<ThreatCfgSt> &threatCfgs,
        std::unordered_map<uint32_t, std::set<int64_t>> &map);
    ErrorCode CheckFileStream(std::ifstream &stream);
    ErrorCode ParseConfig(const nlohmann::json &json);
    std::unordered_map<uint32_t, std::set<int64_t>> modelToEventMap_;
    std::unordered_map<uint32_t, std::shared_ptr<ModelConfig>> modelMap_;
    std::unordered_map<uint32_t, std::shared_ptr<ThreatConfig>> threatMap_;
    std::unordered_map<int64_t, std::shared_ptr<EventConfig>> eventMap_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_ANALYSIS_H