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

#include "model_analysis.h"

#include <fstream>

#include "nlohmann/json.hpp"

#include "data_mgr_cfg.h"
#include "json_cfg.h"
#include "model_analysis_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const char* SG_MODEL_PATH = "/system/etc/security_guard_model.cfg";
    const char* SG_CONFIG_PATH = "/system/etc/security_guard.cfg";
}

ModelAnalysis &ModelAnalysis::GetInstance()
{
    static ModelAnalysis instance;
    return instance;
}

ErrorCode ModelAnalysis::AnalyseModel()
{
    std::ifstream stream(SG_MODEL_PATH, std::ios::in);
    if (!stream) {
        SGLOGE("stream error, %{public}s", strerror(errno));
        return FILE_ERR;
    }

    ErrorCode ret = CheckFileStream(stream);
    if (ret != SUCCESS) {
        SGLOGE("check file stream error, ret=%{public}d", ret);
        stream.close();
        return ret;
    }
    nlohmann::json json;
    stream >> json;
    stream.close();

    if (json.is_discarded()) {
        SGLOGE("parse json error");
        return JSON_ERR;
    }

    return ParseConfig(json);
}

ErrorCode ModelAnalysis::ParseConfig(const nlohmann::json &json)
{
    SGLOGD("parse ModelCfgSt: ");
    std::vector<ModelCfgSt> modelCfgs;
    if (!Unmarshal<ModelCfgSt>(modelCfgs, json, MODEL_CFG_KEY)) {
        return JSON_ERR;
    }
    for (const ModelCfgSt& config : modelCfgs) {
        SGLOGD("modelId=%{public}u", config.modelId);
        for (uint32_t threat : config.threatList) {
            SGLOGD("model threat=%{public}u", threat);
        }
        modelMap_[config.modelId] = std::make_shared<ModelConfig>(config);
    }

    SGLOGD("parse ThreatCfgSt: ");
    std::vector<ThreatCfgSt> threatCfgs;
    if (!Unmarshal<ThreatCfgSt>(threatCfgs, json, THREAT_CFG_KEY)) {
        return JSON_ERR;
    }
    for (const ThreatCfgSt& config : threatCfgs) {
        SGLOGD("threatId=%{public}u", config.threatId);
        for (int64_t event : config.eventList) {
            SGLOGD("threat eventId=%{public}ld", event);
        }
        threatMap_[config.threatId] = std::make_shared<ThreatConfig>(config);
    }

    SGLOGD("parse EventCfgSt: ");
    std::vector<EventCfgSt> eventCfgs;
    if (!Unmarshal<EventCfgSt>(eventCfgs, json, EVENT_CFG_KEY)) {
        return JSON_ERR;
    }
    for (const EventCfgSt& config : eventCfgs) {
        SGLOGE("eventId=%{public}ld", config.eventId);
        eventMap_[config.eventId] = std::make_shared<EventConfig>(config);
    }

    std::unordered_map<uint32_t, std::set<uint32_t>> modelToThreatMap;
    std::unordered_map<uint32_t, std::set<int64_t>> threatToEventMap;
    MapModelToThreat(modelCfgs, modelToThreatMap);
    MapThreatToEvent(threatCfgs, threatToEventMap);
    MapModelToEvent(modelToThreatMap, threatToEventMap);

    return InitDataMgrCfg();
}

std::vector<int64_t> ModelAnalysis::GetEventIds(uint32_t modelId)
{
    SGLOGD("modelId=%{public}u", modelId);
    std::vector<int64_t> vec;
    if (modelToEventMap_.find(modelId) != modelToEventMap_.end()) {
        SGLOGI("map contains modelId=%{public}u", modelId);
        vec.assign(modelToEventMap_[modelId].begin(), modelToEventMap_[modelId].end());
    }
    return vec;
}

std::vector<int64_t> ModelAnalysis::GetAllEventIds() const
{
    std::vector<int64_t> vec;
    for (const auto &entry : eventMap_) {
        SGLOGE("eventId=%{public}ld", entry.first);
        vec.emplace_back(entry.first);
    }
    return vec;
}

void ModelAnalysis::MapModelToThreat(const std::vector<ModelCfgSt>& modelCfgs,
    std::unordered_map<uint32_t, std::set<uint32_t>>& map)
{
    for (const ModelCfgSt& modelCfg : modelCfgs) {
        std::set<uint32_t> tmpSet;
        auto it = map.find(modelCfg.modelId);
        if (it != map.end()) {
            tmpSet = it->second;
        }

        for (uint32_t threat : modelCfg.threatList) {
            tmpSet.emplace(threat);
        }
        map[modelCfg.modelId] = std::move(tmpSet);
    }
}

void ModelAnalysis::MapThreatToEvent(const std::vector<ThreatCfgSt>& threatCfgs,
    std::unordered_map<uint32_t, std::set<int64_t>>& map)
{
    for (const ThreatCfgSt& threatCfg : threatCfgs) {
        std::set<int64_t> tmpSet;
        auto it = map.find(threatCfg.threatId);
        if (it != map.end()) {
            tmpSet = it->second;
        }

        for (int64_t event : threatCfg.eventList) {
            tmpSet.emplace(event);
        }
        map[threatCfg.threatId] = std::move(tmpSet);
    }
}

void ModelAnalysis::MapModelToEvent(const std::unordered_map<uint32_t, std::set<uint32_t>>& modelToThreatMap,
    std::unordered_map<uint32_t, std::set<int64_t>> threatToEventMap)
{
    for (auto &pair : modelToThreatMap) {
        std::set<int64_t> tmpSet;
        auto it = modelToEventMap_.find(pair.first);
        if (it != modelToEventMap_.end()) {
            tmpSet = it->second;
        }

        for (uint32_t threat : pair.second) {
            tmpSet.insert(threatToEventMap[threat].begin(), threatToEventMap[threat].end());
        }
        modelToEventMap_[pair.first] = std::move(tmpSet);
    }
}

ErrorCode ModelAnalysis::CheckFileStream(std::ifstream &stream)
{
    if (!stream.is_open()) {
        SGLOGE("stream open error, %{public}s", strerror(errno));
        return FILE_ERR;
    }

    stream.seekg(0, std::ios::end);
    int len = static_cast<int>(stream.tellg());
    if (len == 0) {
        SGLOGE("stream is empty");
        return BAD_PARAM;
    }
    stream.seekg(0, std::ios::beg);
    return SUCCESS;
}

ErrorCode ModelAnalysis::InitDataMgrCfg()
{
    std::ifstream stream(SG_CONFIG_PATH, std::ios::in);
    ErrorCode ret = CheckFileStream(stream);
    if (ret != SUCCESS) {
        stream.close();
        return ret;
    }
    nlohmann::json json;
    stream >> json;
    stream.close();

    if (json.is_discarded()) {
        SGLOGE("json error");
        return JSON_ERR;
    }

    SGLOGD("parse DataMgrCfgSt: ");
    DataMgrCfgSt dataMgrCfg;
    if (!Unmarshal<DataMgrCfgSt>(dataMgrCfg, json, DATA_MGR_CFG_KEY)) {
        return JSON_ERR;
    }
    DataMgrCfg::GetInstance().SetDeviceRam(dataMgrCfg.deviceRam);
    DataMgrCfg::GetInstance().SetDeviceRom(dataMgrCfg.deviceRom);
    DataMgrCfg::GetInstance().SetEventMaxRamNum(dataMgrCfg.eventMaxRamNum);
    DataMgrCfg::GetInstance().SetEventMaxRomNum(dataMgrCfg.eventMaxRomNum);
    return SUCCESS;
}

ErrorCode ModelAnalysis::GetModelConfig(uint32_t modelId, std::shared_ptr<ModelConfig> &config) const
{
    auto it = modelMap_.find(modelId);
    if (it != modelMap_.end()) {
        config = it->second;
        return SUCCESS;
    }
    return NOT_FOUND;
}

ErrorCode ModelAnalysis::GetThreatConfig(uint32_t threatId, std::shared_ptr<ThreatConfig> &config) const
{
    auto it = threatMap_.find(threatId);
    if (it != threatMap_.end()) {
        config = it->second;
        return SUCCESS;
    }
    return NOT_FOUND;
}

ErrorCode ModelAnalysis::GetEventConfig(int64_t eventId, std::shared_ptr<EventConfig> &config) const
{
    auto it = eventMap_.find(eventId);
    if (it != eventMap_.end()) {
        config = it->second;
        return SUCCESS;
    }
    return NOT_FOUND;
}
}