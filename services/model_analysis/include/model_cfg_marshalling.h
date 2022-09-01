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

#ifndef SECURITY_GUARD_MODEL_CFG_MARSHALLING_H
#define SECURITY_GUARD_MODEL_CFG_MARSHALLING_H

#include <string>
#include <vector>

#include "nlohmann/json.hpp"

using nlohmann::json;

namespace OHOS::Security::SecurityGuard {
using ModelCfgSt = struct {
    uint32_t modelId;
    std::string modelName;
    uint32_t version;
    std::vector<uint32_t> threatList;
    std::string computeModel;
};

using ThreatCfgSt = struct {
    uint32_t threatId;
    std::string threatName;
    uint32_t version;
    std::vector<int64_t> eventList;
    std::string computeModel;
};

using EventCfgSt = struct {
    int64_t eventId;
    std::string eventName;
    uint32_t version;
    uint32_t eventType;
    uint32_t dataSensitivityLevel;
    uint32_t storageRamNums;
    uint32_t storageRomNums;
};

using DataMgrCfgSt = struct {
    uint32_t deviceRom;
    uint32_t deviceRam;
    uint32_t eventMaxRamNum;
    uint32_t eventMaxRomNum;
};

using EventDataSt = struct {
    int64_t eventId;
    std::string version;
    std::string date;
    std::string content;
};

using EventContentSt = struct {
    uint32_t status;
    uint32_t cred;
    std::string extra;
};

void to_json(json &jsonObj, const ModelCfgSt &modelCfg);
void from_json(const json &jsonObj, ModelCfgSt &modelCfg);
void to_json(json &jsonObj, const ThreatCfgSt &threatCfg);
void from_json(const json &jsonObj, ThreatCfgSt &threatCfg);
void to_json(json &jsonObj, const EventCfgSt &eventCfg);
void from_json(const json &jsonObj, EventCfgSt &eventCfg);
void to_json(json &jsonObj, const DataMgrCfgSt &dataMgrCfg);
void from_json(const json &jsonObj, DataMgrCfgSt &dataMgrCfg);
void to_json(json &jsonObj, const EventDataSt &eventDataSt);
void from_json(const json &jsonObj, EventDataSt &eventDataSt);
void to_json(json &jsonObj, const EventContentSt &eventContentSt);
void from_json(const json &jsonObj, EventContentSt &eventContentSt);
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_CFG_MARSHALLING_H
