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

#include "model_cfg_marshalling.h"

#include "json_cfg.h"
#include "model_analysis_define.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
void to_json(json &jsonObj, const ModelCfgSt &modelCfg)
{
    std::vector<std::string> threatList;
    for (uint32_t threat : modelCfg.threatList) {
        threatList.emplace_back(std::to_string(threat));
    }
    jsonObj = json {
        { MODEL_CFG_MODEL_ID_KEY, std::to_string(modelCfg.modelId) },
        { MODEL_CFG_MODEL_NAME_KEY, modelCfg.modelName },
        { MODEL_CFG_VERSION_KEY, modelCfg.version },
        { MODEL_CFG_THREAT_LIST_KEY,  threatList},
        { MODEL_CFG_COMPUTE_MODEL_KEY, modelCfg.computeModel }
    };
}

void from_json(const json &jsonObj, ModelCfgSt &modelCfg)
{
    std::string modelId;
    Unmarshal(modelId, jsonObj, MODEL_CFG_MODEL_ID_KEY);
    uint32_t value = 0;
    if (!SecurityGuardUtils::StrToU32(modelId, value)) {
        return;
    }
    modelCfg.modelId = value;
    Unmarshal(modelCfg.modelName, jsonObj, MODEL_CFG_MODEL_NAME_KEY);
    Unmarshal(modelCfg.version, jsonObj, MODEL_CFG_VERSION_KEY);
    std::vector<std::string> threatList;
    Unmarshal(threatList, jsonObj, MODEL_CFG_THREAT_LIST_KEY);
    for (const std::string& threat : threatList) {
        uint32_t tmp = 0;
        if (!SecurityGuardUtils::StrToU32(threat, tmp)) {
            return;
        }
        modelCfg.threatList.emplace_back(tmp);
    }
    Unmarshal(modelCfg.computeModel, jsonObj, MODEL_CFG_COMPUTE_MODEL_KEY);
}

void to_json(json &jsonObj, const ThreatCfgSt &threatCfg)
{
    std::vector<std::string> eventList;
    for (uint32_t event : threatCfg.eventList) {
        eventList.emplace_back(std::to_string(event));
    }
    jsonObj = json {
        { THREAT_CFG_THREAT_ID_KEY, threatCfg.threatId },
        { THREAT_CFG_THREAT_NAME_KEY, threatCfg.threatName },
        { THREAT_CFG_VERSION_KEY, threatCfg.version },
        { THREAT_CFG_EVENT_LIST_KEY, threatCfg.eventList },
        { THREAT_CFG_COMPUTE_MODEL_KEY, threatCfg.computeModel }
    };
}

void from_json(const json &jsonObj, ThreatCfgSt &threatCfg)
{
    std::string threatId;
    Unmarshal(threatId, jsonObj, THREAT_CFG_THREAT_ID_KEY);
    uint32_t value = 0;
    if (!SecurityGuardUtils::StrToU32(threatId, value)) {
        return;
    }
    threatCfg.threatId = value;
    Unmarshal(threatCfg.threatName, jsonObj, THREAT_CFG_THREAT_NAME_KEY);
    Unmarshal(threatCfg.version, jsonObj, THREAT_CFG_VERSION_KEY);
    std::vector<std::string> eventList;
    Unmarshal(eventList, jsonObj, THREAT_CFG_EVENT_LIST_KEY);
    for (const std::string& event : eventList) {
        int64_t tmp = 0;
        if (!SecurityGuardUtils::StrToI64(event, tmp)) {
            return;
        }
        threatCfg.eventList.emplace_back(tmp);
    }
    Unmarshal(threatCfg.computeModel, jsonObj, THREAT_CFG_COMPUTE_MODEL_KEY);
}

void to_json(json &jsonObj, const EventCfgSt &eventCfg)
{
    jsonObj = json {
        { EVENT_CFG_EVENT_ID_KEY, std::to_string(eventCfg.eventId) },
        { EVENT_CFG_EVENT_NAME_KEY, eventCfg.eventName },
        { EVENT_CFG_VERSION_KEY, eventCfg.version },
        { EVENT_CFG_EVENT_TYPE_KEY, eventCfg.eventType },
        { EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY, eventCfg.dataSensitivityLevel },
        { EVENT_CFG_STORAGE_RAM_NUM_KEY, eventCfg.storageRamNums },
        { EVENT_CFG_STORAGE_ROM_NUM_KEY, eventCfg.storageRomNums }
    };
}

void from_json(const json &jsonObj, EventCfgSt &eventCfg)
{
    std::string eventId;
    Unmarshal(eventId, jsonObj, EVENT_CFG_EVENT_ID_KEY);
    int64_t value = 0;
    if (!SecurityGuardUtils::StrToI64(eventId, value)) {
        return;
    }
    eventCfg.eventId = value;
    Unmarshal(eventCfg.eventName, jsonObj, EVENT_CFG_EVENT_NAME_KEY);
    Unmarshal(eventCfg.version, jsonObj, EVENT_CFG_VERSION_KEY);
    Unmarshal(eventCfg.eventType, jsonObj, EVENT_CFG_EVENT_TYPE_KEY);
    Unmarshal(eventCfg.dataSensitivityLevel, jsonObj, EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY);
    Unmarshal(eventCfg.storageRamNums, jsonObj, EVENT_CFG_STORAGE_RAM_NUM_KEY);
    Unmarshal(eventCfg.storageRomNums, jsonObj, EVENT_CFG_STORAGE_ROM_NUM_KEY);
}

void to_json(json &jsonObj, const DataMgrCfgSt &dataMgrCfg)
{
    jsonObj = json {
        { DATA_MGR_DEVICE_RAM_KEY, dataMgrCfg.deviceRam },
        { DATA_MGR_DEVICE_ROM_KEY, dataMgrCfg.deviceRom },
        { DATA_MGR_EVENT_MAX_RAM_NUM_KEY, dataMgrCfg.eventMaxRamNum },
        { DATA_MGR_EVENT_MAX_ROM_NUM_KEY, dataMgrCfg.eventMaxRomNum }
    };
}

void from_json(const json &jsonObj, DataMgrCfgSt &dataMgrCfg)
{
    Unmarshal(dataMgrCfg.deviceRam, jsonObj, DATA_MGR_DEVICE_RAM_KEY);
    Unmarshal(dataMgrCfg.deviceRom, jsonObj, DATA_MGR_DEVICE_ROM_KEY);
    Unmarshal(dataMgrCfg.eventMaxRamNum, jsonObj, DATA_MGR_EVENT_MAX_RAM_NUM_KEY);
    Unmarshal(dataMgrCfg.eventMaxRomNum, jsonObj, DATA_MGR_EVENT_MAX_ROM_NUM_KEY);
}

void to_json(json &jsonObj, const EventDataSt &eventDataSt)
{
    jsonObj = json {
        { EVENT_DATA_EVENT_ID_KEY, eventDataSt.eventId },
        { EVENT_DATA_VERSION_KEY, eventDataSt.version },
        { EVENT_DATA_DATE_KEY, eventDataSt.date },
        { EVENT_DATA_EVENT_CONTENT_KEY, eventDataSt.content }
    };
}

void from_json(const json &jsonObj, EventDataSt &eventDataSt)
{
    Unmarshal(eventDataSt.eventId, jsonObj, EVENT_DATA_EVENT_ID_KEY);
    Unmarshal(eventDataSt.version, jsonObj, EVENT_DATA_VERSION_KEY);
    Unmarshal(eventDataSt.date, jsonObj, EVENT_DATA_DATE_KEY);
    Unmarshal(eventDataSt.content, jsonObj, EVENT_DATA_EVENT_CONTENT_KEY);
}

void to_json(json &jsonObj, const EventContentSt &eventContentSt)
{
    jsonObj = json {
        { EVENT_CONTENT_STATUS_KEY, eventContentSt.status },
        { EVENT_CONTENT_CRED_KEY, eventContentSt.cred },
        { EVENT_CONTENT_EXTRA_KEY, eventContentSt.extra }
    };
}

void from_json(const json &jsonObj, EventContentSt &eventContentSt)
{
    Unmarshal(eventContentSt.status, jsonObj, EVENT_CONTENT_STATUS_KEY);
    Unmarshal(eventContentSt.cred, jsonObj, EVENT_CONTENT_CRED_KEY);
    Unmarshal(eventContentSt.extra, jsonObj, EVENT_CONTENT_EXTRA_KEY);
}
}