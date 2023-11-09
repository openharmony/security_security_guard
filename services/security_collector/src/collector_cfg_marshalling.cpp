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

#include "collector_cfg_marshalling.h"

#include "json_cfg.h"

namespace OHOS::Security::SecurityCollector {
using nlohmann::json;

void to_json(json &jsonObj, const ModuleCfgSt &moduleCfg)
{
    jsonObj = json {
        { MODULE_ID, moduleCfg.moduleId },
        { EVENT_ID, moduleCfg.eventId },
        { MODULE_NAME, moduleCfg.moduleName },
        { MODULE_PATH, moduleCfg.modulePath },
        { MODULE_VERSION,  moduleCfg.version }
    };
}

void from_json(const json &jsonObj, ModuleCfgSt &moduleCfg)
{
    SecurityGuard::JsonCfg::Unmarshal(moduleCfg.moduleId, jsonObj, MODULE_ID);
    SecurityGuard::JsonCfg::Unmarshal(moduleCfg.eventId, jsonObj, EVENT_ID);
    SecurityGuard::JsonCfg::Unmarshal(moduleCfg.moduleName, jsonObj, MODULE_NAME);
    SecurityGuard::JsonCfg::Unmarshal(moduleCfg.modulePath, jsonObj, MODULE_PATH);
    SecurityGuard::JsonCfg::Unmarshal(moduleCfg.version, jsonObj, MODULE_VERSION);
}
}