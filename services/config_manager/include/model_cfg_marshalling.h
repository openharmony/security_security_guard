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

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
void from_json(const nlohmann::json &jsonObj, Field &field);
void from_json(const nlohmann::json &jsonObj, Rule &rule);
void from_json(const nlohmann::json &jsonObj, BuildInDetectionCfg &config);
void to_json(nlohmann::json &jsonObj, const ModelCfg &modelCfg);
void from_json(const nlohmann::json &jsonObj, ModelCfg &modelCfg);
void to_json(nlohmann::json &jsonObj, const EventCfg &eventCfg);
void from_json(const nlohmann::json &jsonObj, EventCfg &eventCfg);
void to_json(nlohmann::json &jsonObj, const DataMgrCfgSt &dataMgrCfg);
void from_json(const nlohmann::json &jsonObj, DataMgrCfgSt &dataMgrCfg);
void to_json(nlohmann::json &jsonObj, const SecEvent &eventDataSt);
void to_json(nlohmann::json &jsonObj, const EventContentSt &eventContentSt);
void from_json(const nlohmann::json &jsonObj, EventContentSt &eventContentSt);
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_CFG_MARSHALLING_H
