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

#ifndef SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H
#define SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H

#include <string>

namespace OHOS::Security::SecurityGuard {
    const std::string MODEL_CFG_KEY = "modelcfg";
    const std::string THREAT_CFG_KEY = "threatcfg";
    const std::string EVENT_CFG_KEY = "eventcfg";
    const std::string DATA_MGR_CFG_KEY = "datamgrcfg";

    // model config key
    const std::string MODEL_CFG_MODEL_ID_KEY = "modelId";
    const std::string MODEL_CFG_MODEL_NAME_KEY = "modelName";
    const std::string MODEL_CFG_VERSION_KEY = "version";
    const std::string MODEL_CFG_THREAT_LIST_KEY = "threatList";
    const std::string MODEL_CFG_COMPUTE_MODEL_KEY = "computeModel";

    // threat config key
    const std::string THREAT_CFG_THREAT_ID_KEY = "threatId";
    const std::string THREAT_CFG_THREAT_NAME_KEY = "threatName";
    const std::string THREAT_CFG_VERSION_KEY = "version";
    const std::string THREAT_CFG_EVENT_LIST_KEY = "eventList";
    const std::string THREAT_CFG_COMPUTE_MODEL_KEY = "computeModel";

    // event config key
    const std::string EVENT_CFG_EVENT_ID_KEY = "eventId";
    const std::string EVENT_CFG_EVENT_NAME_KEY = "eventName";
    const std::string EVENT_CFG_VERSION_KEY = "version";
    const std::string EVENT_CFG_EVENT_TYPE_KEY = "eventType";
    const std::string EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY = "dataSensitivityLevel";
    const std::string EVENT_CFG_STORAGE_RAM_NUM_KEY = "storageRamNums";
    const std::string EVENT_CFG_STORAGE_ROM_NUM_KEY = "storageRomNums";

    // date manager key
    const std::string DATA_MGR_DEVICE_ROM_KEY = "deviceRom";
    const std::string DATA_MGR_DEVICE_RAM_KEY = "deviceRam";
    const std::string DATA_MGR_EVENT_MAX_ROM_NUM_KEY = "eventMaxRamNum";
    const std::string DATA_MGR_EVENT_MAX_RAM_NUM_KEY = "eventMaxRomNum";

    // event date key
    const std::string EVENT_DATA_EVENT_ID_KEY = "eventId";
    const std::string EVENT_DATA_VERSION_KEY = "version";
    const std::string EVENT_DATA_DATE_KEY = "date";
    const std::string EVENT_DATA_EVENT_CONTENT_KEY = "eventContent";

    // event content key
    const std::string EVENT_CONTENT_STATUS_KEY = "status";
    const std::string EVENT_CONTENT_CRED_KEY = "cred";
    const std::string EVENT_CONTENT_EXTRA_KEY = "extra";

    // radix
    constexpr int32_t DEX_RADIX = 10;
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H
