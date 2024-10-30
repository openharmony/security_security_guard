/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "config_manager_fuzzer.h"

#include <string>

#include "securec.h"

#define private public
#define protected public
#include "base_config.h"
#include "config_data_manager.h"
#include "i_model_info.h"
#include "config_manager.h"
#include "config_operator.h"
#include "config_subscriber.h"
#include "event_config.h"
#include "json_cfg.h"
#include "security_guard_utils.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "security_guard_log.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;

namespace OHOS {
bool ConfigDataManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    uint32_t modelId = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::set<int64_t> eventIds{eventId};
    ModelCfg modelCfg = {};
    EventCfg eventCfg = {};
    std::string table(reinterpret_cast<const char*>(data + offset), size - offset);
    ConfigDataManager::GetInstance().InsertModelMap(modelId, modelCfg);
    ConfigDataManager::GetInstance().InsertEventMap(eventId, eventCfg);
    ConfigDataManager::GetInstance().InsertModelToEventMap(modelId, eventIds);
    ConfigDataManager::GetInstance().InsertEventToTableMap(eventId, table);
    ConfigDataManager::GetInstance().GetEventIds(modelId);
    ConfigDataManager::GetInstance().GetAllEventIds();
    ConfigDataManager::GetInstance().GetAllModelIds();
    ConfigDataManager::GetInstance().GetModelConfig(modelId, modelCfg);
    ConfigDataManager::GetInstance().GetEventConfig(eventId, eventCfg);
    ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    return true;
}

bool ConfigManagerFuzzTest(const uint8_t* data, size_t size)
{
    ConfigManager::GetInstance().StartUpdate();
    return true;
}

bool EventConfigFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int)) {
        return false;
    }
    EventConfig config{};
    int mode = *(reinterpret_cast<const int *>(data));
    nlohmann::json jsonObj;
    EventCfg cfg{};
    std::vector<EventCfg> cfgs{cfg};
    config.Load(mode);
    config.Parse();
    config.Update();
    config.ParseEventConfig(cfgs, jsonObj);
    config.CacheEventConfig(cfgs);
    config.CacheEventToTable(cfgs);
    return true;
}

bool ModelConfigFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int)) {
        return false;
    }
    ModelConfig config{};
    int mode = *(reinterpret_cast<const int *>(data));
    nlohmann::json jsonObj;
    ModelCfg cfg = {};
    std::vector<ModelCfg> cfgs{cfg};
    config.Load(mode);
    config.Parse();
    config.Update();
    config.ParseModelConfig(cfgs, jsonObj);
    config.CacheModelConfig(cfgs);
    config.CacheModelToEvent(cfgs);
    return true;
}

void JsonConfigFuzzTest(const uint8_t* data, size_t size)
{
    uint64_t uint64 = static_cast<uint64_t>(size);
    int64_t int64 = static_cast<int64_t>(size);
    int32_t int32 = static_cast<int32_t>(size);
    std::vector<int32_t> vec32;
    std::vector<int64_t> vec64;
    std::string string(reinterpret_cast<const char*>(data), size);
    nlohmann::json jsonObj {
        { string, uint64 }
    };
    JsonCfg::Unmarshal(uint64, jsonObj, string);
    nlohmann::json jsonObj1 {
        { string, int64 }
    };
    JsonCfg::Unmarshal(int64, jsonObj1, string);
    nlohmann::json jsonObj2 {
        { string, {int32} }
    };
    JsonCfg::Unmarshal(vec32, jsonObj2, string);
    nlohmann::json jsonObj3 {
        { string, {int64} }
    };
    JsonCfg::Unmarshal(vec64, jsonObj3, string);
}

void SecurityGuardUtilsFuzzTest(const uint8_t* data, size_t size)
{
    int64_t int64 = static_cast<int64_t>(size);
    uint32_t uint32 = static_cast<uint32_t>(size);
    std::string string(reinterpret_cast<const char*>(data), size);
    unsigned long long value = 0;
    SecurityGuardUtils::StrToU32(string, uint32);
    SecurityGuardUtils::StrToI64(string, int64);
    SecurityGuardUtils::StrToULL(string, value);
    SecurityGuardUtils::CopyFile(string, string);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::ConfigDataManagerFuzzTest(data, size);
    OHOS::ConfigManagerFuzzTest(data, size);
    OHOS::EventConfigFuzzTest(data, size);
    OHOS::ModelConfigFuzzTest(data, size);
    OHOS::JsonConfigFuzzTest(data, size);
    OHOS::SecurityGuardUtilsFuzzTest(data, size);
    return 0;
}
