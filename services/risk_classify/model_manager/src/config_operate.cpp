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

#include "config_operate.h"
#include "config_data_manager.h"

namespace OHOS::Security::SecurityGuard {
bool ConfigOperate::GetModelConfig(uint32_t modelId, ModelCfg &config)
{
    return ConfigDataManager::GetInstance().GetModelConfig(modelId, config);
}

bool ConfigOperate::GetEventConfig(int64_t eventId, EventCfg &config)
{
    return ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
}
} // namespace OHOS::Security::SecurityGuard