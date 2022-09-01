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

#include "model_config.h"

namespace OHOS::Security::SecurityGuard {
ModelConfig::ModelConfig(const ModelCfgSt &config)
    : modelId_(config.modelId),
    modelName_(config.modelName),
    version_(config.version),
    threatList_(config.threatList),
    computeModel_(config.computeModel)
{
}

uint32_t ModelConfig::GetModelId() const
{
    return modelId_;
}

const std::string &ModelConfig::GetModelName() const
{
    return modelName_;
}

uint32_t ModelConfig::GetVersion() const
{
    return version_;
}

const std::vector<uint32_t> &ModelConfig::GetThreatList() const
{
    return threatList_;
}

const std::string &ModelConfig::GetComputeModel() const
{
    return computeModel_;
}
}