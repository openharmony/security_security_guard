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

#ifndef SECURITY_GUARD_MODEL_CONFIG_H
#define SECURITY_GUARD_MODEL_CONFIG_H

#include "model_cfg_marshalling.h"

namespace OHOS::Security::SecurityGuard {
class ModelConfig {
public:
    explicit ModelConfig(const ModelCfgSt &config);
    uint32_t GetModelId() const;
    const std::string &GetModelName() const;
    uint32_t GetVersion() const;
    const std::vector<uint32_t> &GetThreatList() const;
    const std::string &GetComputeModel() const;

private:
    uint32_t modelId_;
    std::string modelName_;
    uint32_t version_;
    std::vector<uint32_t> threatList_;
    std::string computeModel_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_CONFIG_H
