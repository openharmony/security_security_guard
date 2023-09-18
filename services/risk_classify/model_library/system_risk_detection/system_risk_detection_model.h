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

#ifndef SECURITY_GUARD_SYSTEM_RISK_DETECTION_MODEL_H
#define SECURITY_GUARD_SYSTEM_RISK_DETECTION_MODEL_H

#include "i_model.h"

#include "nlohmann/json.hpp"

namespace OHOS::Security::SecurityGuard {
class SystemRiskDetectionModel : public IModel {
public:
    ~SystemRiskDetectionModel() override;
    int32_t Init(std::shared_ptr<IModelManager> api) override;
    std::string GetResult(uint32_t modelId) override;
    int32_t SubscribeResult(std::shared_ptr<IModelResultListener> listener) override;
    void Release() override;

private:
    bool GetRuleResult(std::vector<bool> &ruleResult, const ModelCfg &cfg);
    void ReportResultEvent(uint32_t modelId, std::string result);
    std::shared_ptr<IDbOperate> dbOpt_;
    std::shared_ptr<IConfigOperate> cfgOpt_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SYSTEM_RISK_DETECTION_MODEL_H