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

#ifndef SECURITY_GUARD_RISK_ANALYSIS_MANAGER_SERVICE_H
#define SECURITY_GUARD_RISK_ANALYSIS_MANAGER_SERVICE_H

#include "nocopyable.h"
#include "system_ability.h"

#include "risk_analysis_manager_stub.h"

namespace OHOS::Security::SecurityGuard {
class RiskAnalysisManagerService : public SystemAbility, public RiskAnalysisManagerStub, public NoCopyable {
DECLARE_SYSTEM_ABILITY(RiskAnalysisManagerService);

public:
    RiskAnalysisManagerService(int32_t saId, bool runOnCreate);
    ~RiskAnalysisManagerService() override = default;
    void OnStart() override;
    void OnStop() override;
    int32_t RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
        const std::string &param, const sptr<IRemoteObject> &callback) override;
    int32_t SetModelState(uint32_t modelId, bool enable) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    void PushRiskAnalysisTask(uint32_t modelId, std::string param, std::shared_ptr<std::promise<std::string>> promise);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RISK_ANALYSIS_MANAGER_SERVICE_H
