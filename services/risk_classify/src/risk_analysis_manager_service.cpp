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

#include "risk_analysis_manager_service.h"

#include <thread>

#include "model_manager.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(RiskAnalysisManagerService, RISK_ANALYSIS_MANAGER_SA_ID, true);

RiskAnalysisManagerService::RiskAnalysisManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void RiskAnalysisManagerService::OnStart()
{
    SGLOGI("RiskAnalysisManagerService %{public}s", __func__);
    if (!Publish(this)) {
        SGLOGE("Publish error");
    }
    ModelManager::GetInstance().InitModel();
}

void RiskAnalysisManagerService::OnStop()
{
}
}
