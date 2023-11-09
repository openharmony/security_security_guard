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

#include "risk_analysis_manager_callback_service.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerCallbackService::RiskAnalysisManagerCallbackService(ResultCallback &callback)
    : callback_(callback)
{
}

int32_t RiskAnalysisManagerCallbackService::ResponseSecurityModelResult(const std::string &devId,
    uint32_t modelId, std::string &result)
{
    SGLOGI("modelId=%{public}u, result=%{public}s", modelId, result.c_str());
    if (callback_ != nullptr) {
        callback_(devId, modelId, result);
    }
    return SUCCESS;
}
}