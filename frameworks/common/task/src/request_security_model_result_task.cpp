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

#include "request_security_model_result_task.h"

#include <vector>

#include "model_manager.h"
#include "risk_analysis_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
RequestSecurityModelResultTask::RequestSecurityModelResultTask(std::string &devId, int32_t modelId,
    TaskCallback callback)
    : BaseTask(std::move(callback)),
      devId_(devId),
      modelId_(modelId)
{
}

void RequestSecurityModelResultTask::OnExecute()
{
    SGLOGD("modelId=%{public}u", modelId_);
    std::vector<int64_t> eventIds = ModelManager::GetInstance().GetEventIds(modelId_);
    if (eventIds.empty()) {
        SGLOGE("eventIds is empty, no need to analyse");
        riskStatus_ = UNKNOWN_STATUS;
        callback_(shared_from_this());
        return;
    }

    int32_t ret = ModelManager::GetInstance().AnalyseRisk(eventIds);
    if (ret != SUCCESS) {
        SGLOGE("status is risk");
        riskStatus_ = RISK_STATUS;
    } else {
        SGLOGI("status is safe");
        riskStatus_ = SAFE_STATUS;
    }
    callback_(shared_from_this());
}

std::string RequestSecurityModelResultTask::GetDevId() const
{
    return devId_;
}

uint32_t RequestSecurityModelResultTask::GetModelId() const
{
    return modelId_;
}

std::string RequestSecurityModelResultTask::GetRiskStatus() const
{
    return riskStatus_;
}
}