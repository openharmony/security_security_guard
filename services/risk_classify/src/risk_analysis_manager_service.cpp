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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

#include "bigdata.h"
#include "model_manager.h"
#include "risk_analysis_define.h"
#include "risk_analysis_manager_callback_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(RiskAnalysisManagerService, RISK_ANALYSIS_MANAGER_SA_ID, true);

namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
    const std::string PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT";
}

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

int32_t RiskAnalysisManagerService::RequestSecurityModelResult(std::string &devId, uint32_t modelId,
    const sptr<IRemoteObject> &callback)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
    SGLOGD("%{public}s", __func__);
    ClassifyEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetData();
    auto promise = std::make_shared<std::promise<std::string>>();
    auto future = promise->get_future();
    PushRiskAnalysisTask(modelId, promise, event);
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    ErrorCode ret;
    std::string result{};
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait for result timeout");
        ret = TIME_OUT;
    } else {
        result = future.get();
        ret =  SUCCESS;
    }
    SGLOGI("ReportClassifyEvent");
    BigData::ReportClassifyEvent(event);
    auto proxy = iface_cast<RiskAnalysisManagerCallbackProxy>(callback);
    if (proxy == nullptr) {
        return NULL_OBJECT;
    }
    proxy->ResponseSecurityModelResult(devId, modelId, result);
    SGLOGI("get analysis result=%{public}s", result.c_str());
    return ret;
}

void RiskAnalysisManagerService::PushRiskAnalysisTask(uint32_t modelId,
    std::shared_ptr<std::promise<std::string>> &promise, ClassifyEvent &event)
{
    TaskHandler::Task task = [modelId, &promise, &event] {
        SGLOGD("modelId=%{public}u", modelId);
        std::vector<int64_t> eventIds = ModelManager::GetInstance().GetEventIds(modelId);
        if (eventIds.empty()) {
            SGLOGE("eventIds is empty, no need to analyse");
            event.status = UNKNOWN_STATUS;
            promise->set_value(UNKNOWN_STATUS);
            return;
        }

        int32_t ret = ModelManager::GetInstance().AnalyseRisk(eventIds, event.eventInfo);
        if (ret != SUCCESS) {
            SGLOGE("status is risk");
            event.status = RISK_STATUS;
            promise->set_value(RISK_STATUS);
        } else {
            SGLOGI("status is safe");
            event.status = SAFE_STATUS;
            promise->set_value(SAFE_STATUS);
        }
    };
    TaskHandler::GetInstance()->AddTask(task);
}
}
