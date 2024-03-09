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
#include "database_manager.h"
#include "errors.h"
#include "model_manager.h"
#include "risk_analysis_define.h"
#include "risk_analysis_manager_callback_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "task_handler.h"
#include "model_manager.h"
#include "config_manager.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(RiskAnalysisManagerService, RISK_ANALYSIS_MANAGER_SA_ID, true);

namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
    const std::string PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT";
    const std::string SET_MODEL_PERMISSION = "ohos.permission.securityguard.SET_MODEL_STATE";
    const std::vector<uint32_t> MODELIDS = { 3001000000, 3001000001, 3001000002, 3001000005, 3001000006, 3001000007 };
    constexpr uint32_t AUDIT_MODEL_ID = 3001000003;
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
    bool success = ConfigManager::InitConfig<EventConfig>();
    if (!success) {
        SGLOGE("init event config error");
    }
    success = ConfigManager::InitConfig<ModelConfig>();
    if (!success) {
        SGLOGE("init model config error");
    }

    TaskHandler::Task task = [] {
        ModelManager::GetInstance().Init();
    };
    TaskHandler::GetInstance()->AddTask(task);

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
}

void RiskAnalysisManagerService::OnStop()
{
}

int32_t RiskAnalysisManagerService::RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, const sptr<IRemoteObject> &callback)
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
    event.time = SecurityGuardUtils::GetDate();
    auto promise = std::make_shared<std::promise<std::string>>();
    auto future = promise->get_future();
    PushRiskAnalysisTask(modelId, param, promise);
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
    event.status = result;
    BigData::ReportClassifyEvent(event);
    auto proxy = iface_cast<RiskAnalysisManagerCallbackProxy>(callback);
    if (proxy == nullptr) {
        return NULL_OBJECT;
    }
    proxy->ResponseSecurityModelResult(devId, modelId, result);
    SGLOGI("get analysis result=%{public}s", result.c_str());
    return ret;
}

void RiskAnalysisManagerService::PushRiskAnalysisTask(uint32_t modelId, std::string param,
    std::shared_ptr<std::promise<std::string>> promise)
{
    TaskHandler::Task task = [modelId, param, promise] {
        SGLOGD("modelId=%{public}u", modelId);
        if (std::count(MODELIDS.begin(), MODELIDS.end(), modelId) == 0) {
            SGLOGE("model not support, no need to analyse, modelId=%{public}u", modelId);
            promise->set_value(UNKNOWN_STATUS);
            return;
        }
        std::string result = ModelManager::GetInstance().GetResult(modelId, param);
        SGLOGI("result is %{public}s", result.c_str());
        promise->set_value(result);
    };
    TaskHandler::GetInstance()->AddTask(task);
}

int32_t RiskAnalysisManagerService::SetModelState(uint32_t modelId, bool enable)
{
    SGLOGI("begin set model state");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, SET_MODEL_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
    if (modelId != AUDIT_MODEL_ID) {
        return BAD_PARAM;
    }
    DatabaseManager::GetInstance().SetAuditState(enable);
    if (!enable) {
        ModelManager::GetInstance().Release(modelId);
        return SUCCESS;
    }

    int32_t ret = ModelManager::GetInstance().InitModel(modelId);
    if (ret != SUCCESS) {
        DatabaseManager::GetInstance().SetAuditState(false);
    }
    return ret;
}

void RiskAnalysisManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGI("OnAddSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        ConfigManager::GetInstance()->StartUpdate();
    }
}

void RiskAnalysisManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}
}
