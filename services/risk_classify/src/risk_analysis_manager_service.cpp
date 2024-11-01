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
#include "tokenid_kit.h"
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
#include "ffrt.h"
#include "config_manager.h"
#include "store_define.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(RiskAnalysisManagerService, RISK_ANALYSIS_MANAGER_SA_ID, true);

namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
    constexpr const char* PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT";
    constexpr const char* REQUEST_PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT";
    constexpr const char* QUERY_SECURITY_MODEL_RESULT_PERMISSION = "ohos.permission.QUERY_SECURITY_MODEL_RESULT";
    const std::vector<uint32_t> MODELIDS = {
        3001000000, 3001000001, 3001000002, 3001000005, 3001000006, 3001000007, 3001000009
    };
    const std::unordered_map<std::string, std::vector<std::string>> g_apiPermissionsMap {
        {"RequestSecurityModelResult", {REQUEST_PERMISSION, QUERY_SECURITY_MODEL_RESULT_PERMISSION}},
    };
}

RiskAnalysisManagerService::RiskAnalysisManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void RiskAnalysisManagerService::OnStart()
{
    SGLOGI("RiskAnalysisManagerService %{public}s", __func__);
    bool success = ConfigManager::InitConfig<EventConfig>();
    if (!success) {
        SGLOGE("init event config error");
    }
    success = ConfigManager::InitConfig<ModelConfig>();
    if (!success) {
        SGLOGE("init model config error");
    }

    auto task = [] {
        ModelManager::GetInstance().Init();
    };
    ffrt::submit(task);

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    if (!Publish(this)) {
        SGLOGE("Publish error");
    }
}

void RiskAnalysisManagerService::OnStop()
{
}

int32_t RiskAnalysisManagerService::IsApiHasPermission(const std::string &api)
{
    if (g_apiPermissionsMap.count(api) == 0) {
        SGLOGE("api not in map");
        return FAILED;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(g_apiPermissionsMap.at(api).cbegin(), g_apiPermissionsMap.at(api).cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
        if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
            uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
            if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
                SGLOGE("not system app no permission");
                return NO_SYSTEMCALL;
            }
        }
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

int32_t RiskAnalysisManagerService::RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter RiskAnalysisManagerService RequestSecurityModelResult");
    int32_t ret = IsApiHasPermission("RequestSecurityModelResult");
    if (ret != SUCCESS) {
        return ret;
    }
    ClassifyEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    auto promise = std::make_shared<std::promise<std::string>>();
    auto future = promise->get_future();
    PushRiskAnalysisTask(modelId, param, promise);
    std::chrono::milliseconds span(TIMEOUT_REPLY);
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
    auto task = [modelId, param, promise] {
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
    ffrt::submit(task);
}

int32_t RiskAnalysisManagerService::SetModelState(uint32_t modelId, bool enable)
{
    return SUCCESS;
}

void RiskAnalysisManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGI("OnAddSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        ConfigManager::GetInstance().StartUpdate();
    }
}

void RiskAnalysisManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}
}
