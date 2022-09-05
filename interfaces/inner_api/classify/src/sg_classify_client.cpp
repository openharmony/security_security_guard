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

#include "sg_classify_client.h"

#include "iremote_broker.h"
#include "iservice_registry.h"

#include "risk_analysis_manager_callback_stub.h"
#include "risk_analysis_manager_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
}

int32_t RiskAnalysisManagerKit::RequestSecurityModelResultSync(std::string &devId, uint32_t modelId,
    std::shared_ptr<SecurityModelResult> &result)
{
    auto promise = std::make_shared<std::promise<SecurityModel>>();
    auto future = promise->get_future();
    auto func = [cap = std::move(promise)] (std::string &devId, uint32_t modelId,
        std::string &result) mutable -> int32_t {
        SecurityModel model = {
            .devId = devId,
            .modelId = modelId,
            .result = result
        };
        cap->set_value(model);
        return SUCCESS;
    };

    int32_t code = RequestSecurityModelResult(devId, modelId, func);
    if (code != SUCCESS) {
        SGLOGE("RequestSecurityModelResult error, code=%{public}d", code);
        return code;
    }
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait timeout");
        return TIME_OUT;
    }
    SecurityModel model = future.get();
    result = std::make_shared<SecurityModelResult>(model.devId, model.modelId, model.result);
    SGLOGD("modelId=%{public}u, result=%{public}s", result->GetModelId(), result->GetResult().c_str());
    return SUCCESS;
}

int32_t RiskAnalysisManagerKit::RequestSecurityModelResultAsync(std::string &devId, uint32_t modelId,
    std::shared_ptr<RiskAnalysisManagerCallback> &callback)
{
    auto func = [callback] (std::string &devId, uint32_t modelId, std::string &result)-> int32_t {
        return callback->OnSecurityModelResult(devId, modelId, result);
    };

    return RequestSecurityModelResult(devId, modelId, func);
}

int32_t RiskAnalysisManagerKit::RequestSecurityModelResult(std::string &devId, uint32_t modelId,
    ResultCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return {};
    }

    auto object = registry->GetSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID);
    auto proxy = new (std::nothrow) RiskAnalysisManagerProxy(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    OHOS::sptr<RiskAnalysisManagerCallbackStub> stub = new (std::nothrow) RiskAnalysisManagerCallbackStub(callback);
    if (stub == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestSecurityModelResult(devId, modelId, stub);
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityModelResult error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
}
