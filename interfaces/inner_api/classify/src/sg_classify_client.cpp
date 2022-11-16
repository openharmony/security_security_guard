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

#include <future>

#include "iremote_broker.h"
#include "iservice_registry.h"
#include "securec.h"

#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
}

using namespace OHOS;
using namespace OHOS::Security::SecurityGuard;

static std::mutex g_mutex;

static int32_t RequestSecurityModelResult(std::string &devId, uint32_t modelId,
    ResultCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return {};
    }

    auto object = registry->GetSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID);
    auto proxy = iface_cast<RiskAnalysisManagerProxy>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    sptr<RiskAnalysisManagerCallbackService> stub = new (std::nothrow) RiskAnalysisManagerCallbackService(callback);
    if (stub == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestSecurityModelResult(devId, modelId, stub);
    SGLOGI("RequestSecurityModelResult result, ret=%{public}d", ret);
    return ret;
}

static int32_t FillingRequestResult(const SecurityModel &model, SecurityModelResult *result)
{
    if (model.devId.length() >= DEVICE_ID_MAX_LEN || model.result.length() >= RESULT_MAX_LEN) {
        return BAD_PARAM;
    }

    result->modelId = model.modelId;
    errno_t rc = memcpy_s(result->devId.identity, DEVICE_ID_MAX_LEN, model.devId.c_str(), model.devId.length());
    if (rc != EOK) {
        return NULL_OBJECT;
    }
    result->devId.length = model.devId.length();

    rc = memcpy_s(result->result, RESULT_MAX_LEN, model.result.c_str(), model.result.length());
    if (rc != EOK) {
        return NULL_OBJECT;
    }
    result->resultLen = model.result.length();

    SGLOGD("modelId=%{public}u, result=%{public}s", model.modelId, model.result.c_str());
    return SUCCESS;
}

static int32_t RequestSecurityModelResultSyncImpl(const DeviceIdentify *devId,
    uint32_t modelId, SecurityModelResult *result)
{
    if (devId == nullptr || result == nullptr || devId->length >= DEVICE_ID_MAX_LEN) {
        return BAD_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    auto promise = std::make_shared<std::promise<SecurityModel>>();
    auto future = promise->get_future();
    auto func = [promise] (const std::string &devId, uint32_t modelId,
        const std::string &result) mutable -> int32_t {
        SecurityModel model = {
            .devId = devId,
            .modelId = modelId,
            .result = result
        };
        promise->set_value(model);
        return SUCCESS;
    };

    uint8_t tmp[DEVICE_ID_MAX_LEN] = {};
    (void) memset_s(tmp, DEVICE_ID_MAX_LEN, 0, DEVICE_ID_MAX_LEN);
    errno_t rc = memcpy_s(tmp, DEVICE_ID_MAX_LEN, devId->identity, devId->length);
    if (rc != EOK) {
        SGLOGE("identity memcpy error, code=%{public}d", rc);
        return NULL_OBJECT;
    }
    std::string identify(reinterpret_cast<const char *>(tmp));
    int32_t code = RequestSecurityModelResult(identify, modelId, func);
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
    return FillingRequestResult(model, result);
}

static int32_t RequestSecurityModelResultAsyncImpl(const DeviceIdentify *devId, uint32_t modelId,
    SecurityGuardRiskCallback callback)
{
    if (devId == nullptr || devId->length >= DEVICE_ID_MAX_LEN) {
        return BAD_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    uint8_t tmp[DEVICE_ID_MAX_LEN] = {};
    (void) memset_s(tmp, DEVICE_ID_MAX_LEN, 0, DEVICE_ID_MAX_LEN);
    errno_t rc = memcpy_s(tmp, DEVICE_ID_MAX_LEN, devId->identity, devId->length);
    if (rc != EOK) {
        SGLOGE("identity memcpy error, code=%{public}d", rc);
        return NULL_OBJECT;
    }
    std::string identify(reinterpret_cast<const char *>(tmp));
    auto func = [callback] (const std::string &devId, uint32_t modelId, const std::string &result)-> int32_t {
        if (devId.length() >= DEVICE_ID_MAX_LEN || result.length() >= RESULT_MAX_LEN) {
            return BAD_PARAM;
        }

        SecurityModelResult modelResult;
        (void) memset_s(&modelResult, sizeof(SecurityModelResult), 0, sizeof(SecurityModelResult));
        modelResult.modelId = modelId;
        errno_t rc = memcpy_s(modelResult.devId.identity, DEVICE_ID_MAX_LEN, devId.c_str(), devId.length());
        if (rc != EOK) {
            return NULL_OBJECT;
        }
        modelResult.devId.length = devId.length();
        rc = memcpy_s(modelResult.result, RESULT_MAX_LEN, result.c_str(), result.length());
        if (rc != EOK) {
            return NULL_OBJECT;
        }
        modelResult.resultLen = result.length();
        callback(&modelResult);
        return SUCCESS;
    };

    return RequestSecurityModelResult(identify, modelId, func);
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t RequestSecurityModelResultSync(const DeviceIdentify *devId, uint32_t modelId, SecurityModelResult *result)
{
    return RequestSecurityModelResultSyncImpl(devId, modelId, result);
}

int32_t RequestSecurityModelResultAsync(const DeviceIdentify *devId, uint32_t modelId,
    SecurityGuardRiskCallback callback)
{
    return RequestSecurityModelResultAsyncImpl(devId, modelId, callback);
}

#ifdef __cplusplus
}
#endif
