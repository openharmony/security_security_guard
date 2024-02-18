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

#include <set>

#include "security_guard_sdk_adaptor.h"

#include "iservice_registry.h"

#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_proxy.h"
#include "i_data_collect_manager.h"
#include "i_risk_analysis_manager.h"
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_proxy.h"
#include "security_collector_manager_callback_service.h"
#include "security_collector_manager_proxy.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "collector_service_loader.h"

namespace OHOS::Security::SecurityGuard {
namespace  { const std::set<int64_t> GRANTED_EVENT{1037000001, 1064001001}; }

int32_t SecurityGuardSdkAdaptor::RequestSecurityEventInfo(std::string &devId, std::string &eventList,
    RequestRiskDataCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerProxy>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) DataCollectManagerCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestRiskData(devId, eventList, obj);
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityEventInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t SecurityGuardSdkAdaptor::RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, ResultCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
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
    int32_t ret = proxy->RequestSecurityModelResult(devId, modelId, param, stub);
    SGLOGI("RequestSecurityModelResult result, ret=%{public}d", ret);
    return ret;
}

int32_t SecurityGuardSdkAdaptor::ReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    if (info == nullptr) {
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerProxy>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is nullptr");
        return NULL_OBJECT;
    }
    int64_t eventId = info->GetEventId();
    std::string version = info->GetVersion();
    std::string content = info->GetContent();
    std::string date = SecurityGuardUtils::GetDate();
    int32_t ret = proxy->RequestDataSubmit(eventId, version, date, content);
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t SecurityGuardSdkAdaptor::SetModelState(uint32_t modelId, bool enable)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID);
    auto proxy = iface_cast<RiskAnalysisManagerProxy>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->SetModelState(modelId, enable);
    SGLOGI("SetModelState result, ret=%{public}d", ret);
    return ret;
}

int32_t SecurityGuardSdkAdaptor::NotifyCollector(const SecurityCollector::Event &event, int64_t duration)
{
    SGLOGI("On NotifyCollector...");
    if (GRANTED_EVENT.find(event.eventId) == GRANTED_EVENT.end()) {
        SGLOGE("NotifyCollector error event id %{public}" PRId64 ", can not Notify", event.eventId);
        return BAD_PARAM;
    }
    auto object = SecurityCollector::CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<SecurityCollector::ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->Subscribe(subscriberInfo, callback);
    SGLOGI("NotifyCollector result, ret=%{public}d", ret);
    return ret;
}
} // OHOS::Security::SecurityGuard