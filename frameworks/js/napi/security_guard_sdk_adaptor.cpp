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
#include "security_event_query_callback_service.h"
#include "acquire_data_manager_callback_service.h"
#include "security_config_update_info.h"

namespace OHOS::Security::SecurityGuard {
namespace  {
    const std::set<int64_t> GRANTED_EVENT{1037000001, 1064001001, 1064001002};
    static std::mutex g_mutex;
}
sptr<IRemoteObject> SecurityGuardSdkAdaptor::object_ = nullptr;
std::map<std::shared_ptr<SecurityCollector::ICollectorSubscriber>,
        sptr<AcquireDataManagerCallbackService>> SecurityGuardSdkAdaptor::subscribers_ {};
std::mutex SecurityGuardSdkAdaptor::objMutex_;
int32_t SecurityGuardSdkAdaptor::RequestSecurityEventInfo(std::string &devId, std::string &eventList,
    RequestRiskDataCallback callback)
{
    auto proxy = LoadDataCollectManageService();
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
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<IDataCollectManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
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

int32_t SecurityGuardSdkAdaptor::StartCollector(const SecurityCollector::Event &event,
    int64_t duration)
{
    auto proxy = LoadDataCollectManageService();
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

    int32_t ret = proxy->CollectorStart(subscriberInfo, callback);
    SGLOGI("StartCollector result, ret=%{public}d", ret);
    return ret;
}

int32_t SecurityGuardSdkAdaptor::StopCollector(const SecurityCollector::Event &event)
{
    SGLOGD("in SecurityGuardSdkAdaptor StopCollector ************");
    auto proxy = LoadDataCollectManageService();
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, -1, true};
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->CollectorStop(subscriberInfo, callback);
    SGLOGI("StopCollector result, ret=%{public}d", ret);
    return ret;
}

int32_t SecurityGuardSdkAdaptor::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    std::shared_ptr<SecurityEventQueryCallback> callback)
{
    auto proxy = LoadDataCollectManageService();
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) SecurityEventQueryCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("obj is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->QuerySecurityEvent(rulers, obj);
    if (ret != SUCCESS) {
        SGLOGE("QuerySecurityEvent error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t SecurityGuardSdkAdaptor::Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    if (subscribers_.find(subscriber) != subscribers_.end()) {
        SGLOGE("the callback has been registered.");
        return BAD_PARAM;
    }
    auto proxy = LoadDataCollectManageService();
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) AcquireDataManagerCallbackService(subscriber);
    if (obj == nullptr) {
        SGLOGE("obj is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), obj);
    if (ret != SUCCESS) {
        SGLOGE("Subscribe error, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        subscribers_[subscriber] = obj;
    }
    return SUCCESS;
}

int32_t SecurityGuardSdkAdaptor::Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    auto iter = subscribers_.find(subscriber);
    if (iter == subscribers_.end()) {
        SGLOGE("the callback has not been registered.");
        return BAD_PARAM;
    }
    auto proxy = LoadDataCollectManageService();
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->Unsubscribe(subscribers_[subscriber]);
    if (ret != SUCCESS) {
        SGLOGE("Unsubscribe error, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        subscribers_.erase(iter);
    }
    return SUCCESS;
}

sptr<IDataCollectManager> SecurityGuardSdkAdaptor::LoadDataCollectManageService()
{
    std::lock_guard<std::mutex> lock(objMutex_);
    if (object_ != nullptr) {
        SGLOGI("object_ not null");
        return iface_cast<IDataCollectManager>(object_);
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return nullptr;
    }
    object_ = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    return iface_cast<IDataCollectManager>(object_);
}

int32_t SecurityGuardSdkAdaptor::ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &updateInfo)
{
    auto proxy = LoadDataCollectManageService();
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->ConfigUpdate(updateInfo);
    if (ret != SUCCESS) {
        SGLOGE("ConfigUpdate error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
} // OHOS::Security::SecurityGuard