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
#include "iservice_registry.h"
#include "data_collect_manager.h"
#include "security_event_ruler.h"
#include "data_collect_manager_callback_service.h"
#include "security_event_query_callback_service.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t DataCollectManager::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
                                               std::shared_ptr<SecurityEventQueryCallback> callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return -1;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<IDataCollectManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return -1;
    }

    auto obj = new (std::nothrow) SecurityEventQueryCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("obj is null");
        return -1;
    }

    int32_t ret = proxy->QuerySecurityEvent(rulers, obj);
    if (ret != 0) {
        SGLOGE("QuerySecurityEvent error, ret=%{public}d", ret);
        return ret;
    }
    return 0;
}

int32_t DataCollectManager::QuerySecurityEventConfig(std::string &result)
{
    SGLOGI("Start DataCollectManager QuerySecurityEventConfig");
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return FAILED;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return FAILED;
    }
    auto proxy = iface_cast<IDataCollectManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return FAILED;
    }
    return proxy->QuerySecurityEventConfig(result);
}
}