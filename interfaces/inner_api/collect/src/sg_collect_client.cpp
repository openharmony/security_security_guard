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

#include "iservice_registry.h"

#include "data_collect_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "sg_collect_client.h"

namespace OHOS::Security::SecurityGuard {
int32_t NativeDataCollectKit::ReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        return {};
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = new (std::nothrow) DataCollectProxy(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is nullptr");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestDataSubmit(info);
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityInfo error, ret=%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}
}