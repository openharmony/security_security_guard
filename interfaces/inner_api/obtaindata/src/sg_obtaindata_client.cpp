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

#include "obtaindata_callback.h"
#include "obtaindata_callback_stub.h"
#include "obtaindata_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "sg_obtaindata_client.h"

namespace OHOS::Security::SecurityGuard {
int32_t ObtainDataKit::RequestSecurityEventInfoAsync(std::string &devId, std::string &eventList,
    std::shared_ptr<RequestSecurityEventInfoCallback> &callback)
{
    auto func = [callback] (std::string &devId, std::string &riskData, uint32_t status)-> int32_t {
        return callback->OnSecurityEventInfoResult(devId, riskData, status);
    };
    return RequestSecurityEventInfo(devId, eventList, func);
}

int32_t ObtainDataKit::RequestSecurityEventInfo(std::string &devId, std::string &eventList,
    RequestRiskDataCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return {};
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = new (std::nothrow) ObtainDataProxy(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    OHOS::sptr<ObtainDataCallbackStub> stub = new (std::nothrow) ObtainDataCallbackStub(callback);
    if (stub == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestRiskData(devId, eventList, stub);
    if (ret != 0) {
        SGLOGE("RequestSecurityEventInfo error, ret=%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}
}

