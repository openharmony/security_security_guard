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

#include "sg_obtaindata_client.h"

#include "iservice_registry.h"
#include "securec.h"

#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

using namespace OHOS;
using namespace OHOS::Security::SecurityGuard;

static std::mutex g_mutex;

static int32_t RequestSecurityEventInfo(std::string &devId, std::string &eventList,
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
    if (ret != 0) {
        SGLOGE("RequestSecurityEventInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

static int32_t RequestSecurityEventInfoAsyncImpl(const DeviceIdentify *devId, const char *eventJson,
    RequestSecurityEventInfoCallBack callback)
{
    if (devId == nullptr || eventJson == nullptr || devId->length >= DEVICE_ID_MAX_LEN) {
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
    std::string identity(reinterpret_cast<const char *>(tmp));
    std::string eventList(eventJson);
    auto func = [callback] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg)-> int32_t {
        SGLOGI("riskData=%{public}s, status=%{public}u, errMsg=%{public}s", riskData.c_str(), status, errMsg.c_str());
        if (devId.length() >= DEVICE_ID_MAX_LEN) {
            return BAD_PARAM;
        }

        struct DeviceIdentify identity;
        (void) memset_s(&identity, sizeof(DeviceIdentify), 0, sizeof(DeviceIdentify));
        errno_t rc = memcpy_s(identity.identity, DEVICE_ID_MAX_LEN, devId.c_str(), devId.length());
        if (rc != EOK) {
            return NULL_OBJECT;
        }
        identity.length = devId.length();
        callback(&identity, riskData.c_str(), status);
        return SUCCESS;
    };
    return RequestSecurityEventInfo(identity, eventList, func);
}


#ifdef __cplusplus
extern "C" {
#endif

int32_t RequestSecurityEventInfoAsync(const DeviceIdentify *devId, const char *eventJson,
    RequestSecurityEventInfoCallBack callback)
{
    return RequestSecurityEventInfoAsyncImpl(devId, eventJson, callback);
}

#ifdef __cplusplus
}
#endif