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
#include "securec.h"

#include "data_collect_manager_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "sg_collect_client.h"

namespace OHOS::Security::SecurityGuard {
namespace {
int32_t ReportSecurityEvent(const std::shared_ptr<EventInfo> &info, bool isSync)
{
    if (info == nullptr) {
        return BAD_PARAM;
    }
    sptr<IDataCollectManager> proxy = SgCollectClient::GetInstance().GetProxy();
    if (proxy == nullptr) {
        return NULL_OBJECT;
    }

    int64_t eventId = info->GetEventId();
    std::string version = info->GetVersion();
    std::string content = info->GetContent();
    std::string date = SecurityGuardUtils::GetDate();
    int32_t ret = proxy->RequestDataSubmit(eventId, version, date, content, isSync);
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
}

SgCollectClient &SgCollectClient::GetInstance()
{
    static SgCollectClient instance;
    return instance;
}

sptr<IDataCollectManager> SgCollectClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}

void SgCollectClient::InitProxy()
{
    if (proxy_ == nullptr) {
        auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (registry == nullptr) {
            SGLOGE("registry is nullptr");
            return;
        }
        auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
        if (object == nullptr) {
            SGLOGE("object is nullptr");
            return;
        }
        proxy_ = iface_cast<IDataCollectManager>(object);
        if (proxy_ == nullptr) {
            SGLOGE("proxy is nullptr");
            return;
        }

        deathRecipient_ = new (std::nothrow) SgCollectClientDeathRecipient();
        if (deathRecipient_ != nullptr) {
            proxy_->AsObject()->AddDeathRecipient(deathRecipient_);
        }
    }
}

void SgCollectClient::ReleaseProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ != nullptr && proxy_->AsObject() != nullptr) {
        proxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
}

void SgCollectClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SgCollectClient::GetInstance().ReleaseProxy();
}

int32_t NativeDataCollectKit::ReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    return ReportSecurityEvent(info, true);
}

int32_t NativeDataCollectKit::ReportSecurityInfoAsync(const std::shared_ptr<EventInfo> &info)
{
    return ReportSecurityEvent(info, false);
}

int32_t NativeDataCollectKit::SecurityGuardConfigUpdate(int32_t fd, const std::string &name)
{
    sptr<IDataCollectManager> proxy = SgCollectClient::GetInstance().GetProxy();
    if (proxy == nullptr) {
        SGLOGE("proxy is nullptr");
        return NULL_OBJECT;
    }
    SecurityGuard::SecurityConfigUpdateInfo updateInfo(fd, name);
    int32_t ret = proxy->ConfigUpdate(updateInfo);
    if (ret != SUCCESS) {
        SGLOGE("ConfigUpdate error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

}  // namespace OHOS::Security::SecurityGuard

static int32_t ReportSecurityInfoImpl(const struct EventInfoSt *info, bool isSync)
{
    if (info == nullptr || info->contentLen >= CONTENT_MAX_LEN || info->version == nullptr) {
        return OHOS::Security::SecurityGuard::BAD_PARAM;
    }
    int64_t eventId = info->eventId;
    std::string version = reinterpret_cast<const char *>(info->version);
    uint8_t tmp[CONTENT_MAX_LEN] = {};
    (void)memset_s(tmp, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(tmp, CONTENT_MAX_LEN, info->content, info->contentLen);
    if (rc != EOK) {
        return OHOS::Security::SecurityGuard::NULL_OBJECT;
    }
    std::string content(reinterpret_cast<const char *>(tmp));
    auto eventInfo = std::make_shared<OHOS::Security::SecurityGuard::EventInfo>(eventId, version, content);
    if (isSync) {
        return OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    } else {
        return OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfoAsync(eventInfo);
    }
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t ReportSecurityInfo(const struct EventInfoSt *info)
{
    return ReportSecurityInfoImpl(info, true);
}

int32_t ReportSecurityInfoAsync(const struct EventInfoSt *info)
{
    return ReportSecurityInfoImpl(info, false);
}

int32_t SecurityGuardConfigUpdate(int32_t fd, const char *fileName)
{
    return OHOS::Security::SecurityGuard::NativeDataCollectKit::SecurityGuardConfigUpdate(fd, fileName);
}
#ifdef __cplusplus
}
#endif