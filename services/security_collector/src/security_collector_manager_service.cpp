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

#include "security_collector_manager_service.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "data_collection.h"
#include "sg_collect_client.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_manager_callback_proxy.h"

namespace OHOS::Security::SecurityCollector {
namespace {
constexpr char PERMISSION[] = "ohos.permission.securityguard.REPORT_SECURITY_INFO";
constexpr char NOTIFY_APP_NAME[] = "security_guard";
std::string GetAppName()
{
    AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        AccessToken::HapTokenInfo hapTokenInfo;
        int ret = AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        if (ret != 0) {
            LOGE("failed to get hap token info, result = %{public}d", ret);
            return "";
        }
        return hapTokenInfo.bundleName;
    } else if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        AccessToken::NativeTokenInfo nativeTokenInfo;
        int ret = AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
        if (ret != 0) {
            LOGE("failed to get native token info, result = %{public}d", ret);
            return "";
        }
        return nativeTokenInfo.processName;
    }
    LOGE("failed to get app name");
    return "";
}

bool HasPermission()
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        return false;
    }
    return true;
}
}

REGISTER_SYSTEM_ABILITY_BY_ID(SecurityCollectorManagerService, SECURITY_COLLECTOR_MANAGER_SA_ID, true);

SecurityCollectorManagerService::SecurityCollectorManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    LOGW("%{public}s", __func__);
}

void SecurityCollectorManagerService::OnStart()
{
    LOGI("%{public}s", __func__);
    if (!Publish(this)) {
        LOGE("Publish error");
    }

    auto handler = [this] (const sptr<IRemoteObject> &remote) { CleanSubscriber(remote); };
    SecurityCollectorSubscriberManager::GetInstance().SetUnsubscribeHandler(handler);
}

void SecurityCollectorManagerService::OnStop()
{
}

int SecurityCollectorManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    return 0;
}

void SecurityCollectorManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
}

void SecurityCollectorManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    LOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

int32_t SecurityCollectorManagerService::Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    LOGI("In subscribe, eventId:%{public}ld", subscribeInfo.GetEvent().eventId);
    Event event = subscribeInfo.GetEvent();
    LOGE("xxxx subscribinfo:  duration:%{public}ld, isNotify:%{public}d, \n"
        "eventid:%{public}ld, version:%{public}s, content:%{public}s, extra:%{public}s,",
        subscribeInfo.GetDuration(), (int)subscribeInfo.IsNotify(),
        event.eventId, event.version.c_str(), event.content.c_str(), event.extra.c_str());

    if (!HasPermission()) {
        LOGE("caller no permission");
        return NO_PERMISSION;
    }
    std::string appName = (subscribeInfo.IsNotify() ? NOTIFY_APP_NAME : GetAppName());
    if (appName.empty()) {
        return BAD_PARAM;
    }
    if (appName != NOTIFY_APP_NAME && !SetDeathRecipient(callback)) {
        return NULL_OBJECT;
    }
    auto eventHandler = [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {
        LOGE("xxxx OnChange eventid:%{public}ld ", event.eventId);
        if (appName == NOTIFY_APP_NAME) {
            LOGI(" xxxx report to SG ");
            auto reportEvent = [event] () {
                auto info = std::make_shared<SecurityGuard::EventInfo>(event.eventId, event.version, event.content);
                (void)SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
            };
            reportEvent();
            return;
        }
        auto proxy = iface_cast<SecurityCollectorManagerCallbackProxy>(remote);
        if (proxy != nullptr) {
            LOGI(" xxxx report to proxy");
            proxy->OnNotify(event);
        } else {
            LOGE("report proxy is null");
        }
    };
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(appName, subscribeInfo, callback, eventHandler);
    if (!SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber)) {
        UnsetDeathRecipient(callback);
        return BAD_PARAM;
    }
    LOGI("Out subscribe");
    return SUCCESS;
}

int32_t SecurityCollectorManagerService::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    LOGI("In unubscribe");
    if (!HasPermission()) {
        LOGE("caller no permission");
        return NO_PERMISSION;
    }
    CleanSubscriber(callback);
    LOGI("Out unubscribe");
    return SUCCESS;
}

void SecurityCollectorManagerService::CleanSubscriber(const sptr<IRemoteObject> &remote)
{
    LOGI("Clean Subscribe ");
    UnsetDeathRecipient(remote);
    SecurityCollectorSubscriberManager::GetInstance().UnsubscribeCollector(remote);
}

bool SecurityCollectorManagerService::SetDeathRecipient(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient(this);
        if (deathRecipient_ == nullptr) {
            LOGE("no memory");
            return false;
        }
    }
    remote->AddDeathRecipient(deathRecipient_);
    return true;
}

void SecurityCollectorManagerService::UnsetDeathRecipient(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ != nullptr) {
        remote->RemoveDeathRecipient(deathRecipient_);
    }
}

void SecurityCollectorManagerService::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    LOGE("xxxx In");
    if (remote == nullptr) {
        LOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        LOGE("object is nullptr");
        return;
    }
    sptr<SecurityCollectorManagerService> service = service_.promote();
    if (service == nullptr) {
        LOGE("service is nullptr");
        return;
    }
    service->CleanSubscriber(object);
    LOGE("xxxx out");
}
}