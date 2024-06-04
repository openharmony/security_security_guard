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

#include "hisysevent.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "data_collection.h"
#include "sg_collect_client.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_manager_callback_proxy.h"
#include "task_handler.h"
#include "event_define.h"

namespace OHOS::Security::SecurityCollector {
namespace {
constexpr char PERMISSION[] = "ohos.permission.securityguard.REPORT_SECURITY_INFO";
constexpr char NOTIFY_APP_NAME[] = "security_guard";

const std::string CALLER_PID = "CALLER_PID";
const std::string EVENT_VERSION = "EVENT_VERSION";
const std::string SC_EVENT_ID = "EVENT_ID";
const std::string SUB_RET = "SUB_RET";
const std::string UNSUB_RET = "UNSUB_RET";

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
    Event event = subscribeInfo.GetEvent();
    LOGI("in subscribe, subscribinfo: duration:%{public}" PRId64 ", \n"
        "isNotify:%{public}d, eventid:%{public}" PRId64 ", \n"
        "version:%{public}s, extra:%{public}s", subscribeInfo.GetDuration(), (int)subscribeInfo.IsNotify(),
        event.eventId, event.version.c_str(), event.extra.c_str());

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
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {
        if (appName == NOTIFY_APP_NAME) {
            LOGI("eventid:%{public}" PRId64 " callback default", event.eventId);
            auto reportEvent = [event] () {
                auto info = std::make_shared<SecurityGuard::EventInfo>(event.eventId, event.version, event.content);
                (void)SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
            };
            reportEvent();
            return;
        }
        ExecuteOnNotifyByTask(remote, event);
    };
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(appName, subscribeInfo, callback, eventHandler);
    ScSubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.version = event.version;
    subEvent.eventId = event.eventId;

    if (!SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber)) {
        UnsetDeathRecipient(callback);
        subEvent.ret = BAD_PARAM;
        ReportScSubscribeEvent(subEvent);
        return BAD_PARAM;
    }
    subEvent.ret = SUCCESS;
    ReportScSubscribeEvent(subEvent);
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

    ScUnsubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.ret = SUCCESS;
    LOGI("SecurityCollectorManagerService, CleanSubscriber");
    ReportScUnsubscribeEvent(subEvent);

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
    LOGD("SecurityCollectorManagerService In");
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
    LOGD("SecurityCollectorManagerService out");
}

void SecurityCollectorManagerService::ReportScSubscribeEvent(const ScSubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SC_EVENT_SUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        EVENT_VERSION, event.version, SC_EVENT_ID, event.eventId, SUB_RET, event.ret);
}

void SecurityCollectorManagerService::ReportScUnsubscribeEvent(const ScUnsubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SC_EVENT_UNSUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid, UNSUB_RET, event.ret);
}

void SecurityCollectorManagerService::ExecuteOnNotifyByTask(const sptr<IRemoteObject> &remote, const Event &event)
{
    auto proxy = iface_cast<SecurityCollectorManagerCallbackProxy>(remote);
    if (proxy != nullptr) {
        LOGI("report to proxy");
        SecurityGuard::TaskHandler::Task task = [proxy, event] () {
            proxy->OnNotify(event);
        };
        if (event.eventId == SecurityCollector::FILE_EVENTID ||
            event.eventId == SecurityCollector::PROCESS_EVENTID ||
            event.eventId == SecurityCollector::NETWORK_EVENTID) {
            SecurityGuard::TaskHandler::GetInstance()->AddMinorsTask(task);
        } else {
            SecurityGuard::TaskHandler::GetInstance()->AddTask(task);
        }
    } else {
        LOGE("report proxy is null");
    }
}
}