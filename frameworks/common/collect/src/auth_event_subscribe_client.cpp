/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_event_subscribe_client.h"

#include <chrono>

#include "ffrt.h"
#include "iservice_registry.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager_idl.h"
#include "i_data_collect_manager.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
    ffrt::mutex g_clientMutex{};
    ffrt::mutex g_mutex_{};
    constexpr int RECONNECT_RETRY_DELAY_SECONDS[] = {1, 5, 15, 30, 60, 60, 60, 60, 60};
}

void AuthEventSubscribeClient::Deleter(AuthEventSubscribeClient *client)
{
    if (client == nullptr) {
        return;
    }
    // 在销毁服务端 client 之前，先排空在途 OnAuthEvent 并清空回调。
    // 本函数在最后一个 shared_ptr 释放时同步执行。当调用方把 client 作为对象成员时，
    // Deleter 在调用方析构函数内部执行，此时调用方内存仍然有效，
    // 在途回调可安全访问其状态；ClearCallBack 返回后不会再触发任何用户回调，
    // 随后销毁调用方状态即不存在 UAF。
    // 注意：若用户回调内部释放了最后一个 shared_ptr，会在此处等待自身持有的
    // notifyMutex_ 而死锁，调用方必须避免在回调内销毁 client。
    if (client->callback_ != nullptr) {
        client->callback_->ClearCallBack();
    }
    std::string clientId;
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        client->deleted_ = true;
        clientId = client->clientId_;
        client->clientId_ = "";
        deathRecipient = client->deathRecipient_;
    }
    if (!clientId.empty()) {
        auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (registry != nullptr) {
            auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
            auto proxy = iface_cast<DataCollectManagerIdl>(object);
            if (proxy != nullptr) {
                proxy->DestoryAuthEventClient(clientId);
            }
            if (object != nullptr && deathRecipient != nullptr) {
                object->RemoveDeathRecipient(deathRecipient);
            }
        }
    }
    delete client;
}

std::string AuthEventSubscribeClient::ConstructClientId(const AuthEventCallbackService *serviceCallback)
{
    std::string timeStr = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string ptrStr = std::to_string(reinterpret_cast<int64_t>(serviceCallback));
    std::size_t hash = std::hash<std::string>{}(timeStr + ptrStr);
    return std::to_string(hash);
}

int32_t AuthEventSubscribeClient::CreatClient(AuthEventCallback callback,
    std::shared_ptr<AuthEventSubscribeClient> &client, bool timeoutAllowFlag)
{
    SGLOGI("enter");
    std::lock_guard<ffrt::mutex> lock(g_clientMutex);
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return NULL_OBJECT;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    auto serviceCallback = new (std::nothrow) AuthEventCallbackService();
    if (serviceCallback == nullptr) {
        SGLOGE("serviceCallback is null");
        return NULL_OBJECT;
    }
    serviceCallback->RegistCallBack(callback);
    std::string clientId = ConstructClientId(serviceCallback);
    int32_t ret = proxy->CreatAuthEventClient(clientId, timeoutAllowFlag, serviceCallback);
    if (ret != SUCCESS) {
        SGLOGI("CreatAuthEventClient result, ret=%{public}d", ret);
        return ret;
    }
    client = std::shared_ptr<AuthEventSubscribeClient>(new AuthEventSubscribeClient(), Deleter);
    client->callback_ = serviceCallback;
    client->timeoutAllowFlag_ = timeoutAllowFlag;
    {
        std::lock_guard<ffrt::mutex> memberLock(g_mutex_);
        client->clientId_ = clientId;
    }
    ret = SetDeathRecipient(client, object);
    if (ret != SUCCESS) {
        SGLOGE("SetDeathRecipient fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t AuthEventSubscribeClient::SetDeathRecipient(std::shared_ptr<AuthEventSubscribeClient> client,
    const sptr<IRemoteObject> &remote)
{
    if (client->deathRecipient_ == nullptr) {
        client->deathRecipient_ = new (std::nothrow) DeathRecipient(client);
        if (client->deathRecipient_ == nullptr) {
            SGLOGE("deathRecipient_ is nullptr.");
            return NULL_OBJECT;
        }
        if (!remote->AddDeathRecipient(client->deathRecipient_)) {
            SGLOGE("Failed to add death recipient");
        }
    }
    return SUCCESS;
}

void AuthEventSubscribeClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("DataCollectManagerService died, try to recover AuthEventSubscribeClient state");
    auto client = client_.lock();
    if (client == nullptr) {
        SGLOGE("client is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object != nullptr) {
        object->RemoveDeathRecipient(this);
    }
    // avoid blocking binder thread
    ffrt::submit([client]() {client->HandleDeath();});
}

sptr<IRemoteObject> AuthEventSubscribeClient::ReconnectService()
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return nullptr;
    }
    sptr<IRemoteObject> object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr || deathRecipient_ == nullptr || !object->AddDeathRecipient(deathRecipient_)) {
        SGLOGE("Failed to reconnect service");
        return nullptr;
    }
    return object;
}

void AuthEventSubscribeClient::HandleDeath()
{
    std::set<int64_t> events;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        events = subscribedEventIds_;
        clientId_ = "";
    }
    for (int delay : RECONNECT_RETRY_DELAY_SECONDS) {
        ffrt::this_task::sleep_for(std::chrono::seconds(delay));
        {
            std::lock_guard<ffrt::mutex> lock(g_mutex_);
            if (deleted_) {
                SGLOGI("client deleted, stop reconnect");
                return;
            }
        }
        sptr<IRemoteObject> object = ReconnectService();
        if (object == nullptr) {
            continue;
        }
        auto proxy = iface_cast<DataCollectManagerIdl>(object);
        if (proxy == nullptr || callback_ == nullptr) {
            SGLOGE("proxy or callback is null");
            continue;
        }
        // 服务端重启后会话丢失，重新生成 clientId 重建会话
        std::string newClientId = ConstructClientId(callback_.GetRefPtr());
        int32_t ret = proxy->CreatAuthEventClient(newClientId, timeoutAllowFlag_, callback_);
        if (ret != SUCCESS) {
            SGLOGE("ReCreatClient fail, ret=%{public}d", ret);
            continue;
        }
        {
            std::lock_guard<ffrt::mutex> lock(g_mutex_);
            if (deleted_) {
                SGLOGI("client deleted during reconnect, discard new session");
                proxy->DestoryAuthEventClient(newClientId);
                return;
            }
            clientId_ = newClientId;
        }
        for (int64_t eventId : events) {
            int32_t code = proxy->SubscribeAuthEvent(eventId, newClientId);
            if (code != SUCCESS) {
                SGLOGE("ReSubscribe fail, eventId=%{public}lld, ret=%{public}d",
                    static_cast<long long>(eventId), code);
            }
        }
        return;
    }
    SGLOGE("recover AuthEventSubscribeClient fail");
}

int32_t AuthEventSubscribeClient::Subscribe(int64_t eventId)
{
    SGLOGI("enter");
    std::string clientId;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        clientId = clientId_;
    }
    if (clientId.empty()) {
        SGLOGE("client not created");
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->SubscribeAuthEvent(eventId, clientId);
    if (ret != SUCCESS) {
        SGLOGI("Subscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        subscribedEventIds_.insert(eventId);
    }
    return SUCCESS;
}

int32_t AuthEventSubscribeClient::Unsubscribe(int64_t eventId)
{
    SGLOGI("enter");
    std::string clientId;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        clientId = clientId_;
    }
    if (clientId.empty()) {
        SGLOGE("client not created");
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->UnsubscribeAuthEvent(eventId, clientId);
    if (ret != SUCCESS) {
        SGLOGI("Unsubscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        subscribedEventIds_.erase(eventId);
    }
    return SUCCESS;
}

int32_t AuthEventSubscribeClient::SetAuthResult(const AuthEvent &event, bool allowFlag)
{
    SGLOGI("enter");
    std::string clientId;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        clientId = clientId_;
    }
    if (clientId.empty()) {
        SGLOGE("client not created");
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    return proxy->SetAuthResult(event, allowFlag, clientId);
}

void AuthEventSubscribeClient::DeleteClient()
{
    // 注意：禁止在用户回调内部（OnAuthEvent 触发的执行流）调用本接口，
    // 否则会因等待自身持有的 notifyMutex_ 而死锁。
    if (callback_ != nullptr) {
        callback_->ClearCallBack();
    }
    std::string clientId;
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        deleted_ = true;
        clientId = clientId_;
        clientId_ = "";
        deathRecipient = deathRecipient_;
    }
    if (clientId.empty()) {
        return;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        return;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy != nullptr) {
        proxy->DestoryAuthEventClient(clientId);
    }
    if (object != nullptr && deathRecipient != nullptr) {
        object->RemoveDeathRecipient(deathRecipient);
    }
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
