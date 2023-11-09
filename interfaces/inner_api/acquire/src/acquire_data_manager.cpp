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
#include "acquire_data_manager.h"

#include "iservice_registry.h"
#include "data_collect_manager_proxy.h"
#include "acquire_data_manager_callback_service.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
void AcquireDataManager::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        SGLOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return;
    }
    object->RemoveDeathRecipient(this);
    AcquireDataManager::GetInstance().HandleDecipient();
}

void AcquireDataManager::HandleDecipient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = nullptr;
}

int32_t AcquireDataManager::Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
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

    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) DeathRecipient();
        if (deathRecipient_ == nullptr) {
            SGLOGE("deathRecipient_ is nullptr.");
            return NULL_OBJECT;
        }
    }

    if (!object->AddDeathRecipient(deathRecipient_)) {
        SGLOGE("Failed to add death recipient");
    }

    sptr<AcquireDataManagerCallbackService> callback = new (std::nothrow) AcquireDataManagerCallbackService(subscriber);
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), callback);
    SGLOGI("Subscribe result, ret=%{public}d", ret);
    callback_ = callback;
    return ret;
}

int32_t AcquireDataManager::Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(mutex_);
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

    int32_t ret = proxy->Unsubscribe(callback_);
    SGLOGI("Unsubscribe result, ret=%{public}d", ret);
    callback_ = nullptr;
    return ret;
}
}