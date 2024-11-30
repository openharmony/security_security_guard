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
namespace {
    constexpr uint32_t MAXRESUBCOUNTS = 3;
}
namespace OHOS::Security::SecurityGuard {

AcquireDataManager& AcquireDataManager::GetInstance()
{
    static AcquireDataManager instance;
    return instance;
};

AcquireDataManager::AcquireDataManager() : callback_(new (std::nothrow) AcquireDataManagerCallbackService())
{
    auto func = [this](const SecurityCollector::Event &event) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &iter : subscribers_) {
            if (iter->GetSubscribeInfo().GetEvent().eventId == event.eventId) {
                iter->OnNotify(event);
            }
        }
    };
    callback_->RegistCallBack(func);
}

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
    if (count_ >= MAXRESUBCOUNTS) {
        SGLOGE("reSubscriber too many times");
        return;
    }
    if (callback_ == nullptr) {
        SGLOGE("subscriber is nullptr");
        return;
    }
    std::set<std::shared_ptr<SecurityCollector::ICollectorSubscriber>> tmp {};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers_.swap(tmp);
    }
    for (const auto &iter : tmp) {
        int32_t ret = Subscribe(iter);
        if (ret != SUCCESS) {
            SGLOGI("Subscribe result, ret=%{public}d", ret);
            return;
        }
    }
    count_++;
}

int32_t AcquireDataManager::Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter AcquireDataManager Subscribe");
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    if (callback_ == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    if (subscribers_.count(subscriber) != 0) {
        SGLOGE("Already subscribed");
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

    if (!IsCurrentSubscriberEventIdExist(subscriber)) {
        int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), callback_);
        if (ret != SUCCESS) {
            SGLOGI("Subscribe result, ret=%{public}d", ret);
            return ret;
        }
    }
    subscribers_.insert(subscriber);
    SGLOGI("current subscrbe size %{public}zu", subscribers_.size());
    return SUCCESS;
}

int32_t AcquireDataManager::Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter AcquireDataManager Subscribe");
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    if (callback_ == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    if (subscribers_.count(subscriber) == 0) {
        SGLOGE("Not subscribed");
        return BAD_PARAM;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<IDataCollectManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    subscribers_.erase(subscriber);
    if (!IsCurrentSubscriberEventIdExist(subscriber)) {
        int32_t ret = proxy->Unsubscribe(subscriber->GetSubscribeInfo(), callback_);
        if (ret != SUCCESS) {
            subscribers_.insert(subscriber);
            return ret;
        }
        SGLOGI("Unsubscribe result, ret=%{public}d", ret);
    }
    SGLOGI("current subscrbe size %{public}zu", subscribers_.size());
    return SUCCESS;
}

bool AcquireDataManager::IsCurrentSubscriberEventIdExist(
    const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &sub)
{
    for (const auto &i : subscribers_) {
        if (i->GetSubscribeInfo().GetEvent().eventId == sub->GetSubscribeInfo().GetEvent().eventId) {
            return true;
        }
    }
    return false;
}
}