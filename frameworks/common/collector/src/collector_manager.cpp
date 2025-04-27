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
#include "collector_manager.h"

#include "iservice_registry.h"
#include "security_collector_manager_proxy.h"
#include "security_collector_manager_callback_service.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "collector_service_loader.h"

namespace OHOS::Security::SecurityCollector {
int32_t CollectorManager::Subscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    LOGI("enter CollectorManager Subscribe");
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return BAD_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (eventListeners_.find(subscriber) != eventListeners_.end()) {
        LOGE("Already subscribed");
        return BAD_PARAM;
    }

    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) DeathRecipient();
        if (deathRecipient_ == nullptr) {
            LOGE("deathRecipient_ is null");
            return NULL_OBJECT;
        }
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        LOGE("Failed to add death recipient");
        return NULL_OBJECT;
    }

    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(subscriber);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), callback);
    if (ret == SUCCESS) {
        eventListeners_[subscriber] = callback;
    }
    LOGI("Subscribe result, ret=%{public}d", ret);
    return ret;
}

int32_t CollectorManager::Unsubscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    LOGI("enter CollectorManager Unsubscribe");
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return BAD_PARAM;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (eventListeners_.find(subscriber) == eventListeners_.end()) {
        LOGE("Not subscribed");
        return BAD_PARAM;
    }
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("Proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->Unsubscribe(eventListeners_[subscriber]);
    LOGI("Unsubscribe result, ret=%{public}d", ret);
    eventListeners_.erase(subscriber);
    return ret;
}

void CollectorManager::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        LOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        LOGE("object is nullptr");
        return;
    }
    object->RemoveDeathRecipient(this);
    CollectorManager::GetInstance().HandleDecipient();
}

void CollectorManager::HandleDecipient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    eventListeners_.clear();
}

int32_t CollectorManager::QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    LOGE("begin collector QuerySecurityEvent");
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->QuerySecurityEvent(rulers, events);
    if (ret != SUCCESS) {
        LOGI("QuerySecurityEvent failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("QuerySecurityEvent result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    LOGI("enter CollectorManager CollectorStart");
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->CollectorStart(subscriber, callback);
    if (ret != SUCCESS) {
        LOGI("CollectorStart failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("CollectorStart result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    LOGI("enter CollectorManager CollectorStart");
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->CollectorStop(subscriber, callback);
    if (ret != SUCCESS) {
        LOGI("CollectorStop failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("CollectorStop result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::AddFilter(const SecurityCollectorEventFilter &subscribeMute,
    const std::string &callbackFlag)
{
    LOGI("enter CollectorManager AddFilter");
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->AddFilter(subscribeMute, callbackFlag);
    if (ret != SUCCESS) {
        LOGI("AddFilter failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("AddFilter result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::RemoveFilter(const SecurityCollectorEventFilter &subscribeMute,
    const std::string &callbackFlag)
{
    LOGI("enter CollectorManager RemoveFilter");
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->RemoveFilter(subscribeMute, callbackFlag);
    if (ret != SUCCESS) {
        LOGI("RemoveFilter failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("RemoveFilter result, ret=%{public}d", ret);
    return SUCCESS;
}
}