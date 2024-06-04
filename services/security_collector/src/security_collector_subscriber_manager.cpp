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

#include "security_collector_subscriber_manager.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "data_collection.h"

namespace OHOS::Security::SecurityCollector {
namespace {
    constexpr int32_t MAX_APP_SUBSCRIBE_COUNT = 100;
}
SecurityCollectorSubscriberManager::SecurityCollectorSubscriberManager()
{
}

std::string SecurityCollectorSubscriberManager::CollectorListenner::GetExtraInfo()
{
    if (subscriber_) {
        return subscriber_->GetSecurityCollectorSubscribeInfo().GetEvent().extra;
    }
    return {};
}

void SecurityCollectorSubscriberManager::CollectorListenner::OnNotify(const Event &event)
{
    SecurityCollectorSubscriberManager::GetInstance().NotifySubscriber(event);
}

void SecurityCollectorSubscriberManager::NotifySubscriber(const Event &event)
{
    std::lock_guard<std::mutex> lock(collectorMutex_);
    LOGE("publish event: eventid:%{public}" PRId64 ", version:%{public}s, extra:%{public}s",
        event.eventId, event.version.c_str(), event.extra.c_str());
    const auto it = eventToSubscribers_.find(event.eventId);
    if (it == eventToSubscribers_.end()) {
        return;
    }
    for (const auto &subscriber : it->second) {
        if (subscriber != nullptr) {
            subscriber->OnChange(event);
        }
    }
}

int32_t SecurityCollectorSubscriberManager::GetAppSubscribeCount(const std::string &appName)
{
    int32_t count = 0;
    for (const auto &element : eventToSubscribers_) {
        const auto &subscribers = element.second;
        count = std::count_if(subscribers.begin(), subscribers.end(), [appName] (const auto &subscriber) {
            return subscriber->GetAppName() == appName;
        });
    }
    LOGI("subcirbipt count, appName=%{public}s, count=%{public}d", appName.c_str(), count);
    return count;
}

int32_t SecurityCollectorSubscriberManager::GetAppSubscribeCount(const std::string &appName, int64_t eventId)
{
    const auto &subscribers = eventToSubscribers_[eventId];
    if (std::any_of(subscribers.begin(), subscribers.end(), [appName] (const auto &subscriber) {
            return subscriber->GetAppName() == appName;
        })) {
        LOGI("subcirbipt count 1, appName=%{public}s, eventId:%{public}" PRId64 "", appName.c_str(), eventId);
        return 1;
    }
    LOGI("subcirbipt count 0, appName=%{public}s, eventId:%{public}" PRId64 "", appName.c_str(), eventId);
    return 0;
}

std::set<int64_t> SecurityCollectorSubscriberManager::FindEventIds(const sptr<IRemoteObject> &remote)
{
    std::set<int64_t> eventIds;
    for (const auto &element : eventToSubscribers_) {
        const auto &subscribers = element.second;
        auto it = std::find_if(subscribers.begin(), subscribers.end(),
            [remote] (const auto &subscriber) { return subscriber->GetRemote() == remote; });
        if (it != subscribers.end()) {
            LOGI("Find Event By Callback appName=%{public}s, eventId:%{public}" PRId64 "",
                 (*it)->GetAppName().c_str(), element.first);
            eventIds.emplace(element.first);
        }
    }
    return eventIds;
}

auto SecurityCollectorSubscriberManager::FindSecurityCollectorSubscribers(const sptr<IRemoteObject> &remote)
{
    std::set<std::shared_ptr<SecurityCollectorSubscriber>> subscribers;
    for (const auto &element : eventToSubscribers_) {
        auto it = std::find_if(element.second.begin(), element.second.end(),
            [remote] (const auto &d) { return d->GetRemote() == remote; });
        if (it != element.second.end()) {
            LOGI("Find Event Listenner appName=%{public}s, eventId:%{public}" PRId64 "",
                (*it)->GetAppName().c_str(), element.first);
            subscribers.emplace(*it);
        }
    }
    return subscribers;
}
bool SecurityCollectorSubscriberManager::SubscribeCollector(
    const std::shared_ptr<SecurityCollectorSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(collectorMutex_);
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return false;
    }
    std::string appName = subscriber->GetAppName();
    int64_t eventId = subscriber->GetSecurityCollectorSubscribeInfo().GetEvent().eventId;
    LOGI("appName:%{public}s, eventId:%{public}" PRId64 "", appName.c_str(), eventId);
    if (GetAppSubscribeCount(appName) >= MAX_APP_SUBSCRIBE_COUNT) {
        LOGE("Max count for app name:%{public}s", appName.c_str());
        return false;
    }
    if (GetAppSubscribeCount(appName, eventId) > 0) {
        LOGE("Already subscribed eventId:%{public}" PRId64 "", eventId);
        return false;
    }
    if (eventToListenner_.count(eventId) == 0) {
        auto collectorListenner = std::make_shared<SecurityCollectorSubscriberManager::CollectorListenner>(subscriber);
        LOGI("Scheduling start collector, eventId:%{public}" PRId64 "", eventId);
        if (!DataCollection::GetInstance().StartCollectors(std::vector<int64_t>{eventId}, collectorListenner)) {
            LOGE("failed to start collectors");
            return false;
        }
        eventToListenner_.emplace(eventId, collectorListenner);
    } else {
        LOGI("Scheduling do not start collecctor, eventId:%{public}" PRId64 "", eventId);
    }
    eventToSubscribers_[eventId].emplace(subscriber);
    LOGI("eventId:%{public}" PRId64 ", callbackCount:%{public}zu", eventId, eventToSubscribers_[eventId].size());
    int64_t duration = subscriber->GetSecurityCollectorSubscribeInfo().GetDuration();
    if (duration > 0) {
        auto remote = subscriber->GetRemote();
        auto timer = std::make_shared<CleanupTimer>();
        timers_.emplace(remote, timer);
        timer->Start(remote, duration);
    }
    return true;
}

bool SecurityCollectorSubscriberManager::UnsubscribeCollector(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(collectorMutex_);
    std::set<int64_t> eventIds = FindEventIds(remote);
    for (int64_t eventId : eventIds) {
        LOGI("Remove collecctor, eventId:%{public}" PRId64 "", eventId);
        if (eventId == -1) {
            LOGE("eventId is not found");
            return false;
        }
        auto subscribers = FindSecurityCollectorSubscribers(remote);
        if (subscribers.size() == 0) {
            LOGE("subscriber is null");
            return false;
        }
        for (auto subscriber: subscribers) {
            eventToSubscribers_[eventId].erase(subscriber);
            if (eventToSubscribers_[eventId].size() == 0) {
                LOGI("Scheduling stop collecctor, eventId:%{public}" PRId64 "", eventId);
                (void) DataCollection::GetInstance().StopCollectors(std::vector<int64_t>{eventId});
                eventToSubscribers_.erase(eventId);
                eventToListenner_.erase(eventId);
            }
        }
    }

    LOGI("erase timer befoe remoteObject");
    timers_.erase(remote);
    LOGI("erase timer after remoteObject");
    return true;
}

}