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

#include "security_collector_run_manager.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "data_collection.h"
#include "event_info.h"
#include "sg_collect_client.h"

namespace OHOS::Security::SecurityCollector {
SecurityCollectorRunManager::SecurityCollectorRunManager()
{
}

std::string SecurityCollectorRunManager::CollectorListenner::GetExtraInfo()
{
    if (subscriber_) {
        return subscriber_->GetSecurityCollectorSubscribeInfo().GetEvent().extra;
    }
    return {};
}

void SecurityCollectorRunManager::CollectorListenner::OnNotify(const Event &event)
{
    LOGI("eventid:%{public}" PRId64 " report by collector, store to db", event.eventId);
    auto info = std::make_shared<SecurityGuard::EventInfo>(event.eventId, event.version, event.content);
    (void)SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
}

bool SecurityCollectorRunManager::StartCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(collectorRunMutex_);
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return false;
    }
    std::string appName = subscriber->GetAppName();
    int64_t eventId = subscriber->GetSecurityCollectorSubscribeInfo().GetEvent().eventId;
    LOGI("appName:%{public}s, eventId:%{public}" PRId64 "", appName.c_str(), eventId);
    if (collectorRunManager_.find(eventId) != collectorRunManager_.end()) {
        LOGE("collector already start");
        return false;
    }
    
    auto collectorListenner = std::make_shared<SecurityCollectorRunManager::CollectorListenner>(subscriber);
    LOGI("start collector, eventId:%{public}" PRId64 "", eventId);
    if (!DataCollection::GetInstance().StartCollectors(std::vector<int64_t>{eventId}, collectorListenner)) {
        LOGE("failed to start collectors");
        return false;
    }
    collectorRunManager_.emplace(eventId, subscriber);
    return true;
}

bool SecurityCollectorRunManager::StopCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber)
{
    std::lock_guard<std::mutex> lock(collectorRunMutex_);
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return false;
    }
    std::string appName = subscriber->GetAppName();
    int64_t eventId = subscriber->GetSecurityCollectorSubscribeInfo().GetEvent().eventId;
    LOGI("appName:%{public}s, eventId:%{public}" PRId64 "", appName.c_str(), eventId);
    if (collectorRunManager_.find(eventId) == collectorRunManager_.end()) {
        LOGE("collector no start");
        return false;
    }
    
    if (collectorRunManager_[eventId]->GetAppName() != appName) {
        LOGE("collector starter is %{public}s, but stoper is %{public}s",
            collectorRunManager_[eventId]->GetAppName().c_str(), appName.c_str());
        return false;
    }
    LOGI("Scheduling stop collector, eventId:%{public}" PRId64 "", eventId);
    if (!DataCollection::GetInstance().StopCollectors(std::vector<int64_t>{eventId})) {
        LOGE("failed to stop collectors");
        return false;
    }
    collectorRunManager_.erase(eventId);
    return true;
}
}