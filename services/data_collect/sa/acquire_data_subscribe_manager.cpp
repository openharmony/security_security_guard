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

#include "acquire_data_subscribe_manager.h"

#include "acquire_data_callback_proxy.h"
#include "database_manager.h"
#include "security_guard_define.h"
#include "security_collector_subscribe_info.h"
#include "security_guard_log.h"
#include "task_handler.h"
#include "event_define.h"

namespace OHOS::Security::SecurityGuard {
AcquireDataSubscribeManager& AcquireDataSubscribeManager::GetInstance()
{
    static AcquireDataSubscribeManager instance;
    return instance;
}

AcquireDataSubscribeManager::AcquireDataSubscribeManager() : listener_(std::make_shared<DbListener>()) {}

int AcquireDataSubscribeManager::InsertSubscribeRecord(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback)
{
    int32_t code = DatabaseManager::GetInstance().SubscribeDb({subscribeInfo.GetEvent().eventId}, listener_);
    if (code != SUCCESS) {
        return code;
    }
    eventIdToSubscriberMap_[subscribeInfo.GetEvent().eventId].insert(callback);

    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeRecord(const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = eventIdToSubscriberMap_.begin(); iter != eventIdToSubscriberMap_.end();) {
        auto iterSet = iter->second.find(callback);
        if (iterSet == iter->second.end()) {
            ++iter;
            continue;
        }
        iter->second.erase(iterSet);
        if (iter->second.empty()) {
            int ret = DatabaseManager::GetInstance().UnSubscribeDb({iter->first}, listener_);
            if (ret != SUCCESS) {
                return ret;
            }
            iter = eventIdToSubscriberMap_.erase(iter);
            continue;
        }
        ++iter;
    }
    return SUCCESS;
}

bool AcquireDataSubscribeManager::Publish(const SecEvent &events)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = eventIdToSubscriberMap_.find(events.eventId);
    if (iter == eventIdToSubscriberMap_.end()) {
        return true;
    }
    auto listerers = iter->second;
    for (const auto &listener : listerers) {
        auto proxy = iface_cast<AcquireDataCallbackProxy>(listener);
        if (proxy == nullptr) {
            return false;
        }
        SecurityCollector::Event event {
            .eventId = events.eventId,
            .version = events.version,
            .content = events.content
        };
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
    }
    return true;
}

void AcquireDataSubscribeManager::DbListener::OnChange(uint32_t optType, const SecEvent &events)
{
    AcquireDataSubscribeManager::GetInstance().Publish(events);
}
}