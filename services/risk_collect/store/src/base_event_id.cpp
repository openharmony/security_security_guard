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

#include "base_event_id.h"

#include "config_data_manager.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
BaseEventId::BaseEventId(int64_t eventId)
    : eventId_(eventId)
{
}

void BaseEventId::ToJson(nlohmann::json &jsonObj) const
{
    jsonObj = nlohmann::json(eventVec_);
}

void BaseEventId::FromJson(const nlohmann::json &jsonObj)
{
    eventVec_ = jsonObj.get<std::vector<EventDataSt>>();
}

std::string BaseEventId::ToString() const
{
    nlohmann::json json;
    ToJson(json);
    return json.dump();
}

std::string BaseEventId::GetPrimeKey() const
{
    return std::to_string(eventId_);
}

bool BaseEventId::Push(const EventDataSt &eventDataSt)
{
    if (eventDataSt.eventId != eventId_) {
        SGLOGE("eventId mismatch, eventId=%{public}ld", eventDataSt.eventId);
        return false;
    }

    EventCfg config;
    ConfigDataManager::GetInstance()->GetEventConfig(eventId_, config);
    uint32_t storageNum = config.storageRomNums;
    if (storageNum == 0) {
        SGLOGE("the eventId %{public}ld does not need to storage in config", eventId_);
        return false;
    }

    if (storageNum == static_cast<uint32_t>(eventVec_.size())) {
        SGLOGE("the eventId %{public}ld replace the oldest date", eventId_);
        ReplaceOldestData(eventDataSt);
        return true;
    }

    eventVec_.emplace_back(eventDataSt);
    return true;
}

void BaseEventId::ReplaceOldestData(const EventDataSt &eventDataSt)
{
    sort(eventVec_.begin(), eventVec_.end(),
        [] (const EventDataSt &a, const EventDataSt &b) -> bool {
            return a.date < b.date;
        });
    eventVec_[0] = eventDataSt;
}

bool BaseEventId::GetCacheData(std::vector<EventDataSt>& vector)
{
    vector.clear();
    EventCfg config;
    ConfigDataManager::GetInstance()->GetEventConfig(eventId_, config);
    uint32_t size = config.storageRamNums;
    if (size == 0) {
        SGLOGE("the eventId %{public}ld does not need to cache in config", eventId_);
        return false;
    }

    if (size > static_cast<uint32_t>(eventVec_.size())) {
        SGLOGE("the eventId %{public}ld does not enough to cache in config", eventId_);
        vector.assign(eventVec_.begin(), eventVec_.end());
        return true;
    }
    sort(eventVec_.begin(), eventVec_.end(),
        [] (const EventDataSt &a, const EventDataSt &b) -> bool {
            return a.date > b.date;
        });

    for (uint32_t index = 0; index < size; index++) {
        vector.emplace_back(eventVec_[index]);
    }

    return true;
}

const std::vector<EventDataSt> &BaseEventId::GetEventVec() const
{
    return eventVec_;
}
}