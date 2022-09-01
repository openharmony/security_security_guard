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

#include "data_manager.h"

#include <vector>

#include "model_analysis.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t ONLY_ONE_SIZE = 1;
    constexpr int64_t GET_ALL_EVENT_ID = -1;
}

DataManager::DataManager(std::shared_ptr<DataStorage> storage)
    : storage_(storage)
{
}

ErrorCode DataManager::LoadCacheData()
{
    if (storage_ == nullptr) {
        SGLOGE("store is nullptr");
        return NULL_OBJECT;
    }
    std::map<std::string, std::shared_ptr<ICollectInfo>> eventIdToDataMap;
    ErrorCode ret = storage_->LoadAllData(eventIdToDataMap);
    if (ret != SUCCESS) {
        SGLOGE("LoadAllData error");
        return ret;
    }

    for (auto &entry : eventIdToDataMap) {
        std::shared_ptr<EventConfig> config = std::make_shared<EventConfig>();
        int64_t value = 0;
        bool isSuccess = SecurityGuardUtils::StrToI64(entry.first, value);
        if (!isSuccess) {
            continue;
        }
        ErrorCode code = ModelAnalysis::GetInstance().GetEventConfig(value, config);
        if (code != SUCCESS) {
            SGLOGE("get config error, eventId=%{public}ld", value);
            continue;
        }
        SGLOGE("get config ok, eventId=%{public}ld", value);
        CacheData(entry.second, config);
    }
    return SUCCESS;
}

ErrorCode DataManager::AddCollectInfo(const EventDataSt& eventData)
{
    if (storage_ == nullptr) {
        SGLOGE("store is nullptr");
        return NULL_OBJECT;
    }
    BaseEventId info(eventData.eventId);
    ErrorCode code = storage_->GetCollectInfoById(info.GetPrimeKey(), info);
    if (code != SUCCESS) {
        SGLOGE("GetCollectInfoById error, code=%{public}u", code);
    }

    if (!info.Push(eventData)) {
        SGLOGW("the eventId %{public}ld push error", eventData.eventId);
        return FAILED;
    }
    code = storage_->AddCollectInfo(info);
    if (code != SUCCESS) {
        SGLOGE("AddCollectInfo error, code=%{public}u", code);
        return code;
    }

    std::vector<EventDataSt> cacheData;
    info.GetCacheData(cacheData);
    nlohmann::json json(cacheData);
    std::lock_guard<std::mutex> lock(mapMutex_);
    eventIdToCacheDataMap_[std::to_string(eventData.eventId)] = json.dump();
    return SUCCESS;
}

ErrorCode DataManager::GetCollectInfoById(const std::string &id, ICollectInfo &info)
{
    if (storage_ == nullptr) {
        SGLOGE("store is nullptr");
        return NULL_OBJECT;
    }
    return storage_->GetCollectInfoById(id, info);
}

ErrorCode DataManager::GetEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData)
{
    if (storage_ == nullptr) {
        SGLOGE("store is nullptr");
        return NULL_OBJECT;
    }

    // get all data
    if (eventIds.size() == ONLY_ONE_SIZE && eventIds[0] == GET_ALL_EVENT_ID) {
        std::map<std::string, std::shared_ptr<ICollectInfo>> eventIdToDataMap;
        ErrorCode ret = storage_->LoadAllData(eventIdToDataMap);
        if (ret != SUCCESS) {
            return ret;
        }
        SGLOGE("get all date");
        for (const auto& item : eventIdToDataMap) {
            std::shared_ptr<ICollectInfo> info = item.second;
            std::shared_ptr<BaseEventId> eventIdInfo = std::static_pointer_cast<BaseEventId>(info);
            std::vector<EventDataSt> data = eventIdInfo->GetEventVec();
            eventData.insert(eventData.end(), data.begin(), data.end());
        }
        return SUCCESS;
    }

    ErrorCode code = FAILED;
    for (int64_t eventId : eventIds) {
        BaseEventId info(eventId);
        code = storage_->GetCollectInfoById(std::to_string(eventId), info);
        if (code != SUCCESS) {
            SGLOGE("GetCollectInfoById error, code=%{public}u, continue", code);
            continue;
        }
        std::vector<EventDataSt> data = info.GetEventVec();
        eventData.insert(eventData.end(), data.begin(), data.end());
    }
    return code;
}

ErrorCode DataManager::GetCachedEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    for (int64_t eventId : eventIds) {
        auto it = eventIdToCacheDataMap_.find(std::to_string(eventId));
        if (it == eventIdToCacheDataMap_.end()) {
            SGLOGE("not find eventId, %{public}s", std::to_string(eventId).c_str());
            continue;
        }

        nlohmann::json jsonObj = nlohmann::json::parse(eventIdToCacheDataMap_[std::to_string(eventId)], nullptr, false);
        if (jsonObj.is_discarded()) {
            SGLOGE("json err eventId, %{public}ld", eventId);
            continue;
        }

        auto data = jsonObj.get<std::vector<EventDataSt>>();
        eventData.insert(eventData.end(), data.begin(), data.end());
    }
    return SUCCESS;
}

ErrorCode DataManager::CacheData(std::shared_ptr<ICollectInfo> &info, std::shared_ptr<EventConfig> &config)
{
    std::shared_ptr<BaseEventId> eventId = std::static_pointer_cast<BaseEventId>(info);
    std::vector<EventDataSt> vector;
    bool isSuccess = eventId->GetCacheData(vector);
    if (!isSuccess) {
        SGLOGE("get cache date error");
        return FAILED;
    }
    nlohmann::json json(vector);
    std::lock_guard<std::mutex> lock(mapMutex_);
    eventIdToCacheDataMap_[eventId->GetPrimeKey()] = json.dump();
    return SUCCESS;
}

ErrorCode DataManager::DeleteKvStore()
{
    if (storage_ == nullptr) {
        SGLOGE("store is nullptr");
        return NULL_OBJECT;
    }
    return storage_->DeleteKvStore();
}
}
