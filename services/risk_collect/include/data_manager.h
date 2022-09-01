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

#ifndef SECURITY_GUARD_DATA_MANAGER_H
#define SECURITY_GUARD_DATA_MANAGER_H

#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

#include "base_event_id.h"
#include "base_event_id_storage.h"
#include "database.h"
#include "event_config.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataManager {
public:
    DataManager() = delete;
    explicit DataManager(std::shared_ptr<DataStorage> storage);
    ~DataManager() = default;
    ErrorCode LoadCacheData();
    ErrorCode AddCollectInfo(const EventDataSt &eventData);
    ErrorCode GetCollectInfoById(const std::string &id, ICollectInfo &info);
    ErrorCode GetEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData);
    ErrorCode GetCachedEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData);
    ErrorCode DeleteKvStore();

private:
    ErrorCode CacheData(std::shared_ptr<ICollectInfo> &info, std::shared_ptr<EventConfig> &config);
    std::map<std::string, std::string> eventIdToCacheDataMap_;
    std::mutex mapMutex_;
    std::shared_ptr<DataStorage> storage_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_MANAGER_H
