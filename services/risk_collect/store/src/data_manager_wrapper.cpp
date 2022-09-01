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

#include "data_manager_wrapper.h"

#include <mutex>

#include "database_wrapper.h"

namespace OHOS::Security::SecurityGuard {
DataManagerWrapper &DataManagerWrapper::GetInstance()
{
    static DataManagerWrapper instance;
    return instance;
}

DataManagerWrapper::DataManagerWrapper()
{
    DistributedKvDataManager kvDataManager;
    std::shared_ptr<DatabaseManager> dataManager = std::make_shared<DatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<Database>(dataManager);
    std::shared_ptr<DatabaseWrapper> databaseWrapper = std::make_shared<DatabaseWrapper>(database);
    std::shared_ptr<DataStorage> storage = std::make_shared<BaseEventIdStorage>(databaseWrapper);
    dataManager_ = std::make_shared<DataManager>(storage);
}

ErrorCode DataManagerWrapper::LoadCacheData() const
{
    return dataManager_->LoadCacheData();
}

ErrorCode DataManagerWrapper::AddCollectInfo(const EventDataSt &eventData) const
{
    return dataManager_->AddCollectInfo(eventData);
}

ErrorCode DataManagerWrapper::GetCollectInfoById(const std::string &id, ICollectInfo &info) const
{
    return dataManager_->GetCollectInfoById(id, info);
}

ErrorCode DataManagerWrapper::GetEventDataById(const std::vector<int64_t> &eventIds,
    std::vector<EventDataSt> &eventData) const
{
    return dataManager_->GetEventDataById(eventIds, eventData);
}

ErrorCode DataManagerWrapper::GetCachedEventDataById(const std::vector<int64_t> &eventIds,
    std::vector<EventDataSt> &eventData) const
{
    return dataManager_->GetCachedEventDataById(eventIds, eventData);
}

ErrorCode DataManagerWrapper::DeleteKvStore()
{
    return dataManager_->DeleteKvStore();
}
}