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

#include "database_manager.h"

namespace OHOS::Security::SecurityGuard {
DatabaseManager::DatabaseManager(const DistributedKvDataManager& dataManager)
    : dataManager_(dataManager)
{
}

Status DatabaseManager::GetSingleKvStore(const Options &options, const AppId &appId, const StoreId &storeId,
    std::shared_ptr<SingleKvStore> &singleKvStore)
{
    return dataManager_.GetSingleKvStore(options, appId, storeId, singleKvStore);
}

Status DatabaseManager::CloseKvStore(const AppId &appId, const StoreId &storeId)
{
    return dataManager_.CloseKvStore(appId, storeId);
}

Status DatabaseManager::CloseKvStore(const AppId &appId, std::shared_ptr<SingleKvStore> &kvStore)
{
    return dataManager_.CloseKvStore(appId, kvStore);
}

Status DatabaseManager::DeleteKvStore(const AppId &appId, const StoreId &storeId)
{
    return dataManager_.DeleteKvStore(appId, storeId);
}
}