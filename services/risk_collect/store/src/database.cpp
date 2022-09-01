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

#include "database.h"

#include <thread>

#include "risk_collect_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t MAX_TIMES = 5;
    constexpr int32_t SLEEP_INTERVAL = 1000;
}

Database::Database(std::shared_ptr<DatabaseManager> dataManager)
    : dataManager_(dataManager)
{
    appId_.appId = KV_STORE_APP_ID;
    storeId_.storeId = BASE_EVENT_ID_STORE_ID;
}

Status Database::GetKvStore()
{
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .area = EL1,
        .baseDir = std::string("/data/service/el1/public/database/") + appId_.appId
    };

    Status status = dataManager_->GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != Status::SUCCESS || kvStorePtr_ == nullptr) {
        SGLOGE("[sg_db] GetSingleKvStore failed! status %{public}d, kvStore_ is nullptr", status);
        return status;
    }
    return status;
}

bool Database::CheckKvStore()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr) {
        SGLOGE("[sg_db] GetSingleKvStore not null!");
        return true;
    }

    if (dataManager_ == nullptr) {
        return false;
    }
    int32_t tryTimes = MAX_TIMES;
    Status status;
    while (tryTimes > 0) {
        status = GetKvStore();
        if (status == Status::SUCCESS && kvStorePtr_ != nullptr) {
            break;
        }

        SGLOGI("[sg_db] tryTimes = %{public}d status = %{public}d.", tryTimes, status);
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL));
        tryTimes--;
    }

    if (kvStorePtr_ == nullptr) {
        SGLOGE("[sg_db] GetSingleKvStore failed!");
        return false;
    }
    return true;
}

Status Database::GetEntries(const Key &prefix, std::vector<Entry> &entries)
{
    if (!CheckKvStore()) {
        SGLOGE("check kv store error");
        return Status::INVALID_ARGUMENT;
    }

    return kvStorePtr_->GetEntries(prefix, entries);
}

Status Database::Get(const Key &key, Value &value)
{
    if (!CheckKvStore()) {
        SGLOGE("check kv store error");
        return Status::INVALID_ARGUMENT;
    }

    return kvStorePtr_->Get(key, value);
}

Status Database::Put(const Key &key, const Value &value)
{
    if (!CheckKvStore()) {
        SGLOGE("check kv store error");
        return Status::INVALID_ARGUMENT;
    }

    return kvStorePtr_->Put(key, value);
}

Status Database::Delete(const Key &key)
{
    if (!CheckKvStore()) {
        SGLOGE("check kv store error");
        return Status::INVALID_ARGUMENT;
    }

    return kvStorePtr_->Delete(key);
}

Status Database::DeleteKvStore()
{
    if (!CheckKvStore()) {
        SGLOGE("check kv store error");
        return Status::INVALID_ARGUMENT;
    }

    Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        dataManager_->CloseKvStore(appId_, storeId_);
        kvStorePtr_ = nullptr;
        status = dataManager_->DeleteKvStore(appId_, storeId_);
    }
    if (status != Status::SUCCESS) {
        SGLOGE("delete kv store error, status = %{public}d", status);
        return status;
    }
    return Status::SUCCESS;
}

Database::~Database()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr && dataManager_ != nullptr) {
        dataManager_->CloseKvStore(appId_, kvStorePtr_);
    }
}
}
