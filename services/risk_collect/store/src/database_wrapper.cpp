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

#include "database_wrapper.h"

#include "database.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DatabaseWrapper::DatabaseWrapper(std::shared_ptr<Database> databasePtr)
    : databasePtr_(databasePtr)
{
}

Status DatabaseWrapper::GetEntries(const Key &prefix, std::vector<Entry> &entries)
{
    if (databasePtr_ == nullptr) {
        SGLOGE("[sg_db] kvStorePtr is null");
        return Status::INVALID_ARGUMENT;
    }
    Status status;
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    status = databasePtr_->GetEntries(prefix, entries);
    if (status == Status::IPC_ERROR) {
        SGLOGE("[sg_db] kvstore ipc error and try again, status = %{public}d", status);
        status = databasePtr_->GetEntries(prefix, entries);
    }

    if (status != Status::SUCCESS) {
        if (status != Status::KEY_NOT_FOUND) {
            SGLOGE("[sg_db] get entries error: %{public}d", status);
        }
        SGLOGW("[sg_db] key does not exist in kvStore_!");
        return Status::DB_ERROR;
    }

    return Status::SUCCESS;
}

Status DatabaseWrapper::Get(const Key &key, Value &value)
{
    if (databasePtr_ == nullptr) {
        SGLOGE("[sg_db] kvStorePtr is null");
        return Status::INVALID_ARGUMENT;
    }
    Status status;
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    status = databasePtr_->Get(key, value);
    if (status == Status::IPC_ERROR) {
        SGLOGE("[sg_db] kv store ipc error and try again, status = %{public}d", status);
        status = databasePtr_->Get(key, value);
    }
    return status;
}

Status DatabaseWrapper::Put(const Key &key, const Value &value)
{
    if (databasePtr_ == nullptr) {
        SGLOGE("[sg_db] kvStorePtr is null");
        return Status::INVALID_ARGUMENT;
    }
    Status status;
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    status = databasePtr_->Put(key, value);
    if (status == Status::IPC_ERROR) {
        SGLOGE("[sg_db] kvstore ipc error and try again, status = %{public}d", status);
        status = databasePtr_->Put(key, value);
    }
    return status;
}

Status DatabaseWrapper::Delete(const Key &key)
{
    if (databasePtr_ == nullptr) {
        SGLOGE("[sg_db] kvStorePtr is null");
        return Status::INVALID_ARGUMENT;
    }
    Value value;
    Status status;
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    status = databasePtr_->Get(key, value);
    if (status == Status::IPC_ERROR) {
        SGLOGE("[sg_db] kvstore ipc error and try again, status = %{public}d", status);
        status = databasePtr_->Get(key, value);
    }
    if (status != Status::SUCCESS) {
        if (status != Status::KEY_NOT_FOUND) {
            SGLOGI("[sg_db] get value from kvstore failed.");
            return Status::DB_ERROR;
        }
        SGLOGW("[sg_db] key does not exist in kvStore_!");
        return Status::SUCCESS;
    }

    status = databasePtr_->Delete(key);
    if (status == Status::IPC_ERROR) {
        SGLOGE("[sg_db] kvstore ipc error and try again, status = %{public}d", status);
        status = databasePtr_->Delete(key);
    }
    return status;
}

Status DatabaseWrapper::DeleteKvStore()
{
    if (databasePtr_ == nullptr) {
        SGLOGE("[sg_db] kvStorePtr is null");
        return Status::INVALID_ARGUMENT;
    }
    return databasePtr_->DeleteKvStore();
}
}
