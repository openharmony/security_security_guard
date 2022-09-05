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

#include "data_storage.h"

#include <memory>
#include <thread>

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DataStorage::DataStorage(std::shared_ptr<DatabaseWrapper> &database)
    : database_(database)
{
}

ErrorCode DataStorage::LoadAllData(std::map<std::string, std::shared_ptr<ICollectInfo>> &infos)
{
    SGLOGI("begin LoadAllData");
    if (database_ == nullptr) {
        return NULL_OBJECT;
    }
    std::vector<OHOS::DistributedKv::Entry> allEntries;
    Status status = database_->GetEntries("", allEntries);
    if (status != Status::SUCCESS) {
        return DB_LOAD_ERR;
    }
    infos.clear();
    SGLOGI("begin SaveEntries");
    SaveEntries(allEntries, infos);
    return SUCCESS;
}

ErrorCode DataStorage::AddCollectInfo(const ICollectInfo &info)
{
    std::string infoStr = info.ToString();
    if (infoStr.empty()) {
        SGLOGE("[sg_db] collect info str is empty!");
        return DB_INFO_ERR;
    }
    return PutValueToKvStore(info.GetPrimeKey(), infoStr);
}

ErrorCode DataStorage::RemoveValueFromKvStore(const std::string &keyStr)
{
    if (database_ == nullptr) {
        return NULL_OBJECT;
    }

    OHOS::DistributedKv::Key key(keyStr);
    Status status = database_->Delete(key);
    if (status != Status::SUCCESS) {
        SGLOGE("[sg_db] delete key from kvstore failed, status %{public}d.", status);
        return DB_OPT_ERR;
    }

    SGLOGI("[sg_db] delete key from kvStore_ succeed!");
    return SUCCESS;
}

ErrorCode DataStorage::GetCollectInfoById(const std::string &id, ICollectInfo &info)
{
    std::string valueStr;
    ErrorCode ret = GetValueFromKvStore(id, valueStr);
    if (ret != ERR_OK) {
        SGLOGE("[sg_db] get value from kvstore failed! id %{public}s.", id.c_str());
        return ret;
    }
    nlohmann::json jsonObj = nlohmann::json::parse(valueStr, nullptr, false);
    if (!jsonObj.is_structured()) {  // check format
        SGLOGE("[sg_db] bad format of value from kvstore! id %{public}s.", id.c_str());
        return JSON_ERR;
    }
    info.FromJson(jsonObj);
    return SUCCESS;
}

ErrorCode DataStorage::PutValueToKvStore(const std::string &keyStr, const std::string &valueStr)
{
    if (database_ == nullptr) {
        return NULL_OBJECT;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value(valueStr);

    Status status = database_->Put(key, value);
    if (status != Status::SUCCESS) {
        SGLOGE("[sg_db] put value to kvStore_ error, status = %{public}d", status);
        return DB_OPT_ERR;
    }
    SGLOGI("[sg_db] put value to kvStore_ succeed");
    return SUCCESS;
}

ErrorCode DataStorage::GetValueFromKvStore(const std::string &keyStr, std::string &valueStr)
{
    if (database_ == nullptr) {
        return NULL_OBJECT;
    }
    OHOS::DistributedKv::Key key(keyStr);
    OHOS::DistributedKv::Value value;
    Status status = database_->Get(key, value);
    if (status != Status::SUCCESS) {
        SGLOGE("[sg_db] put value to kvStore_ error, status = %{public}d", status);
        return DB_OPT_ERR;
    }
    valueStr = value.ToString();
    return SUCCESS;
}

ErrorCode DataStorage::DeleteKvStore()
{
    if (database_ == nullptr) {
        return NULL_OBJECT;
    }
    Status status = database_->DeleteKvStore();
    if (status != Status::SUCCESS) {
        SGLOGE("[sg_db] delete kvStore error, status = %{public}d", status);
        return DB_OPT_ERR;
    }
    return SUCCESS;
}
}
