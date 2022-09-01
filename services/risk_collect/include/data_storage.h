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

#ifndef SECURITY_GUARD_DATA_STORAGE_H
#define SECURITY_GUARD_DATA_STORAGE_H

#include <string>
#include <map>
#include <mutex>

#include "database.h"
#include "database_wrapper.h"
#include "distributed_kv_data_manager.h"
#include "i_collect_info.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
using namespace OHOS::DistributedKv;
class DataStorage {
public:
    DataStorage() = delete;
    virtual ~DataStorage() = default;
    explicit DataStorage(std::shared_ptr<DatabaseWrapper> &database);
    virtual ErrorCode LoadAllData(std::map<std::string, std::shared_ptr<ICollectInfo>> &infos);
    virtual ErrorCode AddCollectInfo(const ICollectInfo &info);
    virtual void SaveEntries(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
        std::map<std::string, std::shared_ptr<ICollectInfo>> &infos) = 0;
    virtual ErrorCode GetCollectInfoById(const std::string &id, ICollectInfo &info);
    virtual ErrorCode DeleteKvStore();

protected:
    ErrorCode PutValueToKvStore(const std::string &keyStr, const std::string &valueStr);
    ErrorCode GetValueFromKvStore(const std::string &keyStr, std::string &valueStr);
    ErrorCode RemoveValueFromKvStore(const std::string &keyStr);
    std::shared_ptr<DatabaseWrapper> database_;
};
} // namespace OHOS::Security::SecurityGuard

#endif  // SECURITY_GUARD_DATA_STORAGE_H
