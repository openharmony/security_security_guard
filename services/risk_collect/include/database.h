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

#ifndef SECURITY_GUARD_DATABASE_H
#define SECURITY_GUARD_DATABASE_H

#include <memory>
#include <mutex>

#include "types.h"

#include "database_manager.h"

namespace OHOS::Security::SecurityGuard {
using namespace OHOS::DistributedKv;

class Database {
public:
    explicit Database(std::shared_ptr<DatabaseManager> dataManager);
    virtual ~Database();
    virtual Status GetEntries(const Key &prefix, std::vector<Entry> &entries);
    virtual Status Get(const Key &key, Value &value);
    virtual Status Put(const Key &key, const Value &value);
    virtual Status Delete(const Key &key);
    virtual Status DeleteKvStore();

private:
    Status GetKvStore();
    bool CheckKvStore();
    std::shared_ptr<SingleKvStore> kvStorePtr_;
    std::shared_ptr<DatabaseManager> dataManager_;
    std::mutex kvStorePtrMutex_;
    AppId appId_;
    StoreId storeId_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATABASE_H
