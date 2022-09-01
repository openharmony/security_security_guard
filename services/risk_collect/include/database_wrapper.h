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

#ifndef SECURITY_GUARD_DATABASE_WRAPPER_H
#define SECURITY_GUARD_DATABASE_WRAPPER_H

#include <memory>
#include <mutex>

#include "distributed_kv_data_manager.h"

#include "database.h"

namespace OHOS::Security::SecurityGuard {
class DatabaseWrapper {
public:
    explicit DatabaseWrapper(std::shared_ptr<Database> databasePtr);
    Status GetEntries(const Key &prefix, std::vector<Entry> &entries);
    Status Get(const Key &key, Value &value);
    Status Put(const Key &key, const Value &value);
    Status Delete(const Key &key);
    Status DeleteKvStore();

private:
    std::shared_ptr<Database> databasePtr_;
    std::mutex kvStorePtrMutex_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATABASE_WRAPPER_H
