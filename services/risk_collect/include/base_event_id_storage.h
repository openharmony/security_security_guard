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

#ifndef SECURITY_GUARD_BASE_EVENT_ID_STORAGE_H
#define SECURITY_GUARD_BASE_EVENT_ID_STORAGE_H

#include "data_storage.h"
#include "database_wrapper.h"

namespace OHOS::Security::SecurityGuard {
class BaseEventIdStorage : public DataStorage {
public:
    explicit BaseEventIdStorage(std::shared_ptr<DatabaseWrapper> &database);
    ~BaseEventIdStorage() override = default;

private:
    void SaveEntries(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
        std::map<std::string, std::shared_ptr<ICollectInfo>> &infos) override;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_BASE_EVENT_ID_STORAGE_H
