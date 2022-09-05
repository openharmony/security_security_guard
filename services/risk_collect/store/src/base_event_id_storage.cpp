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

#include "base_event_id_storage.h"

#include <memory>

#include "base_event_id.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
BaseEventIdStorage::BaseEventIdStorage(std::shared_ptr<DatabaseWrapper> &database)
    : DataStorage(database)
{
}

void BaseEventIdStorage::SaveEntries(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
    std::map<std::string, std::shared_ptr<ICollectInfo>> &infos)
{
    for (const auto &item : allEntries) {
        nlohmann::json jsonObj = nlohmann::json::parse(item.value.ToString(), nullptr, false);
        if (jsonObj.is_discarded()) {
            database_->Delete(item.key);
            return;
        }
        int64_t eventId;
        if (!SecurityGuardUtils::StrToI64(item.key.ToString(), eventId)) {
            return;
        }

        auto eventData = std::make_shared<BaseEventId>(eventId);
        eventData->FromJson(jsonObj);
        infos.emplace(item.key.ToString(), eventData);
    }
}
}