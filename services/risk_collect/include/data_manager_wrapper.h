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

#ifndef SECURITY_GUARD_DATA_MANAGER_WRAPPER_H
#define SECURITY_GUARD_DATA_MANAGER_WRAPPER_H

#include <data_manager.h>

namespace OHOS::Security::SecurityGuard {
class DataManagerWrapper {
public:
    static DataManagerWrapper &GetInstance();
    ErrorCode LoadCacheData() const;
    ErrorCode AddCollectInfo(const EventDataSt &eventData) const;
    ErrorCode GetCollectInfoById(const std::string &id, ICollectInfo &info) const;
    ErrorCode GetEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData) const;
    ErrorCode GetCachedEventDataById(const std::vector<int64_t> &eventIds, std::vector<EventDataSt> &eventData) const;
    ErrorCode DeleteKvStore();

private:
    DataManagerWrapper();
    std::shared_ptr<DataManager> dataManager_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_MANAGER_WRAPPER_H
