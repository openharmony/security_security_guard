/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_DB_OPERATE_H
#define SECURITY_GUARD_DB_OPERATE_H

#include "i_db_operate.h"

namespace OHOS::Security::SecurityGuard {

class DbOperate : public IDbOperate {
public:
    explicit DbOperate(std::string table);
    ~DbOperate() override = default;
    int InsertEvent(SecEvent& event) override;
    int QueryAllEvent(std::vector<SecEvent> &events) override;
    int QueryAllEventFromMem(std::vector<SecEvent> &events) override;
    int QueryRecentEventByEventId(int64_t eventId, SecEvent &event) override;
    int QueryRecentEventByEventId(const std::vector<int64_t> &eventId, std::vector<SecEvent> &event) override;
    int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events) override;
    int QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events) override;
    int QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events) override;
    int QueryEventByLevel(int32_t level, std::vector<SecEvent> &events) override;
    int QueryEventByOwner(std::string owner, std::vector<SecEvent> &events) override;
    int64_t CountAllEvent() override;
    int64_t CountEventByEventId(int64_t eventId) override;
    int DeleteOldEventByEventId(int64_t eventId, int64_t count) override;
    int DeleteAllEventByEventId(int64_t eventId) override;

private:
    std::string table_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DB_OPERATE_H
