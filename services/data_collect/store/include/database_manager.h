/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_DATABASE_MANAGER_H
#define SECURITY_GUARD_DATABASE_MANAGER_H

#include <set>
#include <unordered_map>

#include "singleton.h"

#include "config_define.h"
#include "i_db_listener.h"

namespace OHOS::Security::SecurityGuard {
class DatabaseManager : public Singleton<DatabaseManager> {
public:
    void Init();
    int32_t SetAuditState(bool enable);
    int InsertEvent(uint32_t source, SecEvent& event);
    int QueryAllEvent(std::string table, std::vector<SecEvent> &events);
    int QueryAllEventFromMem(std::vector<SecEvent> &events);
    int QueryRecentEventByEventId(int64_t eventId, SecEvent &event);
    int QueryRecentEventByEventId(std::string table, const std::vector<int64_t> &eventId, std::vector<SecEvent> &event);
    int QueryEventByEventIdAndDate(std::string table, std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime);
    int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events);
    int QueryEventByEventId(std::string table, std::vector<int64_t> &eventIds, std::vector<SecEvent> &events);
    int QueryEventByEventType(std::string table, int32_t eventType, std::vector<SecEvent> &events);
    int QueryEventByLevel(std::string table, int32_t level, std::vector<SecEvent> &events);
    int QueryEventByOwner(std::string table, std::string owner, std::vector<SecEvent> &events);
    int64_t CountAllEvent(std::string table);
    int64_t CountEventByEventId(int64_t eventId);
    int DeleteOldEventByEventId(int64_t eventId, int64_t count);
    int DeleteAllEventByEventId(int64_t eventId);
    int32_t SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener);
    int32_t UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener);
    int32_t InitDeviceId();

private:
    std::mutex mutex_;
    std::unordered_map<int64_t, std::set<std::shared_ptr<IDbListener>>> listenerMap_;
    std::string deviceId_;
    void FillUserIdAndDeviceId(SecEvent& event);
    void DbChanged(int32_t optType, const SecEvent &event);
    int32_t OpenAudit();
    int32_t CloseAudit();
};
} // namespace OHOS::Security::SecurityGuard {
#endif // SECURITY_GUARD_DATABASE_MANAGER_H