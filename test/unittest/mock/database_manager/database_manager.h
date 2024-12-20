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

#include "gmock/gmock.h"

#include "singleton.h"

#include "i_db_listener.h"

namespace OHOS::Security::SecurityGuard {
class BaseDatabaseManager {
public:
    virtual void Init() = 0;
    virtual int32_t SetAuditState(bool enable) = 0;
    virtual int InsertEvent(uint32_t source, const SecEvent& event,
        const std::set<std::string> &eventSubscribes = {}) = 0;
    virtual int QueryAllEvent(std::string table, std::vector<SecEvent> &events) = 0;
    virtual int QueryRecentEventByEventId(int64_t eventId, SecEvent &event) = 0;
    virtual int QueryRecentEventByEventId(std::string table, const std::vector<int64_t> &eventId,
        std::vector<SecEvent> &event) = 0;
    virtual int QueryEventByEventIdAndDate(std::string table, std::vector<int64_t> &eventIds,
        std::vector<SecEvent> &events, std::string beginTime, std::string endTime) = 0;
    virtual int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventId(std::string table, std::vector<int64_t> &eventIds,
        std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventType(std::string table, int32_t eventType, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByLevel(std::string table, int32_t level, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByOwner(std::string table, std::string owner, std::vector<SecEvent> &events) = 0;
    virtual int64_t CountAllEvent(std::string table) = 0;
    virtual int64_t CountEventByEventId(int64_t eventId) = 0;
    virtual int DeleteOldEventByEventId(int64_t eventId, int64_t count) = 0;
    virtual int DeleteAllEventByEventId(int64_t eventId) = 0;
    virtual int32_t SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener) = 0;
    virtual int32_t UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener) = 0;
};

class DatabaseManager : public BaseDatabaseManager {
public:
    static DatabaseManager &GetInstance()
    {
        static DatabaseManager instance;
        return instance;
    };

    MOCK_METHOD0(Init, void());
    MOCK_METHOD1(SetAuditState, int32_t(bool enable));
    MOCK_METHOD3(InsertEvent, int(uint32_t source, const SecEvent& event,
        const std::set<std::string> &eventSubscribes));
    MOCK_METHOD2(QueryAllEvent, int(std::string table, std::vector<SecEvent> &events));
    MOCK_METHOD2(QueryRecentEventByEventId, int(int64_t eventId, SecEvent &event));
    MOCK_METHOD3(QueryRecentEventByEventId, int(std::string table, const std::vector<int64_t> &eventId,
        std::vector<SecEvent> &event));
    MOCK_METHOD5(QueryEventByEventIdAndDate, int(std::string table, std::vector<int64_t> &eventIds,
        std::vector<SecEvent> &events, std::string beginTime, std::string endTime));
    MOCK_METHOD2(QueryEventByEventId, int(int64_t eventId, std::vector<SecEvent> &events));
    MOCK_METHOD3(QueryEventByEventId, int(std::string table, std::vector<int64_t> &eventIds,
        std::vector<SecEvent> &events));
    MOCK_METHOD3(QueryEventByEventType, int(std::string table, int32_t eventType, std::vector<SecEvent> &events));
    MOCK_METHOD3(QueryEventByLevel, int(std::string table, int32_t level, std::vector<SecEvent> &events));
    MOCK_METHOD3(QueryEventByOwner, int(std::string table, std::string owner, std::vector<SecEvent> &events));
    MOCK_METHOD1(CountAllEvent, int64_t(std::string table));
    MOCK_METHOD1(CountEventByEventId, int64_t(int64_t eventId));
    MOCK_METHOD2(DeleteOldEventByEventId, int(int64_t eventId, int64_t count));
    MOCK_METHOD1(DeleteAllEventByEventId, int(int64_t eventId));
    MOCK_METHOD2(SubscribeDb, int32_t(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener));
    MOCK_METHOD2(UnSubscribeDb, int32_t(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener));
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DATABASE_MANAGER_H
