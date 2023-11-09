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

#ifndef SECURITY_GUARD_I_DB_OPERATE_H
#define SECURITY_GUARD_I_DB_OPERATE_H

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {

class IDbOperate {
public:
    virtual ~IDbOperate() = default;
    virtual int InsertEvent(SecEvent& event) = 0;
    virtual int QueryAllEvent(std::vector<SecEvent> &events) = 0;
    virtual int QueryAllEventFromMem(std::vector<SecEvent> &events) = 0;
    virtual int QueryRecentEventByEventId(int64_t eventId, SecEvent &event) = 0;
    virtual int QueryRecentEventByEventId(const std::vector<int64_t> &eventId,
        std::vector<SecEvent> &event) = 0;
    virtual int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByLevel(int32_t level, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByOwner(std::string owner, std::vector<SecEvent> &events) = 0;
    virtual int64_t CountAllEvent() = 0;
    virtual int64_t CountEventByEventId(int64_t eventId) = 0;
    virtual int DeleteOldEventByEventId(int64_t eventId, int64_t count) = 0;
    virtual int DeleteAllEventByEventId(int64_t eventId) = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_DB_OPERATE_H