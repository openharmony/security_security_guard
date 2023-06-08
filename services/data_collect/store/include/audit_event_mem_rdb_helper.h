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

#ifndef SECURITY_GUARD_AUDIT_EVENT_MEM_RDB_HELPER_H
#define SECURITY_GUARD_AUDIT_EVENT_MEM_RDB_HELPER_H

#include "rdb_predicates.h"
#include "values_bucket.h"

#include "timer.h"

#include "database_helper.h"
#include "config_define.h"
#include "store_define.h"

namespace OHOS::Security::SecurityGuard {
class AuditEventMemRdbHelper : public DatabaseHelper {
public:
    static DatabaseHelper &GetInstance();
    int Init() override;
    void Release() override;
    int QueryAllEvent(std::vector<SecEvent> &events) override;
    int QueryAllEventFromMem(std::vector<SecEvent> &events) override;
    int FlushAllEvent() override;

private:
    AuditEventMemRdbHelper();
    ~AuditEventMemRdbHelper();
    int QueryEventFromMemByDate(std::vector<SecEvent> &events, std::string date);
    void DeleteRedundantData(const std::unordered_map<int64_t, int64_t> &countMap);
    int DeleteFlushDataFromMem(std::string date);
    int DeleteExpiredDataFromMain(std::string date);
    Utils::Timer timer_{"sg_db_flush"};
    uint32_t timerId_{};
};
} // namespace OHOS::Security::SecurityGuard {
#endif // SECURITY_GUARD_AUDIT_EVENT_MEM_RDB_HELPER_H