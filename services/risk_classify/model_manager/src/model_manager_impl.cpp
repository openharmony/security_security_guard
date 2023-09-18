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

#include "model_manager_impl.h"

#include "config_operate.h"
#include "db_operate.h"
#include "database_manager.h"

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<IDbOperate> ModelManagerImpl::GetDbOperate(std::string table)
{
    std::shared_ptr<IDbOperate> operate = nullptr;
    if (table == "risk_event" || table == "audit_event") {
        operate = std::make_shared<DbOperate>(table);
    }
    return operate;
}

std::shared_ptr<IConfigOperate> ModelManagerImpl::GetConfigOperate()
{
    return std::make_shared<ConfigOperate>();
}

int32_t ModelManagerImpl::SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    return DatabaseManager::GetInstance().SubscribeDb(eventIds, listener);
}

int32_t ModelManagerImpl::UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    return DatabaseManager::GetInstance().UnSubscribeDb(eventIds, listener);
}
} // namespace OHOS::Security::SecurityGuard