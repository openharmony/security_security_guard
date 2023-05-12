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

#include "hiview_listener.h"

#include "config_define.h"
#include "database_manager.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityGuard {
void HiviewListener::OnEvent(std::shared_ptr<HiviewDFX::HiSysEventRecord> sysEvent)
{
    if (sysEvent == nullptr) {
        return;
    }
    SGLOGI("Hiview OnEvent: %{public}s", sysEvent->AsJson().c_str());
    SecEvent event = {
        .eventId = 1011015000,
        .content = sysEvent->AsJson()
    };
    DatabaseManager::GetInstance().InsertEvent(HIVIEW_SOURCE, event);
}

void HiviewListener::OnServiceDied()
{
    SGLOGI("Hiview service disconnect");
}
} // OHOS::Security::SecurityGuard