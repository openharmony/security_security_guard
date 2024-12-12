/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_event_query_callback_service.h"

namespace OHOS::Security::SecurityGuard {
void SecurityEventQueryCallbackService::OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events)
{
    if (queryCallback != nullptr) {
        queryCallback->OnQuery(events);
    }
}

void SecurityEventQueryCallbackService::OnComplete()
{
    if (queryCallback != nullptr) {
        queryCallback->OnComplete();
    }
}

void SecurityEventQueryCallbackService::OnError(const std::string &message)
{
    if (queryCallback != nullptr) {
        queryCallback->OnError(message);
    }
}
} // namespace OHOS::Security::SecurityGuard
