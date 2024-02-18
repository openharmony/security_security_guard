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

#include "security_collector_manager_callback_service.h"
 
#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {

int32_t SecurityCollectorManagerCallbackService::OnNotify(const Event &event)
{
    LOGD("eventId = %{public}" PRId64 " callback", event.eventId);
    if (subscriber_ != nullptr) {
        subscriber_->OnNotify(event);
    }
    return SUCCESS;
}
}