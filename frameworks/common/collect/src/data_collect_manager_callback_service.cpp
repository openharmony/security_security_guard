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

#include "data_collect_manager_callback_service.h"

#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
DataCollectManagerCallbackService::DataCollectManagerCallbackService(RequestRiskDataCallback &callback)
    : callback_(callback)
{
}

int32_t DataCollectManagerCallbackService::ResponseRiskData(std::string &devId, std::string &riskData, uint32_t status,
    const std::string& errMsg)
{
    if (callback_ != nullptr) {
        callback_(devId, riskData, status, errMsg);
        return SUCCESS;
    }
    return NULL_OBJECT;
}
}