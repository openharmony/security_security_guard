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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_CALLBACK_SERVICE_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_CALLBACK_SERVICE_H

#include <string>

#include "data_collect_manager_callback_stub.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataCollectManagerCallbackService : public DataCollectManagerCallbackStub {
public:
    explicit DataCollectManagerCallbackService(RequestRiskDataCallback &callback);
    ~DataCollectManagerCallbackService() override = default;
    int32_t ResponseRiskData(std::string &devId, std::string &riskData, uint32_t status,
        const std::string& errMsg = "") override;

private:
    RequestRiskDataCallback callback_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_CALLBACK_SERVICE_H