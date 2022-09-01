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

#ifndef SECURITY_GUARD_REQUEST_SECURITY_MODEL_RESULT_TASK_H
#define SECURITY_GUARD_REQUEST_SECURITY_MODEL_RESULT_TASK_H

#include <string>

#include "base_task.h"

namespace OHOS::Security::SecurityGuard {
class RequestSecurityModelResultTask final : public BaseTask,
    public std::enable_shared_from_this<RequestSecurityModelResultTask> {
public:
    RequestSecurityModelResultTask(std::string &devId, int32_t modelId, TaskCallback callback);
    void OnExecute() override;
    std::string GetDevId() const;
    uint32_t GetModelId() const;
    std::string GetRiskStatus() const;

private:
    std::string devId_{};
    uint32_t modelId_{};
    std::string riskStatus_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_REQUEST_SECURITY_MODEL_RESULT_TASK_H
