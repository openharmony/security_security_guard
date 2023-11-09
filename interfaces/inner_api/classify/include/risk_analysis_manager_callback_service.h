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

#ifndef SECURITY_GUARD_RISK_ANALYSIS_MANAGER_CALBACK_SERVICE_H
#define SECURITY_GUARD_RISK_ANALYSIS_MANAGER_CALBACK_SERVICE_H

#include "risk_analysis_manager_callback_stub.h"

namespace OHOS::Security::SecurityGuard {
class RiskAnalysisManagerCallbackService : public RiskAnalysisManagerCallbackStub {
public:
    explicit RiskAnalysisManagerCallbackService(ResultCallback &callback);
    ~RiskAnalysisManagerCallbackService() override = default;
    int32_t ResponseSecurityModelResult(const std::string &devId, uint32_t modelId, std::string &result) override;

private:
    ResultCallback callback_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RISK_ANALYSIS_MANAGER_CALBACK_SERVICE_H