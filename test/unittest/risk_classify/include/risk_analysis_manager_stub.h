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

#ifndef SECURITY_GUARD_RISK_RISK_ANALYSIS_MANAGER_STUB_H
#define SECURITY_GUARD_RISK_RISK_ANALYSIS_MANAGER_STUB_H

#include "iremote_stub.h"

#include <future>

#include "i_risk_analysis_manager.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class RiskAnalysisManagerStub : public IRemoteStub<IRiskAnalysisManager> {
public:
    RiskAnalysisManagerStub() = default;
    ~RiskAnalysisManagerStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;

private:
    int32_t HandleGetSecurityModelResult(MessageParcel &data, MessageParcel &reply);
    int32_t HandleSetModelState(MessageParcel &data, MessageParcel &reply);
    void PushRiskAnalysisTask(uint32_t modelId, std::shared_ptr<std::promise<std::string>> &promise,
        ClassifyEvent &eventInfo);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RISK_RISK_ANALYSIS_MANAGER_STUB_H
