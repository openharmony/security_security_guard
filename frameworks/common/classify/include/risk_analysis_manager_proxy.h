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

#ifndef SECURITY_GUARD_RISK_ANALYSIS_MANAGER_PROXY_H
#define SECURITY_GUARD_RISK_ANALYSIS_MANAGER_PROXY_H

#include <string>

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"

#include "i_risk_analysis_manager.h"

namespace OHOS::Security::SecurityGuard {
class RiskAnalysisManagerProxy : public IRemoteProxy<IRiskAnalysisManager>, public NoCopyable {
public:
    explicit RiskAnalysisManagerProxy(const sptr<IRemoteObject> &impl);
    ~RiskAnalysisManagerProxy() override = default;
    int32_t RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
        const std::string &param, const sptr<IRemoteObject> &callback) override;
    int32_t SetModelState(uint32_t modelId, bool enable) override;

private:
    static inline BrokerDelegator<RiskAnalysisManagerProxy> delegator_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RISK_ANALYSIS_MANAGER_PROXY_H
