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

#ifndef SECURITY_GUARD_IRISK_ANALYSIS_MANAGER_H
#define SECURITY_GUARD_IRISK_ANALYSIS_MANAGER_H

#include <cstdint>
#include <cstring>

#include "iremote_broker.h"
#include "message_parcel.h"

namespace OHOS::Security::SecurityGuard {
constexpr int32_t RISK_ANALYSIS_MANAGER_SA_ID = 3523;

class IRiskAnalysisManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.RiskAnalysisManager");
    enum {
        CMD_GET_SECURITY_MODEL_RESULT = 2,
        CMD_SET_MODEL_STATE = 3,
    };

    virtual int32_t RequestSecurityModelResult(std::string &devId, uint32_t modelId,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t SetModelState(uint32_t modelId, bool enable) = 0;
};

class IRiskAnalysisManagerCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.RiskAnalysisManager.Callback");
    enum {
        CMD_SET_SECURITY_MODEL_RESULT = 1,
    };

    virtual int32_t ResponseSecurityModelResult(std::string &devId, uint32_t modelId, std::string &result) = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_IRISK_ANALYSIS_MANAGER_H
