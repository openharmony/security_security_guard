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

#include "risk_analysis_manager_callback_proxy.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerCallbackProxy::RiskAnalysisManagerCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IRiskAnalysisManagerCallback>(impl)
{
}

int32_t RiskAnalysisManagerCallbackProxy::ResponseSecurityModelResult(const std::string &devId, uint32_t modelId,
    std::string &result)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_OPERATION;
    }

    data.WriteUint32(modelId);
    data.WriteString(result);

    MessageOption option = { MessageOption::TF_ASYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return NULL_OBJECT;
    }
    return remote->SendRequest(CMD_SET_SECURITY_MODEL_RESULT, data, reply, option);
}
}