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

#include "risk_analysis_manager_proxy.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerProxy::RiskAnalysisManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IRiskAnalysisManager>(impl)
{
}

int32_t RiskAnalysisManagerProxy::RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
    data.WriteString(devId);
    data.WriteUint32(modelId);
    data.WriteString(param);
    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_GET_SECURITY_MODEL_RESULT, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t RiskAnalysisManagerProxy::SetModelState(uint32_t modelId, bool enable)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
    data.WriteUint32(modelId);
    data.WriteBool(enable);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_SET_MODEL_STATE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    return reply.ReadInt32();
}
}