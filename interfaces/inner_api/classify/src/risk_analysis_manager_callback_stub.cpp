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

#include "risk_analysis_manager_callback_stub.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerCallbackStub::RiskAnalysisManagerCallbackStub(ResultCallback &callback)
    : callback_(callback)
{
}

int32_t RiskAnalysisManagerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (IRiskAnalysisManagerCallback::GetDescriptor() != data.ReadInterfaceToken()) {
        SGLOGE("Descriptor error");
        return NO_PERMISSION;
    }

    if (code == RiskAnalysisManagerCallbackStub::CMD_SET_SECURITY_MODEL_RESULT) {
        uint32_t expected = sizeof(uint32_t);
        uint32_t actual = data.GetReadableBytes();
        if (expected >= actual) {
            SGLOGE("actual length error, value=%{public}u", actual);
            return BAD_PARAM;
        }

        uint32_t modelId = data.ReadUint32();
        std::string devId = data.ReadString();
        std::string result = data.ReadString();
        SGLOGI("modelId=%{public}u, result=%{public}s", modelId, result.c_str());
        if (callback_ != nullptr) {
            callback_(devId, modelId, result);
        }
        return SUCCESS;
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
}