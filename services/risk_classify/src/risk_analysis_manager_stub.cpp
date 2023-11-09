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

#include "risk_analysis_manager_stub.h"

#include <future>

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t RiskAnalysisManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    SGLOGD("%{public}s", __func__);
    do {
        if (IRiskAnalysisManager::GetDescriptor() != data.ReadInterfaceToken()) {
            SGLOGE("descriptor error");
            break;
        }

        switch (code) {
            case CMD_GET_SECURITY_MODEL_RESULT: {
                return HandleGetSecurityModelResult(data, reply);
            }
            case CMD_SET_MODEL_STATE: {
                return HandleSetModelState(data, reply);
            }
            default:
                return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t RiskAnalysisManagerStub::HandleGetSecurityModelResult(MessageParcel &data, MessageParcel &reply)
{
    // UDID + MODELID + CALLBACK
    uint32_t expected = sizeof(uint32_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string devId = data.ReadString();
    uint32_t modelId = data.ReadUint32();
    std::string param = data.ReadString();
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = RequestSecurityModelResult(devId, modelId, param, object);
    reply.WriteInt32(ret);
    return ret;
}

int32_t RiskAnalysisManagerStub::HandleSetModelState(MessageParcel &data, MessageParcel &reply)
{
    // MODELID + ENABLE
    uint32_t expected = sizeof(uint32_t) + sizeof(bool);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    uint32_t modelId = data.ReadUint32();
    bool enable = data.ReadBool();
    int32_t ret = SetModelState(modelId, enable);
    reply.WriteInt32(ret);
    return ret;
}
}
