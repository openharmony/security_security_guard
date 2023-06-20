/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "risk_analysis_manager_fuzzer.h"

#include <string>

#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_service.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerService g_service(RISK_ANALYSIS_MANAGER_SA_ID, true);
constexpr int32_t REMAINDER_VALUE = 2;

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    if (size % REMAINDER_VALUE == 0) {
        // handle get security model result cmd
        uint32_t modelId = static_cast<uint32_t>(size);
        std::string deviceId(reinterpret_cast<const char *>(data), size);
        datas.WriteString(deviceId);
        datas.WriteUint32(modelId);
        ResultCallback func = [] (const std::string &devId, uint32_t modelId, const std::string &result) -> int32_t {
            SGLOGI("RiskAnalysisManagerCallbackService called");
            return 0;
        };
        sptr<IRemoteObject> callback = new (std::nothrow) RiskAnalysisManagerCallbackService(func);
        datas.WriteRemoteObject(callback);
        g_service.OnRemoteRequest(RiskAnalysisManagerStub::CMD_GET_SECURITY_MODEL_RESULT, datas, reply, option);
        return;
    }
    // handle set model state cmd
    uint32_t modelId = static_cast<uint32_t>(size);
    datas.WriteUint32(modelId);
    datas.WriteBool(size % REMAINDER_VALUE == 0);
    g_service.OnRemoteRequest(RiskAnalysisManagerStub::CMD_SET_MODEL_STATE, datas, reply, option);
}
}  // namespace OHOS::Security::SecurityGuard

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityGuard::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
