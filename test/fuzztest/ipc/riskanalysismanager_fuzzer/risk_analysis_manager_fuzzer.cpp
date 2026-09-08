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

#include <string_ex.h>
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_service.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityGuard {
RiskAnalysisManagerService g_service(RISK_ANALYSIS_MANAGER_SA_ID, true);
constexpr int32_t REMAINDER_VALUE = 2;

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    uint32_t modelId = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    if (size % REMAINDER_VALUE == 0) {
        // handle get security model result cmd
        std::string deviceId(reinterpret_cast<const char *>(data + offset), size - offset);
        datas.WriteUint32(modelId);
        ResultCallback func = [] (const std::string &devId, uint32_t modelId, const std::string &result) -> int32_t {
            SGLOGI("RiskAnalysisManagerCallbackService called");
            return 0;
        };
        sptr<IRemoteObject> callback = new (std::nothrow) RiskAnalysisManagerCallbackService(func);
        datas.WriteRemoteObject(callback);
        g_service.OnRemoteRequest(
            static_cast<uint32_t>(RiskAnalysisManagerIpcCode::COMMAND_REQUEST_SECURITY_MODEL_RESULT),
            datas, reply, option);
        return;
    }
    // handle start security model cmd
    datas.WriteUint32(modelId);
    std::string param(reinterpret_cast<const char *>(data + offset), size - offset);
    datas.WriteString16(Str8ToStr16(param));
    g_service.OnRemoteRequest(
        static_cast<uint32_t>(RiskAnalysisManagerIpcCode::COMMAND_START_SECURITY_MODEL), datas, reply, option);
}
}  // namespace OHOS::Security::SecurityGuard

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityGuard::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
