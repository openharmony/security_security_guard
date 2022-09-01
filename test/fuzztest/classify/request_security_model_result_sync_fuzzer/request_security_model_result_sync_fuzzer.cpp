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

#include "request_security_model_result_sync_fuzzer.h"
#include "security_model_result.h"
#include <string>
#include "securec.h"
#include "parcel.h"
#include "risk_analysis_manager_stub.h"
#include "risk_analysis_manager_callback_stub.h"
#include "security_guard_log.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
RiskAnalysisManagerStub riskAnalysisManagerStub;

static std::string Uint8ArrayToString(const uint8_t* buff, size_t size)
{
    std::string str;
    for (size_t i = 0; i < size; i++) {
        str += (33 + buff[i] % (126 - 33));  // Visible Character Range 33 - 126
    }
    return str;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    std::string devId = Uint8ArrayToString(data, size);
    uint32_t modelId = rand() % (size + 1);
    std::shared_ptr<SecurityModelResult> result = std::make_shared<SecurityModelResult>();
    RiskAnalysisManagerKit::RequestSecurityModelResultSync(devId, modelId, result);
}

// classify SA test
void OnRemoteRequestFuzzer(Parcel &parcel, size_t size)
{
    SGLOGE("Start Risk Classify SA(sync) Fuzz Test");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    data.WriteString(parcel.ReadString());
    data.WriteUint32(parcel.ReadUint32());
    ResultCallback resultCallback = [] (std::string &devId, uint32_t modelId,  std::string &result) -> int32_t {
            SGLOGE("RiskAnalysisManagerCallbackStub Called");
            return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) RiskAnalysisManagerCallbackStub(resultCallback);
    if (callback == nullptr) {
        return;
    }
    data.WriteRemoteObject(callback);
    const static int32_t getSecurityModelResultCmd = 2;
    riskAnalysisManagerStub.OnRemoteRequest(getSecurityModelResultCmd, data, reply, option);
    SGLOGE("end");
}

bool RequestSecurityModelResultAsyncFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    OnRemoteRequestFuzzer(parcel, size);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::RequestSecurityModelResultAsyncFuzzTest(data, size);
    return 0;
}
