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

#include "request_security_event_info_async_fuzzer.h"
#include "obtaindata_callback.h"
#include <string>
#include "securec.h"
#include "parcel.h"
#include "security_guard_log.h"
#include "data_collect_manager_stub.h"
#include "obtaindata_callback_stub.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
DataCollectManagerStub dataCollectManagerStub;

class RequestSecurityEventInfoCallbackTest : public RequestSecurityEventInfoCallback {
public:
    RequestSecurityEventInfoCallbackTest() = default;
    ~RequestSecurityEventInfoCallbackTest() override = default;
    int32_t OnSecurityEventInfoResult(std::string &devId,
            std::string &riskData, uint32_t status) override
    {
        (void) devId;
        (void) riskData;
        (void) status;
        return 0;
    }
};

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
    std::string eventList = Uint8ArrayToString(data, size);
    std::shared_ptr<RequestSecurityEventInfoCallback> callback =
        std::make_shared<RequestSecurityEventInfoCallbackTest>();
    ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback);
}

// classify SA test
void OnRemoteRequestFuzzer(Parcel &parcel, size_t size)
{
    SGLOGE("Start Risk Collect SA(obtaindata) Fuzz Test");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());

    data.WriteString(parcel.ReadString());
    data.WriteString(parcel.ReadString());
    RequestRiskDataCallback requestRiskDataCallback = [] (std::string &devId, std::string &riskData,
        uint32_t status) -> int32_t {
        SGLOGE("ObtainDataCallbackStub Called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) ObtainDataCallbackStub(requestRiskDataCallback);
    if (callback == nullptr) {
        return;
    }
    data.WriteRemoteObject(callback);
    const static int32_t dataRequestCmd = 2;
    dataCollectManagerStub.OnRemoteRequest(dataRequestCmd, data, reply, option);
    SGLOGE("end");
}


bool RequestSecurityEventInfoAsyncFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::RequestSecurityEventInfoAsyncFuzzTest(data, size);
    return 0;
}