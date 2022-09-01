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

#include "report_security_info_fuzzer.h"
#include "event_info.h"
#include <string>
#include "securec.h"
#include "parcel.h"
#include "security_guard_log.h"
#include "data_collect_manager_stub.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
DataCollectManagerStub dataCollectManagerStub;
static std::string Uint8ArrayToString(const uint8_t* buff, size_t size)
{
    std::string str;
    for (size_t i = 0; i < size; i++) {
        str += (33 + buff[i] % (126 - 33));  // Visible Character Range 33 - 126
    }
    return str;
}

// interface test
static void FuzzTest(const uint8_t* data, size_t size)
{
    int64_t eventId = rand() % (size + 1);
    std::string version = Uint8ArrayToString(data, size);
    std::string content = Uint8ArrayToString(data, size);

    std::shared_ptr<EventInfo> eventInfo =
        std::make_shared<EventInfo>(eventId, version, content);
    NativeDataCollectKit::ReportSecurityInfo(eventInfo);
}

// collect SA test
void OnRemoteRequestFuzzer(Parcel &parcel, size_t size)
{
    SGLOGE("Start Risk Collect SA(collect date) Fuzz Test");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());

    data.WriteInt64(parcel.ReadInt64());
    data.WriteString(parcel.ReadString());
    data.WriteString(parcel.ReadString());
    data.WriteString(parcel.ReadString());
    dataCollectManagerStub.OnRemoteRequest(1, data, reply, option);
    SGLOGE("end");
}

bool ReportSecurityInfoFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::ReportSecurityInfoFuzzTest(data, size);
    return 0;
}
