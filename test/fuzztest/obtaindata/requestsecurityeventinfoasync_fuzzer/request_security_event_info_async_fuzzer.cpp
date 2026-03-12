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
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "securec.h"

#include "sg_obtaindata_client.h"

#undef private

extern "C" int32_t RequestSecurityEventInfoAsync(const DeviceIdentify *devId, const char *eventJson,
    RequestSecurityEventInfoCallBack callback);

namespace OHOS {
namespace {
constexpr int MAX_STRING_SIZE = 1024;
}
static void RequestSecurityEventInfoCallBackFunc(const DeviceIdentify *devId, const char *eventBuffList,
    uint32_t status)
{
    (void) devId;
    (void) eventBuffList;
}

bool RequestSecurityEventInfoAsyncFuzzTest(const uint8_t* data, size_t size)
{
    DeviceIdentify deviceIdentify = {};
    FuzzedDataProvider fdp(data, size);
    std::string identity(fdp.ConsumeRandomLengthString(DEVICE_ID_MAX_LEN - 1));
    (void) memcpy_s(deviceIdentify.identity, DEVICE_ID_MAX_LEN, identity.c_str(), identity.size());
    deviceIdentify.length = identity.size();
    std::string eventJson(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    RequestSecurityEventInfoAsync(&deviceIdentify, eventJson.c_str(), RequestSecurityEventInfoCallBackFunc);
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