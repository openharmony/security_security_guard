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

#include <string>

#include "securec.h"

#include "sg_obtaindata_client.h"

#undef private

extern "C" int32_t RequestSecurityEventInfoAsync(const DeviceIdentify *devId, const char *eventJson,
    RequestSecurityEventInfoCallBack callback);

namespace OHOS {
static void RequestSecurityEventInfoCallBackFunc(const DeviceIdentify *devId, const char *eventBuffList,
    uint32_t status)
{
    (void) devId;
    (void) eventBuffList;
}

bool RequestSecurityEventInfoAsyncFuzzTest(const uint8_t* data, size_t size)
{
    DeviceIdentify deviceIdentify = {};
    uint32_t cpyLen = size > DEVICE_ID_MAX_LEN ? DEVICE_ID_MAX_LEN : static_cast<uint32_t>(size);
    (void) memcpy_s(deviceIdentify.identity, DEVICE_ID_MAX_LEN, data, cpyLen);
    deviceIdentify.length = cpyLen;
    std::string eventJson(reinterpret_cast<const char*>(data), size);
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