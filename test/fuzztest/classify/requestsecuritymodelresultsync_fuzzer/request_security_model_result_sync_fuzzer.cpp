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

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#include "sg_classify_client.h"

#undef private

extern "C" int32_t RequestSecurityModelResultSync(const DeviceIdentify *devId, uint32_t modelId,
    SecurityModelResult *result);
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
}
namespace OHOS {
bool RequestSecurityModelResultAsyncFuzzTest(const uint8_t* data, size_t size)
{
    DeviceIdentify deviceIdentify = {};
    uint32_t cpyLen = size > DEVICE_ID_MAX_LEN ? DEVICE_ID_MAX_LEN : static_cast<uint32_t>(size);
    (void) memcpy_s(deviceIdentify.identity, DEVICE_ID_MAX_LEN, data, cpyLen);
    deviceIdentify.length = cpyLen;
    uint32_t modelId = rand() % (size + 1);
    SecurityModelResult result = {};
    RequestSecurityModelResultSync(&deviceIdentify, modelId, &result);
    return true;
}

bool StartSecurityModelFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::Security::SecurityGuard::StartSecurityModel(fdp.ConsumeIntegral<uint32_t>(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::RequestSecurityModelResultAsyncFuzzTest(data, size);
    OHOS::StartSecurityModelFuzzTest(data, size);
    return 0;
}
