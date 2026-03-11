/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

namespace OHOS {
bool RequestSecurityModelResultAsyncFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    DeviceIdentify deviceIdentify = {};
    std::string str = fdp.ConsumeRandomLengthString(DEVICE_ID_MAX_LEN - 1);
    (void) memcpy_s(deviceIdentify.identity, DEVICE_ID_MAX_LEN, str.c_str(), str.size());
    deviceIdentify.length = str.size();
    uint32_t modelId = fdp.ConsumeIntegral<uint32_t>();
    SecurityModelResult result = {};
    RequestSecurityModelResultSync(&deviceIdentify, modelId, &result);
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
