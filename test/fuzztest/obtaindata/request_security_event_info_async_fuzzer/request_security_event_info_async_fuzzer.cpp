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

#include "obtaindata_callback.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
class RequestSecurityEventInfoCallbackTest : public RequestSecurityEventInfoCallback {
public:
    RequestSecurityEventInfoCallbackTest() = default;
    ~RequestSecurityEventInfoCallbackTest() override = default;
    int32_t OnSecurityEventInfoResult(std::string &devId, std::string &riskData, uint32_t status) override
    {
        (void) devId;
        (void) riskData;
        (void) status;
        return 0;
    }
};

bool RequestSecurityEventInfoAsyncFuzzTest(const uint8_t* data, size_t size)
{
    std::string devId(reinterpret_cast<const char*>(data), size);
    std::string eventList(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<RequestSecurityEventInfoCallback> callback =
        std::make_shared<RequestSecurityEventInfoCallbackTest>();
    ObtainDataKit::RequestSecurityEventInfoAsync(devId, eventList, callback);
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