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

#include "request_security_model_result_async_fuzzer.h"

#include <string>

#include "risk_analysis_manager_callback.h"
#include "sg_classify_client.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
class RiskAnalysisManagerCallbackTest : public RiskAnalysisManagerCallback {
public:
    RiskAnalysisManagerCallbackTest() = default;
    ~RiskAnalysisManagerCallbackTest() override = default;
    int32_t OnSecurityModelResult(const std::string &devId, uint32_t modelId, const std::string &result) override
    {
        (void) devId;
        (void) modelId;
        (void) result;
        return 0;
    }
};

bool RequestSecurityModelResultAsyncFuzzTest(const uint8_t* data, size_t size)
{
    std::string devId(reinterpret_cast<const char*>(data), size);
    uint32_t modelId = rand() % (size + 1);
    std::shared_ptr<RiskAnalysisManagerCallback> callback = std::make_shared<RiskAnalysisManagerCallbackTest>();
    RiskAnalysisManagerKit::RequestSecurityModelResultAsync(devId, modelId, callback);
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
