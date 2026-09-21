/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Test model plugin for ModelManager::InitModel coverage (dlopen path).
// Behavior is controlled by env SG_TEST_MODEL_API_MODE within the test process:
// - "null":      GetModelApi returns nullptr (dlsym ok but api null branch)
// - "init_fail": model Init returns TEST_INIT_FAIL_CODE (model init fail branch)
// - unset/other: model Init returns SUCCESS (success branch)
// Returned instance is heap-allocated because ModelAttrs destructor deletes it.
#include <cstdlib>
#include <cstring>
#include <new>

#include "i_model.h"

namespace OHOS::Security::SecurityGuard {
namespace {
constexpr int32_t TEST_INIT_FAIL_CODE = 999;

class TestModel : public IModel {
public:
    ~TestModel() override = default;
    int32_t Init(std::shared_ptr<IModelManager> api) override
    {
        const char *mode = getenv("SG_TEST_MODEL_API_MODE");
        if (mode != nullptr && strcmp(mode, "init_fail") == 0) {
            return TEST_INIT_FAIL_CODE;
        }
        return 0;
    }
    std::string GetResult(uint32_t modelId, const std::string &param) override
    {
        return "";
    }
    int32_t SubscribeResult(std::shared_ptr<IModelResultListener> listener) override
    {
        return 0;
    }
    void Release() override {}
};
} // namespace
} // namespace OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel* GetModelApi()
{
    const char *mode = getenv("SG_TEST_MODEL_API_MODE");
    if (mode != nullptr && strcmp(mode, "null") == 0) {
        return nullptr;
    }
    return new (std::nothrow) OHOS::Security::SecurityGuard::TestModel();
}
