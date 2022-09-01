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

#ifndef SECURITY_GUARD_SECURITY_MODEL_RESULT_H
#define SECURITY_GUARD_SECURITY_MODEL_RESULT_H

#include <string>

namespace OHOS::Security::SecurityGuard {
class SecurityModelResult {
public:
    SecurityModelResult() = default;

    SecurityModelResult(std::string &devId, uint32_t modelId, std::string &result)
        : devId_(devId),
        modelId_(modelId),
        result_(result) {}

    SecurityModelResult(const SecurityModelResult& result) = default;
    std::string GetDevId() const;
    uint32_t GetModelId() const;
    std::string GetResult() const;

private:
    std::string devId_{};
    uint32_t modelId_{};
    std::string result_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SECURITY_MODEL_RESULT_H
