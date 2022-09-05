/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_I_COLLECT_INFO_H
#define SECURITY_GUARD_I_COLLECT_INFO_H

#include <string>

#include "nlohmann/json.hpp"

namespace OHOS::Security::SecurityGuard {
class ICollectInfo {
public:
    virtual ~ICollectInfo() = default;
    virtual void ToJson(nlohmann::json &jsonObj) const = 0;
    virtual void FromJson(const nlohmann::json &jsonObj) = 0;
    virtual std::string ToString() const = 0;
    virtual std::string GetPrimeKey() const = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif  // SECURITY_GUARD_I_COLLECT_INFO_H
