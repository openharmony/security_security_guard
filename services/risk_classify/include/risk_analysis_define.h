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

#ifndef SECURITY_GUARD_RISK_ANALYSIS_DEFINE_H
#define SECURITY_GUARD_RISK_ANALYSIS_DEFINE_H

#include <functional>
#include <memory>
#include <string>

namespace OHOS::Security::SecurityGuard {
constexpr const char* RISK_STATUS = "risk";
constexpr const char* SAFE_STATUS = "safe";
constexpr const char* UNKNOWN_STATUS = "unknown";

using CONTENT_STATUS = enum {
    RISK,
    SAFE
};

using CONTENT_RELIABLITY = enum {
    INCREDIBLE,
    CREDIBLE
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_RISK_ANALYSIS_DEFINE_H