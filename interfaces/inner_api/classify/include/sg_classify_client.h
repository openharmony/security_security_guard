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

#ifndef SECURITY_GUARD_SG_CLASSIFY_CLIENT_H
#define SECURITY_GUARD_SG_CLASSIFY_CLIENT_H

#include "security_guard_api.h"

#ifdef __cplusplus
#include <string>
namespace OHOS::Security::SecurityGuard {
using SecurityModelResult = struct {
    std::string devId;
    uint32_t modelId;
    std::string param;
    std::string result;
};

using SecurityGuardRiskCallback = std::function<void(const SecurityModelResult &result)>;

int32_t RequestSecurityModelResultSync(const std::string &devId, uint32_t modelId,
    const std::string &param, SecurityModelResult &result);

int32_t RequestSecurityModelResultAsync(const std::string &devId, uint32_t modelId,
    const std::string &param, SecurityGuardRiskCallback callback);
}

#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t RequestSecurityModelResultSync(const DeviceIdentify *devId, uint32_t modelId, SecurityModelResult *result);

int32_t RequestSecurityModelResultAsync(const DeviceIdentify *devId, uint32_t modelId,
    SecurityGuardRiskCallback callback);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_GUARD_SG_CLASSIFY_CLIENT_H
