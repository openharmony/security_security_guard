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

#ifndef SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H
#define SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H

#include "security_guard_api.h"
#include "security_guard_define.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t RequestSecurityEventInfoAsync(const DeviceIdentify *devId, const char *eventJson,
    RequestSecurityEventInfoCallBack callback);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H