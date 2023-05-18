/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_API_H
#define SECURITY_GUARD_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONTENT_MAX_LEN 900
#define DEVICE_ID_MAX_LEN 64
#define RESULT_MAX_LEN 20

typedef struct EventInfoSt {
    int64_t eventId;
    const char *version;
    uint32_t contentLen;
    uint8_t content[CONTENT_MAX_LEN];
} EventInfoSt;

typedef struct DeviceIdentify {
    uint32_t length;
    uint8_t identity[DEVICE_ID_MAX_LEN];
} DeviceIdentify;

typedef struct SecurityModelResult {
    DeviceIdentify devId;
    uint32_t modelId;
    uint32_t resultLen;
    uint8_t result[RESULT_MAX_LEN];
} SecurityModelResult;

typedef void RequestSecurityEventInfoCallBack(const DeviceIdentify *devId, const char *eventBuffList, uint32_t status);

typedef void SecurityGuardRiskCallback(SecurityModelResult *result);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_GUARD_API_H
