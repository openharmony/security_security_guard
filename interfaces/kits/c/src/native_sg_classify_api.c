/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "native_sg_classify_api.h"

#include "sg_classify_client.h"

int32_t OH_SG_RequestSecurityModelResultSync(const struct OH_SG_DeviceIdentify *devId, uint32_t modelId,
    struct OH_SG_SecurityModelResult *result)
{
    return RequestSecurityModelResultSync((const DeviceIdentify *) devId, modelId,
        (SecurityModelResult *) result);
}

int32_t OH_SG_RequestSecurityModelResultAsync(const struct OH_SG_DeviceIdentify *devId, uint32_t modelId,
    OH_SG_SecurityGuardRiskCallback callback)
{
    return RequestSecurityModelResultAsync((const DeviceIdentify *) devId, modelId,
        (SecurityGuardRiskCallback *) callback);
}