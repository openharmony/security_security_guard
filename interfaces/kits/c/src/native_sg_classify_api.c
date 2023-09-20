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

#define SUCCESS 0
#define NO_PERMISSION 2

static int32_t ConvertToOhErr(int32_t code)
{
    if (code == SUCCESS) {
        return OH_SG_SUCCESS;
    } else if (code == NO_PERMISSION) {
        return OH_SG_PERMISSION_FAIL;
    } else {
        return OH_SG_BAD_PARAM;
    }
}

int32_t OH_SG_RequestSecurityModelResultSync(const struct OH_SG_DeviceIdentify *devId, enum OH_SG_ModelId modelId,
    struct OH_SG_SecurityModelResult *result)
{
    return ConvertToOhErr(RequestSecurityModelResultSync((const DeviceIdentify *) devId, modelId,
        (SecurityModelResult *) result));
}

int32_t OH_SG_RequestSecurityModelResultAsync(const struct OH_SG_DeviceIdentify *devId, enum OH_SG_ModelId modelId,
    OH_SG_SecurityGuardRiskCallback callback)
{
    return ConvertToOhErr(RequestSecurityModelResultAsync((const DeviceIdentify *) devId, modelId,
        (SecurityGuardRiskCallback *) callback));
}