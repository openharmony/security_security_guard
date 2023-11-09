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

#ifndef NATIVE_SG_CLASSIFY_API_H
#define NATIVE_SG_CLASSIFY_API_H

/**
 * @addtogroup SgClassifyApi
 * @{
 *
 * @brief Describes the Security Guard (SG) classify capabilities, including
 *    two modes: synchronous and asynchronous.
 *
 * @since 4.0.0(10)
 */

 /**
 * @file native_sg_classify.h
 *
 * @brief Declares the APIs used to access the classify capabilities of SG
 *
 * @since 4.0.0(10)
 */

#include "native_sg_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Synchronous request security model result.
 *
 * This API is used to request security model result synchronously.
 *
 * @param devId Indicates the device identify {@link HMS_SG_DeviceIdentify}.
 * @param moduleId Indicates the module ID {@link HMS_SG_ModelId}.
 * @param result Indicates the security model result.
 * @return Returns {@link HMS_SG_ErrCode#HMS_SG_SUCCESS} if the operation is successful,
 *    returns an error code otherwise.
 * @since 4.0.0(10)
 */
int32_t HMS_SG_RequestSecurityModelResultSync(const struct HMS_SG_DeviceIdentify *devId,
    enum HMS_SG_ModelId modelId, struct HMS_SG_SecurityModelResult *result);

/**
 * @brief Asynchronous request security model result.
 *
 * This API is used to request security model result asynchronously.
 *
 * @param devId Indicates the device identify {@link HMS_SG_DeviceIdentify}.
 * @param moduleId Indicates the module ID {@link HMS_SG_ModelId}.
 * @param callback Indicates the callback for receiving the security model result.
 * @return Returns {@link HMS_SG_ErrCode#HMS_SG_SUCCESS} if the operation is successful,
 *    returns an error code otherwise.
 * @since 4.0.0(10)
 */
int32_t HMS_SG_RequestSecurityModelResultAsync(const struct HMS_SG_DeviceIdentify *devId,
    enum HMS_SG_ModelId modelId, HMS_SG_SecurityGuardRiskCallback callback);

#ifdef __cplusplus
}
#endif

/** @} */
#endif // NATIVE_SG_CLASSIFY_API_H