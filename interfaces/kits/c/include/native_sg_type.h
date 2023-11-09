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

#ifndef NATIVE_HMS_SG_TYPE_H
#define NATIVE_HMS_SG_TYPE_H

/**
 * @addtogroup SgTypeApi
 * @{
 *
 * @brief Defines the macros, error codes, enumerated values, data structures
 * used by SecurityGuard APIs.
 *
 * @since 4.0.0(10)
 */

 /**
 * @file native_sg_type.h
 *
 * @brief Defines the macros, error codes, enumerated values, data structures
 * used by SecurityGuard APIs.
 *
 * @since 4.0.0(10)
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The max length of device identity.
 *
 * The max length is 64 bytes, including the terminating null byte.
 */
#define HMS_SG_DEVICE_ID_MAX_LEN 64

/**
 * @brief The max length of the security model result.
 *
 * The max length is 20 bytes, including the terminating null byte.
 */
#define HMS_SG_RESULT_MAX_LEN 20

/**
 * @brief The model result "safe".
 */
#define HMS_SG_MODEL_RESULT_SAFE "safe"

/**
 * @brief The model result "risk".
 */
#define HMS_SG_MODEL_RESULT_RISK "risk"

/**
 * @brief The model result "unknown".
 */
#define HMS_SG_MODEL_RESULT_UNKNOWN "unknown"

/**
 * @brief Enumerates the error codes.
 */
enum HMS_SG_ErrCode {
    /** The result is successful. */
    HMS_SG_SUCCESS = 0,
    /** Permission verification failed. */
    HMS_SG_PERMISSION_FAIL = 201,
    /** The parameter is incorrect. */
    HMS_SG_BAD_PARAM = 401,
};

/**
 * @brief The model Id.
 */
enum HMS_SG_ModelId {
    /** The root scan model Id */
    HMS_SG_ROOT_SCAN_MODEL_ID = 3001000000,
    /** The device completeness model Id. */
    HMS_SG_DEVICE_COMPLETENESS_MODEL_ID = 3001000001,
    /** The physical machine dection model Id. */
    HMS_SG_PHYSICAL_MACHINE_DETECTION_MODEL_ID = 3001000002,
};

/**
 * @brief Defines the structure for the device identify.
 */
struct HMS_SG_DeviceIdentify {
    /** The length of device identity. */
    uint32_t length;
    /** The device identity. */
    uint8_t identity[HMS_SG_DEVICE_ID_MAX_LEN];
};

/**
 * @brief Defines the structure for the security model result.
 */
struct HMS_SG_SecurityModelResult {
    /** The device identity. */
    struct HMS_SG_DeviceIdentify devId;

    /** The model id. */
    uint32_t modelId;

    /** The length of security model result. */
    uint32_t resultLen;

    /**
     * The security model result, value range is "safe", "risk" or "unknown".
     * "safe" indicates the security model result is safe.
     * "risk" indicates the security model result is risk.
     * "unknown" indicates an internal error.
     */
    uint8_t result[HMS_SG_RESULT_MAX_LEN];
};

/**
 * @brief The calbback is used to receive the security model result.
 *
 * @param result The security model result.
 * @see HMS_SG_RequestSecurityModelResultAsync
 */
typedef void HMS_SG_SecurityGuardRiskCallback(struct HMS_SG_SecurityModelResult *result);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HMS_SG_TYPE_H */
