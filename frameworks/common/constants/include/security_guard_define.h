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

#ifndef SECURITY_GUARD_DEFINE_H
#define SECURITY_GUARD_DEFINE_H

#include <string>

namespace OHOS::Security::SecurityGuard {
using ErrorCode = enum {
    SUCCESS,
    FAILED,
    NO_PERMISSION,
    FILE_ERR,
    BAD_PARAM,
    JSON_ERR,
    NULL_OBJECT,
    TIME_OUT,
    NOT_FOUND,
    TASK_ERR,
    READ_ERR,
    WRITE_ERR,
    DB_CHECK_ERR,
    DB_LOAD_ERR,
    DB_OPT_ERR,
    DB_INFO_ERR,
};

using SecurityModel = struct {
    std::string devId;
    uint32_t modelId;
    std::string result;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DEFINE_H
