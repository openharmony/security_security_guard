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

#ifndef SECURITY_COLLECTOR_DEFINE_H
#define SECURITY_COLLECTOR_DEFINE_H

#include <string>

namespace OHOS::Security::SecurityCollector {
using ErrorCode = enum {
    SUCCESS,
    FAILED,
    NO_PERMISSION,
    STREAM_ERROR,
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
    RET_DLOPEN_LIB_FAIL = 1001,
    RET_DLSYM_LIB_FAIL = 1002,
    RET_LIB_NOT_LOAD = 1003,
    RET_OUT_OF_MEMORT = 1004
};

using ModuleCfgSt = struct {
    std::string moduleId;
    int64_t eventId;
    std::string moduleName;
    std::string modulePath;
    uint32_t version;
};

using ScSubscribeEvent = struct {
    int32_t pid;
    std::string version;
    int64_t eventId;
    int32_t ret;
    std::string extend;
};

using ScUnsubscribeEvent = struct {
    int32_t pid;;
    int32_t ret;
    std::string extend;
};

const std::string MODULES = "modules";

// model config key
const std::string MODULE_ID = "moduleId";
const std::string EVENT_ID = "eventId";
const std::string MODULE_NAME = "moduleName";
const std::string MODULE_PATH = "modulePath";
const std::string MODULE_VERSION = "version";

} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_COLLECTOR_DEFINE_H
