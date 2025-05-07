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
    NO_SYSTEMCALL,
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
    std::vector<int64_t> eventId;
    std::string moduleName;
    std::string modulePath;
    uint32_t version;
    int32_t collectorType;
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

using CollectorType = enum {
    COLLECTOR_NOT_CAN_START,
    COLLECTOR_CAN_START
};

constexpr const char* MODULES = "modules";

// model config key
constexpr const char* MODULE_ID = "moduleId";
constexpr const char* EVENT_ID = "eventId";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* MODULE_PATH = "modulePath";
constexpr const char* MODULE_VERSION = "version";
constexpr const char* MODULE_COLLECTOR_TYPE = "collectorType";

const size_t MAX_QUERY_EVENT_SIZE = 1000;
const size_t MAX_API_INSTACNE_SIZE = 1000;

} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_COLLECTOR_DEFINE_H
