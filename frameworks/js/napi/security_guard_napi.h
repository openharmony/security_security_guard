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

#ifndef SECURITY_GUARD_NAPI_H
#define SECURITY_GUARD_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "security_guard_define.h"
#include "event_define.h"

constexpr int CONDITIONS_MAX_LEN = 100;
constexpr int VERSION_MAX_LEN = 50;
constexpr int CONTENT_MAX_LEN = 900;
constexpr int EXTRA_MAX_LEN = 900;
constexpr int DEVICE_ID_MAX_LEN = 64;
constexpr int MODEL_NAME_MAX_LEN = 64;
constexpr int NAPI_ON_RESULT_ARGS_CNT = 3;
constexpr char NAPI_ON_RESULT_ATTR[] = "onResult";
constexpr char NAPI_SECURITY_MODEL_RESULT_DEVICE_ID_ATTR[] = "deviceId";
constexpr char NAPI_SECURITY_MODEL_RESULT_MODEL_ID_ATTR[] = "modelId";
constexpr char NAPI_SECURITY_MODEL_RESULT_RESULT_ATTR[] = "result";
constexpr int32_t TIMEOUT_REPLY = 500;

struct RequestSecurityEventInfoContext {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    uint32_t status = 0;
    pid_t threadId;
    std::string devId;
    std::string info;
    std::vector<int64_t> eventIds;
    std::string beginTime;
    std::string endTime;
    std::string conditions;
    std::string errMsg;
    napi_ref dataCallback = nullptr;
    napi_ref endCallback = nullptr;
    napi_ref errorCallback = nullptr;
};

struct RequestSecurityModelResultContext {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    napi_deferred deferred;
    napi_async_work asyncWork;
    std::string deviceId;
    uint32_t modelId;
    OHOS::Security::SecurityGuard::SecurityModel result;
    int32_t ret;
};

struct ReportSecurityEventInfoContext {
    int64_t eventId;
    std::string version;
    std::string content;
};


struct NotifyCollectorContext {
    OHOS::Security::SecurityCollector::Event event;
    int64_t duration;
};

enum EventIdType : int64_t {
    PRINTER_EVENT_ID = 1011015004
};

enum ModelIdType : uint32_t {
    ROOT_SCAN_MODEL_ID = 3001000000,
    DEVICE_COMPLETENESS_MODEL_ID = 3001000001,
    PHYSICAL_MACHINE_DETECTION_MODEL_ID = 3001000002,
    SECURITY_AUDIT_MODEL_ID = 3001000003,
};

enum JsErrCode : int32_t {
    JS_ERR_SUCCESS = 0,
    JS_ERR_NO_PERMISSION = 201,
    JS_ERR_BAD_PARAM = 401,
    JS_ERR_SYS_ERR = 21200001,
};

#endif // SECURITY_GUARD_NAPI_H