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

#include <future>
#include <unistd.h>
#include <syscall.h>
#include <unordered_map>

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_napi.h"
#include "security_guard_sdk_adaptor.h"
#include "uv.h"

#include "securec.h"

using namespace OHOS::Security::SecurityGuard;

constexpr int NAPI_REPORT_EVENT_INFO_ARGS_CNT = 1;
constexpr int NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT = 3;
constexpr int NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MIN_CNT = 2;
constexpr int NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT = 3;
constexpr int VERSION_MAX_LEN = 50;

static const std::unordered_map<int32_t, std::pair<int32_t, std::string>> g_errorStringMap = {
    { SUCCESS, { JS_ERR_SUCCESS, "The operation was successful" }},
    { NO_PERMISSION, { JS_ERR_NO_PERMISSION, "Check permission fail"} },
    { BAD_PARAM, { JS_ERR_BAD_PARAM, "Parameter error. please make sure using the correct value"} },
};

static std::string ConvertToJsErrMsg(int32_t code)
{
    auto iter = g_errorStringMap.find(code);
    if (iter != g_errorStringMap.end()) {
        return iter->second.second;
    } else {
        return "Unknown error, please reboot your device and try again";
    }
}

static int32_t ConvertToJsErrCode(int32_t code)
{
    auto iter = g_errorStringMap.find(code);
    if (iter != g_errorStringMap.end()) {
        return iter->second.first;
    } else {
        return JS_ERR_SYS_ERR;
    }
}

static napi_value NapiGetNamedProperty(const napi_env env, const napi_value &object, const std::string &name)
{
    napi_value result = nullptr;
    napi_status status = napi_get_named_property(env, object, name.c_str(), &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to parse property named %{public}s from JS object.", name.c_str());
    }
    return result;
}

static napi_value NapiCreateObject(const napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of object type.");
    }
    return result;
}

static napi_value NapiCreateString(const napi_env env, const std::string &value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &result);
    SGLOGD("create napi value of string type, value is %{public}s.", value.c_str());
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of string type.");
    }
    return result;
}

static napi_value NapiCreateInt32(const napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, value, &result);
    SGLOGI("create napi value of int32 type, value is %{public}d.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int32 type.");
    }
    return result;
}

static napi_value NapiCreateUint32(const napi_env env, uint32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_uint32(env, value, &result);
    SGLOGI("create napi value of uint32 type, value is %{public}u.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of uint32 type.");
    }
    return result;
}

static napi_value ParseInt64(napi_env env, napi_value object, const std::string &key, int64_t &value)
{
    napi_value result;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return nullptr;
    }

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, result, &type));
    if (type != napi_number) {
        SGLOGE("type of param %{public}s is not number", key.c_str());
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_int64(env, result, &value));
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value ParseUint32(napi_env env, napi_value object, uint32_t &value)
{
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_number) {
        SGLOGE("type of param is not number");
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_uint32(env, object, &value));
    return NapiCreateInt32(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value ParseString(napi_env env, napi_value object, char *value, size_t &maxLen)
{
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_string) {
        SGLOGE("type of param is not string");
        return nullptr;
    }

    size_t tmp = maxLen;
    NAPI_CALL(env, napi_get_value_string_utf8(env, object, value, maxLen, &maxLen));
    if (maxLen >= tmp) {
        SGLOGE("get value failed");
        return nullptr;
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value ParseString(napi_env env, napi_value object, const std::string &key, char *value, size_t &maxLen)
{
    napi_value result;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return nullptr;
    }

    return ParseString(env, result, value, maxLen);
}

static napi_value ParseEventInfo(napi_env env, napi_value object, ReportSecurityEventInfoContext *context)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_object) {
        SGLOGE("type of param eventInfo is not object");
        return nullptr;
    }

    if (ParseInt64(env, object, "eventId", context->eventId) == nullptr) {
        return nullptr;
    }

    char version[VERSION_MAX_LEN] = {0};
    size_t len = VERSION_MAX_LEN;
    if (ParseString(env, object, "version", version, len) == nullptr) {
        return nullptr;
    }
    context->version = version;

    char content[CONTENT_MAX_LEN] = {0};
    len = CONTENT_MAX_LEN;
    if (ParseString(env, object, "content", content, len) == nullptr) {
        return nullptr;
    }
    context->content = content;
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value GenerateBusinessError(napi_env env, int32_t code)
{
    napi_value result;
    SGLOGI("GenerateBusinessError code:%{public}d", code);
    if (code == SUCCESS) {
        napi_get_undefined(env, &result);
    } else {
        int32_t jsErrCode = ConvertToJsErrCode(code);
        napi_value errCode = NapiCreateInt32(env, jsErrCode);

        std::string errMsgStr = ConvertToJsErrMsg(code);
        napi_value errMsg = NapiCreateString(env, errMsgStr.c_str());

        napi_create_error(env, nullptr, errMsg, &result);
        napi_set_named_property(env, result, "code", errCode);
        napi_set_named_property(env, result, "message", errMsg);
    }
    return result;
}

static napi_value NapiReportSecurityInfo(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REPORT_EVENT_INFO_ARGS_CNT;
    napi_value argv[NAPI_REPORT_EVENT_INFO_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_REPORT_EVENT_INFO_ARGS_CNT) {
        SGLOGE("report eventInfo arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return NapiCreateInt32(env, ConvertToJsErrCode(BAD_PARAM));
    }

    ReportSecurityEventInfoContext context = {};
    napi_value ret = ParseEventInfo(env, argv[0], &context);
    if (ret == nullptr) {
        SGLOGE("report eventInfo parse error");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return NapiCreateInt32(env, ConvertToJsErrCode(BAD_PARAM));
    }

    auto eventInfo = std::make_shared<EventInfo>(context.eventId, context.version, context.content);
    int32_t code = SecurityGuardSdkAdaptor::ReportSecurityInfo(eventInfo);
    if (code != SUCCESS) {
        SGLOGE("report eventInfo error, code=%{public}d", code);
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

static void DestoryWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<RequestSecurityEventInfoContext *>(work->data));
    }
    delete work;
}

static void DeleteRefIfFinish(uint32_t status, napi_env env, napi_ref ref)
{
    if (status != 0) {
        return;
    }
    napi_delete_reference(env, ref);
}

static void OnResultWork(uv_work_t *work, int status)
{
    if (work == nullptr || work->data == nullptr) {
        DestoryWork(work);
        return;
    }
    RequestSecurityEventInfoContext *context = reinterpret_cast<RequestSecurityEventInfoContext *>(work->data);
    if (context == nullptr || context->env == nullptr) {
        DestoryWork(work);
        return;
    }
    if (context->threadId != syscall(SYS_gettid)) {
        DeleteRefIfFinish(context->status, context->env, context->ref);
        DestoryWork(work);
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);
    if (scope == nullptr) {
        DeleteRefIfFinish(context->status, context->env, context->ref);
        DestoryWork(work);
        return;
    }
    napi_value deviceIdJsParam = NapiCreateString(context->env, context->devId);
    napi_value infoJsParam = NapiCreateString(context->env, context->info);
    napi_value statusJsParam = NapiCreateInt32(context->env, context->status);
    napi_value argv[NAPI_ON_RESULT_ARGS_CNT] = { deviceIdJsParam, infoJsParam, statusJsParam };
    napi_value requestor = nullptr;
    napi_get_reference_value(context->env, context->ref, &requestor);
    napi_value onResult = NapiGetNamedProperty(context->env, requestor, NAPI_ON_RESULT_ATTR);
    napi_value returnVal = nullptr;
    napi_status res = napi_call_function(context->env, requestor, onResult, NAPI_ON_RESULT_ARGS_CNT, argv, &returnVal);
    if (res != napi_ok) {
        SGLOGE("failed to call onResult JS function, res=%{public}d", res);
    }
    napi_close_handle_scope(context->env, scope);
    DeleteRefIfFinish(context->status, context->env, context->ref);
    DestoryWork(work);
}

static int32_t CallRequestSecurityEventInfo(std::shared_ptr<RequestSecurityEventInfoContext> context,
    std::string &deviceId, std::string &conditions)
{
    auto func = [context] (std::string &devId, std::string &riskData, uint32_t status) -> int32_t {
        uv_loop_t *loop = nullptr;
        napi_get_uv_event_loop(context->env, &loop);
        if (loop == nullptr) {
            SGLOGE("failed to get uv_loop.");
            DeleteRefIfFinish(status, context->env, context->ref);
            return BAD_PARAM;
        }

        uv_work_t *work = new (std::nothrow) uv_work_t();
        if (work == nullptr) {
            SGLOGE("uv_work new failed, no memory left.");
            DeleteRefIfFinish(status, context->env, context->ref);
            return BAD_PARAM;
        }
        RequestSecurityEventInfoContext *tmpContext = new (std::nothrow) RequestSecurityEventInfoContext();
        tmpContext->env = context->env;
        tmpContext->ref = context->ref;
        tmpContext->threadId = context->threadId;
        tmpContext->devId = devId;
        tmpContext->status = status;
        tmpContext->info = riskData;
        work->data = reinterpret_cast<void *>(tmpContext);
        uv_queue_work(loop, work, [] (uv_work_t *work) {}, OnResultWork);
        return SUCCESS;
    };
    int32_t code = SecurityGuardSdkAdaptor::RequestSecurityEventInfo(deviceId, conditions, func);
    if (code != SUCCESS) {
        SGLOGE("report eventInfo error, code=%{public}d.", code);
    }
    return code;
}

static napi_value NapiRequestSecurityEventInfo(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT;
    napi_value argv[NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT) {
        SGLOGE("request security eventInfo arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    uint32_t index = 0;
    char deviceIdArr[DEVICE_ID_MAX_LEN];
    size_t len = DEVICE_ID_MAX_LEN;
    napi_value result = ParseString(env, argv[index], deviceIdArr, len);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }
    std::string deviceId(deviceIdArr);

    index++;
    char conditionsArr[CONDITIONS_MAX_LEN];
    len = CONDITIONS_MAX_LEN;
    result = ParseString(env, argv[index], conditionsArr, len);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }
    std::string conditions(conditionsArr);

    auto context = std::make_shared<RequestSecurityEventInfoContext>();
    index++;
    napi_create_reference(env, argv[index], 1, &context->ref);
    context->env = env;
    context->threadId = syscall(SYS_gettid);
    int32_t code = CallRequestSecurityEventInfo(context, deviceId, conditions);
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

static void RequestSecurityModelResultExecute(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<RequestSecurityModelResultContext *>(data);
    auto promise = std::make_shared<std::promise<SecurityModel>>();
    auto future = promise->get_future();
    auto func = [promise] (const std::string &devId, uint32_t modelId, const std::string &result) mutable -> int32_t {
        SecurityModel model = {
            .devId = devId,
            .modelId = modelId,
            .result = result
        };
        promise->set_value(model);
        return SUCCESS;
    };
    context->ret = SecurityGuardSdkAdaptor::RequestSecurityModelResult(context->deviceId, context->modelId, func);
    if (context->ret != SUCCESS) {
        SGLOGE("RequestSecurityModelResultSync error, ret=%{public}d", context->ret);
        return;
    }
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait timeout");
        context->ret = TIME_OUT;
        return;
    }
    context->result = future.get();
}

static napi_value GenerateSecurityModelResult(napi_env env, RequestSecurityModelResultContext *context)
{
    napi_value ret = NapiCreateObject(env);
    napi_value deviceId = NapiCreateString(env, context->result.devId.c_str());
    napi_value modelId = NapiCreateUint32(env, context->result.modelId);
    napi_value result = NapiCreateString(env, context->result.result.c_str());

    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_DEVICE_ID_ATTR, deviceId);
    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_MODEL_ID_ATTR, modelId);
    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_RESULT_ATTR, result);
    return ret;
}

static napi_value GenerateReturnValue(napi_env env, RequestSecurityModelResultContext *context)
{
    napi_value result;
    if (context->ret == SUCCESS) {
        result = GenerateSecurityModelResult(env, context);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

static void RequestSecurityModelResultComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<RequestSecurityModelResultContext *>(data);
    napi_value result[2] = {0};
    result[0] = GenerateBusinessError(env, context->ret);
    result[1] = GenerateReturnValue(env, context);
    if (context->ref != nullptr) {
        napi_value callbackfunc = nullptr;
        napi_get_reference_value(env, context->ref, &callbackfunc);
        napi_value returnVal;
        napi_call_function(env, nullptr, callbackfunc, sizeof(result) / sizeof(result[0]), result, &returnVal);
        napi_delete_reference(env, context->ref);
    } else {
        if (context->ret == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[0]);
        }
    }
    napi_delete_async_work(env, context->asyncWork);
    delete context;
}

static napi_value NapiRequestSecurityModelResult(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT;
    napi_value argv[NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MIN_CNT &&
        argc != NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT) {
        SGLOGE("request security model result arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    size_t index = 0;
    char deviceId[DEVICE_ID_MAX_LEN];
    size_t len = DEVICE_ID_MAX_LEN;
    if (ParseString(env, argv[index], deviceId, len) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    index++;
    uint32_t modelId = 0;
    if (ParseUint32(env, argv[index], modelId) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    RequestSecurityModelResultContext *context = new (std::nothrow) RequestSecurityModelResultContext();
    if (context == nullptr) {
        SGLOGE("context new failed, no memory left.");
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT));
        return nullptr;
    }
    context->deviceId = deviceId;
    context->modelId = modelId;
    index++;
    if (index < argc) {
        napi_create_reference(env, argv[index], 1, &context->ref);
    }

    napi_value promise = nullptr;
    if (context->ref == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resourceName = NapiCreateString(env, "NapiRequestSecurityModelResult");
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, RequestSecurityModelResultExecute,
        RequestSecurityModelResultComplete, static_cast<void *>(context), &context->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, context->asyncWork));
    return promise;
}

static napi_value EventIdTypeConstructor(napi_env env)
{
    napi_value eventIdType = nullptr;
    napi_value printerEventId = nullptr;
    NAPI_CALL(env, napi_create_object(env, &eventIdType));
    NAPI_CALL(env, napi_create_int64(env, EventIdType::PRINTER_EVENT_ID, &printerEventId));
    NAPI_CALL(env, napi_set_named_property(env, eventIdType, "PRINTER_EVENT_ID", printerEventId));
    return eventIdType;
}

static napi_value ModelIdTypeConstructor(napi_env env)
{
    napi_value modelIdType = nullptr;
    napi_value rsModelId = nullptr;
    napi_value dcModelId = nullptr;
    napi_value pmdModelId = nullptr;
    napi_value saModeltId = nullptr;
    NAPI_CALL(env, napi_create_object(env, &modelIdType));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::ROOT_SCAN_MODEL_ID, &rsModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::DEVICE_COMPLETENESS_MODEL_ID, &dcModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::PHYSICAL_MACHINE_DETECTION_MODEL_ID, &pmdModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::SECURITY_AUDIT_MODEL_ID, &saModeltId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "ROOT_SCAN_MODEL_ID", rsModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "DEVICE_COMPLETENESS_MODEL_ID", dcModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "PHYSICAL_MACHINE_DETECTION_MODEL_ID", pmdModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "SECURITY_AUDIT_MODEL_ID", saModeltId));
    return modelIdType;
}

EXTERN_C_START
static napi_value SecurityGuardNapiRegister(napi_env env, napi_value exports)
{
    static napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EventIdType", EventIdTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("ModelIdType", ModelIdTypeConstructor(env)),
        DECLARE_NAPI_FUNCTION("reportSecurityInfo", NapiReportSecurityInfo),
        DECLARE_NAPI_FUNCTION("requestSecurityEventInfo", NapiRequestSecurityEventInfo),
        DECLARE_NAPI_FUNCTION("requestSecurityModelResult", NapiRequestSecurityModelResult),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SecurityGuardNapiRegister,
    .nm_modname = "security.securityGuard",
    .nm_priv = reinterpret_cast<void *>(0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}