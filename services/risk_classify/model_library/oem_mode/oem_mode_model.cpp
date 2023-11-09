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

#include "oem_mode_model.h"

#include "hilog/log.h"
#include "parameter.h"

using OHOS::HiviewDFX::HiLog;

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F10, "SG_OEM_MODE" };
    constexpr uint32_t OEM_MODE_MODEL_ID = 3001000005;
    constexpr int32_t SUCCESS = 0;
    constexpr int32_t PARAM_MAN_LEN = 10;
    constexpr const char* RISK_STATUS = "risk";
    constexpr const char* SAFE_STATUS = "safe";
    constexpr const char* UNKNOWN_STATUS = "unknown";
    constexpr const char* RD_MODE = "rd";
    constexpr const char* USER_MODE = "user";
}

OemModeModel::~OemModeModel()
{
    HiLog::Info(LABEL, "~OemModeModel");
}

int32_t OemModeModel::Init(std::shared_ptr<IModelManager> api)
{
    HiLog::Info(LABEL, "Init");
    return SUCCESS;
}

std::string OemModeModel::GetResult(uint32_t modelId, const std::string &param)
{
    HiLog::Info(LABEL, "GetResult");
    if (modelId != OEM_MODE_MODEL_ID) {
        HiLog::Error(LABEL, "model id mismatch, actual is %{public}d", modelId);
        return UNKNOWN_STATUS;
    }
    char value[PARAM_MAN_LEN] = {};
    int ret = GetParameter("const.boot.oemmode", "", value, PARAM_MAN_LEN);
    if (ret <= 0) {
        HiLog::Error(LABEL, "GetParameter fail, ret is %{public}d", ret);
    }
    std::string tmp(value);
    if (tmp == RD_MODE) {
        return RISK_STATUS;
    } else if (tmp == USER_MODE) {
        return SAFE_STATUS;
    } else {
        return UNKNOWN_STATUS;
    }
}

int32_t OemModeModel::SubscribeResult(std::shared_ptr<IModelResultListener> listener)
{
    HiLog::Info(LABEL, "SubscribeResult");
    return SUCCESS;
}

void OemModeModel::Release()
{
    HiLog::Info(LABEL, "Release");
}
} // OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel *GetModelApi()
{
    OHOS::Security::SecurityGuard::IModel *api =
        new (std::nothrow) OHOS::Security::SecurityGuard::OemModeModel();
    return api;
}
