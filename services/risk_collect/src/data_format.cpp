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

#include "data_format.h"

#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr uint32_t MAX_CONTENT_SIZE = 900;
}

bool DataFormat::CheckRiskContent(std::string content)
{
    auto size = static_cast<uint32_t>(content.size());
    if (size > MAX_CONTENT_SIZE) {
        SGLOGE("size error, size=%{public}u", size);
        return false;
    }

    nlohmann::json jsonObj = nlohmann::json::parse(content, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("json parse error");
        return false;
    }
    return true;
}

ErrorCode DataFormat::ParseEventList(std::string eventList, std::vector<int64_t> &eventListVec)
{
    nlohmann::json jsonObj = nlohmann::json::parse(eventList, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("json parse error");
        return JSON_ERR;
    }

    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, EVENT_CFG_EVENT_ID_KEY, array, JSON_ERR);
    ErrorCode code = FAILED;
    nlohmann::json &eventListJson = jsonObj[EVENT_CFG_EVENT_ID_KEY];
    for (const auto& event : eventListJson) {
        if (!event.is_number()) {
            SGLOGE("event type is error");
            continue;
        }
        eventListVec.emplace_back(event);
        code = SUCCESS;
    }

    return code;
}
}