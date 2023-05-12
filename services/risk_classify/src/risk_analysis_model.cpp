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

#include "risk_analysis_model.h"

#include <nlohmann/json.hpp>

#include "risk_analysis_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
void RiskAnalysisModel::SetEventInfo(int64_t eventId, std::string status, std::string &eventInfo)
{
    eventInfo += "[" + std::to_string(eventId) + ":" + status + "]";
}

ErrorCode RiskAnalysisModel::RiskAnalysis(std::vector<SecEvent> &eventData, std::string &eventInfo)
{
    for (const SecEvent &data : eventData) {
        nlohmann::json jsonObj = nlohmann::json::parse(data.content, nullptr, false);
        if (jsonObj.is_discarded()) {
            SGLOGE("json err");
            return JSON_ERR;
        }

        auto content = jsonObj.get<EventContentSt>();
        if (content.cred != CREDIBLE) {
            SetEventInfo(data.eventId, "INCREDIBLE", eventInfo);
            SGLOGE("not cred");
            continue;
        }

        if (content.status != SAFE) {
            SetEventInfo(data.eventId, "RISK", eventInfo);
            SGLOGE("status error");
            return FAILED;
        }
        SetEventInfo(data.eventId, "SAFE", eventInfo);
    }

    SGLOGI("no risk");
    return SUCCESS;
}
}
