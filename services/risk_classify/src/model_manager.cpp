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

#include "model_manager.h"

#include <nlohmann/json.hpp>

#include "data_manager_wrapper.h"
#include "model_analysis.h"
#include "model_cfg_marshalling.h"
#include "risk_analysis_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
using nlohmann::json;
ModelManager &ModelManager::GetInstance()
{
    static ModelManager instance;
    return instance;
}

ErrorCode ModelManager::InitModel() const
{
    return ModelAnalysis::GetInstance().AnalyseModel();
}

std::vector<int64_t> ModelManager::GetEventIds(uint32_t modelId)
{
    SGLOGE("%{public}s", __func__);
    return ModelAnalysis::GetInstance().GetEventIds(modelId);
}

ErrorCode ModelManager::AnalyseRisk(const std::vector<int64_t> &events) const
{
    SGLOGE("%{public}s, size=%{public}u", __func__, static_cast<uint32_t>(events.size()));
    std::vector<EventDataSt> eventData;
    ErrorCode code = DataManagerWrapper::GetInstance().GetCachedEventDataById(events, eventData);
    if (code != SUCCESS) {
        SGLOGE("code=%{public}u", code);
        return code;
    }

    for (const EventDataSt &data : eventData) {
        SGLOGE("eventId=%{public}ld, content=%{public}s", data.eventId, data.content.c_str());
        json jsonObj = json::parse(data.content, nullptr, false);
        if (jsonObj.is_discarded()) {
            SGLOGE("json err");
            return JSON_ERR;
        }

        auto content = jsonObj.get<EventContentSt>();
        if (content.cred != CREDIBLE) {
            SGLOGE("not cred");
            continue;
        }

        if (content.status != SAFE) {
            SGLOGE("status error");
            return FAILED;
        }
    }

    SGLOGE("no risk");
    return SUCCESS;
}
}
