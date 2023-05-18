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
#include "security_guard_log.h"
#include "config_data_manager.h"
#include "store_define.h"

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

std::pair<std::vector<std::vector<int64_t>>, std::string> DataFormat::ParseConditions(std::string conditions)
{
    nlohmann::json jsonObj = nlohmann::json::parse(conditions, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("json parse error");
        return {};
    }
    std::set<int64_t> set;
    auto iter = jsonObj.find(EVENT_CFG_EVENT_ID_KEY);
    if (iter != jsonObj.end() && (*iter).is_array()) {
        for (const auto &event : *iter) {
            if (!event.is_number()) {
                SGLOGE("event type is error");
                continue;
            }
            set.emplace(event);
        }
    }

    iter = jsonObj.find(MODEL_CFG_MODEL_ID_KEY);
    if (iter != jsonObj.end() && (*iter).is_array()) {
        for (const auto &model : *iter) {
            if (!model.is_number()) {
                SGLOGE("model type is error");
                continue;
            }
            std::vector<int64_t> vector = ConfigDataManager::GetInstance()->GetEventIds(model);
            set.insert(vector.begin(), vector.end());
        }
    }

    std::string date;
    iter = jsonObj.find("date");
    if (iter != jsonObj.end() && (*iter).is_string()) {
        date = *iter;
    }
    std::vector<int64_t> riskEvent;
    std::vector<int64_t> auditEvent;
    for (auto it = set.begin(); it != set.end(); it++) {
        std::string table = ConfigDataManager::GetInstance()->GetTableFromEventId(*it);
        if (table == RISK_TABLE) {
            riskEvent.emplace_back(*it);
        } else if (table == AUDIT_TABLE) {
            auditEvent.emplace_back(*it);
        }
    }
    std::vector<std::vector<int64_t>> vector { riskEvent, auditEvent };
    return std::make_pair(vector, date);
}
}