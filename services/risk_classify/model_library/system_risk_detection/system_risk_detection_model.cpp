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

#include "system_risk_detection_model.h"

#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F10, "SG_SYS_RISK_DETECTION" };
    constexpr const int32_t FAILED = -1;
    constexpr const int32_t SUCCESS = 0;
    constexpr const size_t MAX_CFG_ITEM_SIZE = 10;
    constexpr const uint32_t ROOT_SCAN_MODEL_ID = 3001000000;
    constexpr const uint32_t DEVICE_COMPLETENESS_MODEL_ID = 3001000001;
    constexpr const uint32_t PHYSICAL_MACHINE_DETECTION_MODEL_ID = 3001000002;
    constexpr const int64_t ROOT_SCAN_RESULT_ID = 1011009201;
    constexpr const int64_t DEVICE_COMPLETENESS_RESULT_ID = 1011009203;
    constexpr const int64_t PHYSICAL_MACHINE_DETECTION_RESULT_ID = 1011009202;
    constexpr const char* UNKNOWN_STATUS = "unknown";
}

SystemRiskDetectionModel::~SystemRiskDetectionModel()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
}

int32_t SystemRiskDetectionModel::Init(std::shared_ptr<IModelManager> api)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    if (api == nullptr) {
        HiLog::Error(LABEL, "api is null");
        return FAILED;
    }
    dbOpt_ = api->GetDbOperate("risk_event");
    if (dbOpt_ == nullptr) {
        HiLog::Error(LABEL, "get db operate error");
        return FAILED;
    }
    cfgOpt_ = api->GetConfigOperate();
    if (cfgOpt_ == nullptr) {
        HiLog::Error(LABEL, "get config operate error");
        return FAILED;
    }
    return SUCCESS;
}

bool SystemRiskDetectionModel::GetRuleResult(std::vector<bool> &ruleResult, const ModelCfg &cfg)
{
    for (const auto &rule : cfg.config.rules) {
        HiLog::Info(LABEL, "eventId=%{public}ld", rule.eventId);

        SecEvent event;
        int ret = dbOpt_->QueryRecentEventByEventId(rule.eventId, event);
        if (ret != SUCCESS) {
            HiLog::Info(LABEL, "query eventId(%{public}ld) error(%{public}d)", rule.eventId, ret);
            return false;
        }

        nlohmann::json jsonObj = nlohmann::json::parse(event.content, nullptr, false);
        if (jsonObj.is_discarded()) {
            HiLog::Info(LABEL, "json error eventId(%{public}ld)", rule.eventId);
            continue;
        }

        const size_t fieldSize = rule.fields.size();
        if (fieldSize > MAX_CFG_ITEM_SIZE) {
            HiLog::Info(LABEL, "the fieldSize actual length exceeds the expected length");
            return false;
        }
        std::vector<bool> fieldResult;
        for (const auto &field : rule.fields) {
            if (jsonObj.find(field.fieldName) == jsonObj.end()) {
                continue;
            }
            if (field.fieldType != "int32" || !jsonObj.at(field.fieldName).is_number()) {
                continue;
            }
            int32_t value = jsonObj.at(field.fieldName); // db content key-value
            fieldResult.emplace_back(std::to_string(value) == field.value);
        }

        if (fieldResult.empty()) {
            continue;
        }

        HiLog::Info(LABEL, "fieldsRelation=%{public}s", rule.fieldsRelation.c_str());
        bool tmp = fieldResult[0];
        if (rule.fieldsRelation == "OR") {
            for (const auto &result : fieldResult) {
                tmp = (tmp || result);
            }
        } else if (rule.fieldsRelation == "AND") {
            for (const auto &result : fieldResult) {
                tmp = (tmp && result);
            }
        } else {
            continue;
        }
        ruleResult.emplace_back(tmp);
    }
    return true;
}

std::string SystemRiskDetectionModel::GetResult(uint32_t modelId)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    std::string result(UNKNOWN_STATUS);
    ModelCfg cfg;
    bool success = cfgOpt_->GetModelConfig(modelId, cfg);
    if (!success) {
        HiLog::Error(LABEL, "the model not support, modelId=%{public}u", modelId);
        return result;
    }

    if (cfg.type != "build-in") {
        HiLog::Error(LABEL, "the model type not support, type=%{public}s", cfg.type.c_str());
        return result;
    }
    size_t ruleSize = cfg.config.rules.size();
    if (ruleSize > MAX_CFG_ITEM_SIZE) {
        HiLog::Info(LABEL, "the ruleSize actual length exceeds the expected length");
        return result;
    }
    std::vector<bool> ruleResult;
    success = GetRuleResult(ruleResult, cfg);
    if (!success) {
        HiLog::Info(LABEL, "get rule result error");
        return result;
    }

    if (ruleResult.empty()) {
        HiLog::Info(LABEL, "rule result is empty");
        return result;
    }

    bool finalResult = ruleResult[0];
    if (cfg.config.rulesRelation == "OR") {
        for (const auto &result : ruleResult) {
            finalResult = (finalResult || result);
        }
    } else if (cfg.config.rulesRelation == "AND") {
        for (const auto &result : ruleResult) {
            finalResult = (finalResult && result);
        }
    } else {
        HiLog::Info(LABEL, "rules relation error (%{public}s)", cfg.config.rulesRelation.c_str());
        return result;
    }

    if (finalResult) {
        result = cfg.config.trueResult;
    } else {
        result = cfg.config.falseResult;
    }

    HiLog::Info(LABEL, "result=%{public}s", result.c_str());
    ReportResultEvent(modelId, result);
    return result;
}

int32_t SystemRiskDetectionModel::SubscribeResult(std::shared_ptr<IModelResultListener> listener)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    return SUCCESS;
}

void SystemRiskDetectionModel::Release()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
}

std::string GetDate()
{
    time_t timestamp = time(nullptr);
    struct tm timeInfo{};
    localtime_r(&timestamp, &timeInfo);
    char buf[32] = {};
    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &timeInfo) == 0) {
        return "";
    }
    std::string data = buf;
    return data;
}

void SystemRiskDetectionModel::ReportResultEvent(uint32_t modelId, std::string result)
{
    nlohmann::json jsonObj {
        { "result", result }
    };

    int64_t eventId;
    if (modelId == ROOT_SCAN_MODEL_ID) {
        eventId = ROOT_SCAN_RESULT_ID;
    } else if (modelId == DEVICE_COMPLETENESS_MODEL_ID) {
        eventId = DEVICE_COMPLETENESS_RESULT_ID;
    } else if (modelId == PHYSICAL_MACHINE_DETECTION_MODEL_ID) {
        eventId = PHYSICAL_MACHINE_DETECTION_RESULT_ID;
    } else {
        return;
    }
    SecEvent event {
        .eventId = eventId,
        .version = "1.0",
        .date = GetDate(),
        .content = jsonObj.dump()
    };
    int32_t ret = dbOpt_->InsertEvent(event);
    HiLog::Info(LABEL, "insert root result, ret=%{public}d", ret);
}
} // OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel *GetModelApi()
{
    OHOS::Security::SecurityGuard::IModel *api =
        new (std::nothrow) OHOS::Security::SecurityGuard::SystemRiskDetectionModel();
    return api;
}
