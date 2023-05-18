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

#include "root_scan_model.h"

#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F10, "SG_ROOT_SCAN" };
    const std::vector<int64_t> EVENTIDS = { 1011009000, 1011009001, 1011009100, 1011009101,
        1011009102, 1011009103, 1011009104 };
    constexpr const int32_t FAILED = -1;
    constexpr const int32_t SUCCESS = 0;
    constexpr const char* RISK_STATUS = "risk";
    constexpr const char* SAFE_STATUS = "safe";
    constexpr const char* UNKNOWN_STATUS = "unknown";
}

RootScanModel::~RootScanModel()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
}

int32_t RootScanModel::Init(std::shared_ptr<IModelManager> api)
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
    return SUCCESS;
}

std::string RootScanModel::GetResult()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    std::vector<SecEvent> events;
    int32_t ret = dbOpt_->QueryRecentEventByEventId(EVENTIDS, events);
    HiLog::Info(LABEL, "ret=%{public}d", ret);
    return RiskAnalysis(events);
}

int32_t RootScanModel::SubscribeResult(std::shared_ptr<IModelResultListener> listener)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    return SUCCESS;
}

void RootScanModel::Release()
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

std::string RootScanModel::RiskAnalysis(const std::vector<SecEvent> &eventData)
{
    std::string result = SAFE_STATUS;
    for (const SecEvent &data : eventData) {
        nlohmann::json jsonObj = nlohmann::json::parse(data.content, nullptr, false);
        if (jsonObj.is_discarded()) {
            HiLog::Error(LABEL, "json err");
            result = UNKNOWN_STATUS;
            break;
        }

        auto content = jsonObj.get<EventContent>();
        if (content.cred != CREDIBLE) {
            HiLog::Error(LABEL, "not cred");
            continue;
        }

        if (content.status != SAFE) {
            HiLog::Error(LABEL, "status error");
            result = RISK_STATUS;
            break;
        }
    }

    nlohmann::json jsonObj {
        { "result", result }
    };

    SecEvent event {
        .eventId = 1011009201,
        .version = "1.0",
        .date = GetDate(),
        .content = jsonObj.dump()
    };
    int32_t ret = dbOpt_->InsertEvent(event);
    HiLog::Info(LABEL, "insert root result, ret=%{public}d", ret);
    return result;
}
} // OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel *GetModelApi()
{
    OHOS::Security::SecurityGuard::IModel *api = new (std::nothrow) OHOS::Security::SecurityGuard::RootScanModel();
    return api;
}