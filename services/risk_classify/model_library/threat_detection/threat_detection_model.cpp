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

#include "threat_detection_model.h"

#include "time_service_client.h"

using OHOS::HiviewDFX::HiLog;

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F10, "SG_THREAT_DETECTION" };
    constexpr int64_t ACCOUNT_ID = 1011015001;
    constexpr int64_t ACCOUNT_ANONYMIZE_ID = 1011009200;
    constexpr int32_t FAILED = -1;
    constexpr int32_t SUCCESS = 0;
    constexpr const char* KEY_TYPE = "type";
    constexpr const char* KEY_SUB_TYPE = "subType";
    constexpr const char* KEY_CALLER = "caller";
    constexpr const char* KEY_OBJECT_INFO = "objectInfo";
    constexpr const char* KEY_BOOT_TIME = "bootTime";
    constexpr const char* KEY_WALL_TIME = "wallTime";
    constexpr const char* KEY_OUTCOME = "outcome";
    constexpr const char* KEY_SOURCE_INFO = "sourceInfo";
    constexpr const char* KEY_TARGET_INFO = "targetInfo";
    constexpr const char* KEY_EXTRA = "extra";
    const std::vector<int64_t> EVENTIDS = { ACCOUNT_ID };
}

ThreatDetectionModel::~ThreatDetectionModel()
{
    HiLog::Info(LABEL, "%{public}s", __func__);
}

int32_t ThreatDetectionModel::Init(std::shared_ptr<IModelManager> api)
{
    if (api == nullptr) {
        return FAILED;
    }
    api_ = api;

    listener_ = std::make_shared<DbListener>();
    listener_->model_ = this;
    helper_ = api_->GetDbOperate("audit_event");
    if (helper_ == nullptr) {
        HiLog::Error(LABEL, "get db operate error");
        return FAILED;
    }
    return api_->SubscribeDb(EVENTIDS, listener_);
}

std::string ThreatDetectionModel::GetResult(uint32_t modelId, const std::string &param)
{
    return {};
}

int32_t ThreatDetectionModel::SubscribeResult(std::shared_ptr<IModelResultListener> listener)
{
    return SUCCESS;
}

void ThreatDetectionModel::Release()
{
    int32_t ret = api_->UnSubscribeDb(EVENTIDS, listener_);
    HiLog::Info(LABEL, "ret=%{public}d", ret);
}

void ThreatDetectionModel::DbListener::OnChange(uint32_t optType, const SecEvent &events)
{
    HiLog::Info(LABEL, "%{public}s, eventId is %{public}ld", __func__, events.eventId);
    if (model_ == nullptr) {
        HiLog::Info(LABEL, "model is nullptr");
        return;
    }
    switch (events.eventId) {
        case ACCOUNT_ID: {
            model_->ParseAccountAndReport(events);
            break;
        }
        default: {
            HiLog::Info(LABEL, "error event, id=%{public}ld", events.eventId);
        }
    }
}

ThreatDetectionModel::DbListener::~DbListener()
{
    if (model_ != nullptr) {
        delete model_;
        model_ = nullptr;
    }
}

void ThreatDetectionModel::GetAccountConetnt(const nlohmann::json &jsonObj, AuditContent &content)
{
    if (jsonObj.find(KEY_TYPE) != jsonObj.end() && jsonObj.at(KEY_TYPE).is_number()) {
        content.type = jsonObj.at(KEY_TYPE).get<int32_t>();
    }
    if (jsonObj.find(KEY_SUB_TYPE) != jsonObj.end() && jsonObj.at(KEY_SUB_TYPE).is_number()) {
        content.subType = jsonObj.at(KEY_SUB_TYPE).get<int32_t>();
    }
    if (jsonObj.find(KEY_OBJECT_INFO) != jsonObj.end() && jsonObj.at(KEY_OBJECT_INFO).is_string()) {
        content.objectInfo = jsonObj.at(KEY_OBJECT_INFO).get<std::string>();
    }
    if (jsonObj.find(KEY_OUTCOME) != jsonObj.end() && jsonObj.at(KEY_OUTCOME).is_string()) {
        content.outTime = jsonObj.at(KEY_OUTCOME).get<std::string>();
    }
    if (jsonObj.find(KEY_SOURCE_INFO)!= jsonObj.end() && jsonObj.at(KEY_SOURCE_INFO).is_string()) {
        content.sourceInfo = jsonObj.at(KEY_SOURCE_INFO).get<std::string>();
    }
    if (jsonObj.find(KEY_TARGET_INFO) != jsonObj.end() && jsonObj.at(KEY_TARGET_INFO).is_string()) {
        content.targetInfo = jsonObj.at(KEY_TARGET_INFO).get<std::string>();
    }
    if (jsonObj.find(KEY_EXTRA) != jsonObj.end() && jsonObj.at(KEY_EXTRA).is_string()) {
        content.extra = jsonObj.at(KEY_EXTRA).get<std::string>();
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer != nullptr) {
        content.bootTime = std::to_string(timer->GetBootTimeNs());
        content.wallTime = std::to_string(timer->GetWallTimeNs());
    }
}

std::string ThreatDetectionModel::GetDate()
{
    time_t timestamp = time(nullptr);
    struct tm timeInfo{};
    localtime_r(&timestamp, &timeInfo);
    char buf[32] = {};
    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &timeInfo) == 0) {
        return "";
    }
    std::string data(buf);
    return data;
}

void ThreatDetectionModel::ParseAccountAndReport(const SecurityGuard::SecEvent &events)
{
    HiLog::Info(LABEL, "parse account");
    nlohmann::json jsonObj = nlohmann::json::parse(events.content, nullptr, false);
    if (jsonObj.is_discarded()) {
        HiLog::Error(LABEL, "parse json error");
        return;
    }
    AuditContent content;
    GetAccountConetnt(jsonObj, content);
    nlohmann::json json = {
        { KEY_TYPE, content.type },
        { KEY_SUB_TYPE, content.subType },
        { KEY_CALLER, content.caller },
        { KEY_OBJECT_INFO, content.objectInfo },
        { KEY_BOOT_TIME, content.bootTime },
        { KEY_WALL_TIME, content.wallTime },
        { KEY_OUTCOME, content.outTime },
        { KEY_SOURCE_INFO, content.sourceInfo },
        { KEY_TARGET_INFO, content.targetInfo },
        { KEY_EXTRA, content.extra },
    };

    SecurityGuard::SecEvent event = {
        .eventId = ACCOUNT_ANONYMIZE_ID,
        .version = "1.0",
        .date = GetDate(),
        .content = json.dump()
    };
    int ret = helper_->InsertEvent(event);
    HiLog::Info(LABEL, "insert event, result is %{public}d", ret);
}
} // OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel *GetModelApi()
{
    OHOS::Security::SecurityGuard::IModel *api =
        new (std::nothrow) OHOS::Security::SecurityGuard::ThreatDetectionModel();
    return api;
}
