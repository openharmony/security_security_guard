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

#include "hiview_listener.h"

#include <unordered_set>

#include "database_manager.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int CONTENT_MAX_LEN = 900;
    constexpr int64_t PASTEBOARD_EVENT_ID = 1011015000;
    constexpr int64_t BUNDLE_INSTALL_EVENT_ID = 0x818800800;
    constexpr int64_t BUNDLE_UPDATE_EVENT_ID = 0x818800801;
    const std::unordered_set<std::string> HAP_INSTALL_UPDATE_STR = {"USERID", "BUNDLE_NAME",
        "VERSION", "APP_DISTRIBUTION_TYPE", "INSTALL_TIME", "CALLING_UID", "CALLING_APPID",
        "CALLING_BUNDLE_NAME", "FINGERPRINT", "HIDE_DESKTOP_ICON", "INSTALL_TYPE", "HASH_VALUE"};
}

void HiviewListener::OnEvent(std::shared_ptr<HiviewDFX::HiSysEventRecord> sysEvent)
{
    if (sysEvent == nullptr) {
        return;
    }
    SGLOGD("Hiview OnEvent: %{public}s", sysEvent->AsJson().c_str());
    SecEvent event;
    if (!GetSecEvent(sysEvent, event)) {
        SGLOGE("Unknown event");
        return;
    }
    DatabaseManager::GetInstance().InsertEvent(HIVIEW_SOURCE, event);
}

void HiviewListener::OnServiceDied()
{
    SGLOGI("Hiview service disconnect");
}

bool HiviewListener::GetSecEvent(std::shared_ptr<HiviewDFX::HiSysEventRecord> sysEvent, SecEvent& event)
{
    std::unordered_map<std::string, int64_t> domainName2Id = {
        {"PASTEBOARD-USE_BEHAVIOUR", PASTEBOARD_EVENT_ID},
        {"BUNDLE_MANAGER-BUNDLE_INSTALL", BUNDLE_INSTALL_EVENT_ID},
        {"BUNDLE_MANAGER-BUNDLE_UPDATE", BUNDLE_UPDATE_EVENT_ID}
    };
    std::string domainName = sysEvent->GetDomain() + "-" + sysEvent->GetEventName();
    if (domainName2Id.count(domainName) == 0) {
        SGLOGE("The eventId is not applied for");
        return false;
    }

    std::string eventJsonStr = sysEvent->AsJson();
    if (eventJsonStr.empty() || !nlohmann::json::accept(eventJsonStr)) {
        SGLOGE("eventJsonStr err");
        return false;
    }
    nlohmann::json eventJson = nlohmann::json::parse(eventJsonStr);
    if (eventJson.is_discarded()) {
        SGLOGE("json err");
        return false;
    }

    int64_t sysEventId = domainName2Id[domainName];
    filterInstallOrUpdateContent(sysEventId, eventJson);
    if (eventJson.dump().size() >= CONTENT_MAX_LEN) {
        SGLOGE("The JSON length is too long.");
        return false;
    }

    event = {
        .eventId = sysEventId,
        .version = "1.0",
        .date = SecurityGuardUtils::GetDate(),
        .content = eventJson.dump()
    };
    return true;
}

void HiviewListener::filterInstallOrUpdateContent(int64_t eventId, nlohmann::json& jsonObj)
{
    if ((eventId != BUNDLE_INSTALL_EVENT_ID) && (eventId != BUNDLE_UPDATE_EVENT_ID)) {
        return;
    }
    if (!filterHashValue(jsonObj)) {
        return;
    }
    for (auto it = jsonObj.begin(); it != jsonObj.end();) {
        if (HAP_INSTALL_UPDATE_STR.find(it.key()) == HAP_INSTALL_UPDATE_STR.end()) {
            it = jsonObj.erase(it);
        } else {
            ++it;
        }
    }
}

bool HiviewListener::filterHashValue(nlohmann::json& jsonObj)
{
    if (jsonObj.contains("FILE_PATH") && jsonObj.contains("HASH_VALUE")) {
        bool isFindHap = false;
        size_t index = 0;
        const auto& filePath = jsonObj["FILE_PATH"];
        for (size_t i = 0; i < filePath.size(); i++) {
            const std::string& path = filePath[i];
            if (path.find(".hap") != std::string::npos) {
                isFindHap = true;
                index = i;
                break;
            }
        }
        if (!isFindHap || (jsonObj["HASH_VALUE"].size() <= index)) {
            SGLOGE("Failed to find the hash value of hap");
            return false;
        }
        jsonObj["HASH_VALUE"] = jsonObj["HASH_VALUE"][index];
    }
    return true;
}
} // OHOS::Security::SecurityGuard