/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fstream>
#include <unordered_map>
#include <dlfcn.h>
#include "string_ex.h"
#include "nlohmann/json.hpp"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "json_cfg.h"
#include "system_ability_definition.h"
#include "task_handler.h"
#include "security_guard_utils.h"
#include "real_time_detect_callback_proxy.h"
#include "acquire_data_manager.h"
#include "data_collect_manager.h"
#include "real_time_detect_service.h"

namespace OHOS::Security::SecurityGuard {

REGISTER_SYSTEM_ABILITY_BY_ID(RealTimeDetectService, REAL_TIME_DETECT_SA_ID, true);

RealTimeDetectService::RealTimeDetectService(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
    SGLOGE("%{public}s", __func__);
}

bool RealTimeDetectService::GetEventList(std::vector<int64_t> &eventsId, std::vector<std::string> &eventsSecurityLevel)
{
    SGLOGI("Start GetEventList");
    std::ifstream stream("/system/etc/real_time_upload_event.cfg", std::ios::in);
    if (!stream) {
        SGLOGE("Stream error, %{public}s", strerror(errno));
        return false;
    }

    nlohmann::json json;
    stream >> json;
    stream.close();

    if (json.is_discarded()) {
        SGLOGE("Parse json error");
        return false;
    }
    std::vector<std::string> eventList;

    for (const auto &eventObj : json["uploadEvents"]) {
        if (eventObj.contains("eventId") && !eventObj["eventId"].is_null() && eventObj.contains("securityLevel") &&
            !eventObj["securityLevel"].is_null()) {
            std::string eventId = eventObj["eventId"].get<std::string>();
            std::string securityLevel = eventObj["securityLevel"].get<std::string>();

            eventsSecurityLevel.emplace_back(securityLevel);
            int64_t tmp = 0;
            if (SecurityGuardUtils::StrToI64Hex(eventId, tmp)) {
                eventsId.emplace_back(tmp);
            }
        }
    }
    return true;
}

void RealTimeDetectService::OnStart()
{
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }
    AddSystemAbilityListener(DATA_COLLECT_MANAGER_SA_ID);
    std::vector<int64_t> eventsId;
    std::vector<std::string> eventsSecurityLevel;
    if (!GetEventList(eventsId, eventsSecurityLevel)) {
        SGLOGE("GetEventList error");
        return;
    }

    for (const auto &it : eventsId) {
        SecurityCollector::Event sgEvent;
        sgEvent.eventId = it;
        auto subscriber = std::make_shared<SecurityGuardSubscriber>(sgEvent);
        int32_t code = AcquireDataManager::GetInstance().Subscribe(subscriber);
        if (code != SUCCESS) {
            SGLOGE("Subscribe failed, code=%{public}d", code);
            return;
        }
        sgSubscribeMap_[it] = subscriber;
    }
    UploadManager::GetInstance().Init(eventsId, eventsSecurityLevel);
}

void RealTimeDetectService::OnStop()
{
    SGLOGI("%{public}s", __func__);
}

bool RealTimeDetectService::UploadManager::Init(std::vector<int64_t> eventsId,
                                                std::vector<std::string> eventsSecurityLevel)
{
    eventsIdIndex = eventsId;
    eventsSecurityLevelIndex = eventsSecurityLevel;
    handle = dlopen("libdevice_health_attestation_ca.z.so", RTLD_LAZY);
    if (handle != nullptr) {
        readRpmbFunc = (ReadRpmbFunc)dlsym(handle, "DHA_ReadSecurityGuardEventFromRpmb");
        writeRpmbFunc = (WriteRpmbFunc)dlsym(handle, "DHA_WriteSecurityGuardEventToRpmb");
    }

    uint8_t data[RPMB_SIZE] = { 0 };
    if (readRpmbFunc != nullptr) {
        uint32_t ret = readRpmbFunc(RPMB_START_POS, data, RPMB_SIZE);
        SGLOGI("Read RPMB Func ret: %{public}d", ret);
    }

    std::unordered_map<int32_t, int64_t> rpmbEventIndexMap;

    for (int32_t index = 0; index < static_cast<int32_t>(eventsIdIndex.size()); ++index) {
        rpmbEventIndexMap[index] = eventsIdIndex[index];
    }

    std::vector<int32_t> rpmbEventIndex = {};
    for (int32_t i = 0; i < RPMB_SIZE; ++i) {
        if (data[i] != 0) {
            if (rpmbEventIndexMap[i] != 0) {
                SGLOGI("RPMB has event: %{public}" PRId64 "", rpmbEventIndexMap[i]);
                AddQueue(rpmbEventIndexMap[i]);
            }
        }
    }

    TaskHandler::Task task = [this]() {
        UploadManager::UploadTask();
    };
    TaskHandler::GetInstance()->AddTask(task);
    return true;
}

bool RealTimeDetectService::UploadManager::Publish(const SecurityCollector::Event &event)
{
    AddQueue(event);
    return true;
}

void RealTimeDetectService::UploadManager::AddQueue(const SecurityCollector::Event &event)
{
    SGLOGI("Event Add to uploadQueue start");
    int64_t addEventId = event.eventId;
    int32_t queueSize = 0;
    std::queue<SecurityCollector::Event> queueCopy;
    std::set<int64_t> blackList;
    {
        std::lock_guard<std::mutex> lock(uploadQueueMutex);
        blackList = reportSuccessList;
        for (const auto &failEventId : reportFailedList) {
            blackList.insert(failEventId);
        }
        queueCopy = uploadQueue;
    }

    while (!queueCopy.empty()) {
        SecurityCollector::Event element = queueCopy.front();
        queueCopy.pop();
        blackList.insert(element.eventId);
    }

    if (blackList.find(addEventId) == blackList.end()) {
        std::lock_guard<std::mutex> lock(uploadQueueMutex);
        uploadQueue.push(event);
        queueSize = static_cast<int32_t>(uploadQueue.size());
    }

    if (queueSize >= QUEUE_MAX_SIZE)
        queueSendCond.notify_one();
    SGLOGI("Event Add to uploadQueue end");
}

std::string SecurityEventJson(const SecurityCollector::SecurityEvent &event)
{
    nlohmann::json jsonEvent;
    jsonEvent["eventId"] = event.GetEventId();
    jsonEvent["version"] = event.GetVersion();
    jsonEvent["content"] = event.GetContent();

    return jsonEvent.dump();
}

void RealTimeDetectService::UploadManager::AddQueue(const int64_t &eventId)
{
    SGLOGI("AddQueue(eventId) start");
    int64_t addEventId = eventId;
    int32_t queueSize = 0;
    std::queue<SecurityCollector::Event> queueCopy;
    std::set<int64_t> blackList;
    {
        std::lock_guard<std::mutex> lock(uploadQueueMutex);
        blackList = reportSuccessList;
        for (const auto &failEventId : reportFailedList) {
            blackList.insert(failEventId);
        }
        queueCopy = uploadQueue;
    }
    while (!queueCopy.empty()) {
        SecurityCollector::Event element = queueCopy.front();
        queueCopy.pop();
        blackList.insert(static_cast<int64_t>(element.eventId));
    }
    if (blackList.find(addEventId) != blackList.end()) {
        SGLOGI("EventId already in uploadQueue, End");
        return;
    }

    SecurityCollector::SecurityEventRuler ruler(addEventId);
    auto callback = std::make_shared<UploadQueryCallback>();
    replyEvents.clear();
    int32_t ret = SecurityGuard::DataCollectManager::GetInstance().QuerySecurityEvent({ ruler }, callback);
    std::unique_lock<std::mutex> queryLock(callback->queryMutex);
    const int32_t WAIT_TIME = 3;
    callback->queryCond.wait_for(queryLock, std::chrono::seconds(WAIT_TIME));

    SGLOGI("Query Security Event ret: %{public}d", ret);
    if (replyEvents.empty()) {
        return;
    }
    SecurityCollector::Event event = {};
    event.eventId = replyEvents[0].GetEventId();
    event.version = replyEvents[0].GetVersion();
    event.content = replyEvents[0].GetContent();
    {
        std::lock_guard<std::mutex> lock(uploadQueueMutex);
        uploadQueue.push(event);
        queueSize = static_cast<int32_t>(uploadQueue.size());
    }
    if (queueSize >= QUEUE_MAX_SIZE)
        queueSendCond.notify_one();
}

std::vector<std::vector<SecurityCollector::Event>> RealTimeDetectService::UploadManager::QueuePagination(
    const int32_t &size)
{
    std::vector<std::vector<SecurityCollector::Event>> result;
    while (!uploadQueue.empty()) {
        std::vector<SecurityCollector::Event> subVector;
        for (int32_t i = 0; i < size && !uploadQueue.empty(); ++i) {
            SecurityCollector::Event event = uploadQueue.front();
            uploadQueue.pop();
            subVector.push_back(event);
        }
        result.push_back(subVector);
    }

    return result;
}

bool RealTimeDetectService::UploadManager::CallWriteRpmb()
{
    SGLOGD("WriteRpmb Calling");
    std::chrono::steady_clock::time_point nextCallTime = callRpmbWriteTime + std::chrono::hours(24);
    if (std::chrono::steady_clock::now() > nextCallTime) {
        writeRpmbCount = 0;
        callRpmbWriteTime = std::chrono::steady_clock::now();
    }

    if (writeRpmbCount >= RPMB_WRITE_MAX) {
        return false;
    }

    uint8_t mockRpmbData[RPMB_SIZE] = { 0 };
    std::unordered_map<int64_t, int32_t> rpmbEventIndex;
    for (int32_t index = 0; index < static_cast<int32_t>(eventsIdIndex.size()); ++index) {
        rpmbEventIndex[eventsIdIndex[index]] = index;
    }

    for (const int64_t &failEvnetId : reportFailedList) {
        if (eventsSecurityLevelIndex[rpmbEventIndex[failEvnetId]] == "fatal") {
            mockRpmbData[rpmbEventIndex[failEvnetId]] = 1;
        }
    }
    if (std::all_of(mockRpmbData, mockRpmbData + RPMB_SIZE, [](uint8_t elem) { return elem == 0; })) {
        return false;
    }

    if (writeRpmbFunc != nullptr) {
        uint32_t ret = writeRpmbFunc(RPMB_START_POS, mockRpmbData, RPMB_SIZE);
        SGLOGI("Write RPMB Func ret: %{public}d", ret);
        ++writeRpmbCount;
    }
    return true;
}

void RealTimeDetectService::UploadManager::Upload()
{
    std::unique_lock<std::mutex> lock(uploadQueueMutex);
    queueSendCond.wait_for(lock, std::chrono::seconds(UPLOAD_PERIODICALLLY));
    std::vector<SecurityCollector::Event> succeeUploadEvents = {};
    std::vector<SecurityCollector::Event> failedUploadEvents = {};
    std::vector<std::vector<SecurityCollector::Event>> uploadDatas = QueuePagination(HSDR_INTERFACE_SIZE);
    SGLOGD("UploadTask Pagination Queue done");
    for (const auto &uploadData : uploadDatas) {
        hsdrSendEvents.clear();
        for (const auto &event : uploadData) {
            hsdrSendEvents.push_back({ event.eventId, event.version, event.content });
        }

        SGLOGI("Upload data to HSDR");
        AAFwk::Want want;
        std::string bundleName = "com.huawei.hmos.hsdr";
        std::string abilityName = "UploadSecurityEventsService";
        want.SetAction("security_guard");
        want.SetElementName(bundleName, abilityName);
        sptr<UploadAbilityConnection> abilityConnection = new UploadAbilityConnection();
        auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, abilityConnection,
                                                                                               HSDR_INTERFACE_SIZE);
        SGLOGI("HSDR Connect result ret: %{public}d", ret);
        std::this_thread::sleep_for(std::chrono::milliseconds(HSDR_INTERFACE_WAIT_TIME));
        auto ret1 = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(abilityConnection);
        SGLOGI("HSDR Disconnect result ret: %{public}d", ret1);
        if (uploadStatus == 0) {
            for (const auto &event : uploadData) {
                reportSuccessList.insert(event.eventId);
                reportFailedList.erase(event.eventId);
            }
        } else {
            for (const auto &event : uploadData) {
                reportFailedList.insert(event.eventId);
            }
        }
    }
}

void RealTimeDetectService::UploadManager::UploadTask()
{
    while (true) {
        SGLOGD("UploadTask Start");
        Upload();
        if (oldReportFailedList.size() != reportFailedList.size()) {
            oldReportFailedList = reportFailedList;
            CallWriteRpmb();
        }
    }
}
}  // namespace OHOS::Security::SecurityGuard