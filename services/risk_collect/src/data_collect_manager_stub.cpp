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

#include "data_collect_manager_stub.h"

#include "bigdata.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_format.h"
#include "data_manager_wrapper.h"
#include "i_data_collect_manager.h"
#include "ipc_skeleton.h"
#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "risk_collect_define.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
}

int32_t DataCollectManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    SGLOGD("%{public}s", __func__);
    do {
        if (IDataCollectManager::GetDescriptor() != data.ReadInterfaceToken()) {
            SGLOGE("descriptor error");
            break;
        }

        switch (code) {
            case CMD_DATA_COLLECT: {
                return HandleDataCollectCmd(data, reply);
            }
            case CMD_DATA_REQUEST: {
                return HandleDataRequestCmd(data, reply);
            }
            default: {
                break;
            }
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrorCode DataCollectManagerStub::HandleDataCollectCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    uint32_t expected = sizeof(int64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    int64_t eventId = data.ReadInt64();
    std::string version = data.ReadString();
    std::string time = data.ReadString();
    std::string content = data.ReadString();
    if (!DataFormat::CheckRiskContent(content)) {
        SGLOGE("CheckRiskContent error");
        return BAD_PARAM;
    }
    SGLOGI("eventId=%{public}ld, version=%{public}s, date=%{public}s", eventId, version.c_str(), time.c_str());
    EventDataSt eventData {
        .eventId = eventId,
        .version = version,
        .date = time,
        .content = content
    };
    TaskHandler::Task task = [eventData] {
        ErrorCode code = DataManagerWrapper::GetInstance().AddCollectInfo(eventData);
        if (code != SUCCESS) {
            SGLOGE("AddCollectInfo error, %{public}d", code);
        }
    };
    TaskHandler::GetInstance()->AddTask(task);
    return SUCCESS;
}

ErrorCode DataCollectManagerStub::HandleDataRequestCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    ObatinDataEvent event;
    auto pid = IPCSkeleton::GetCallingPid();
    event.pid = pid;
    event.time = SecurityGuardUtils::GetData();
    const uint32_t expected = 4;
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string devId = data.ReadString();
    std::string eventList = data.ReadString();
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return BAD_PARAM;
    }
    SGLOGI("eventList=%{public}s", eventList.c_str());
    auto promise = std::make_shared<std::promise<int32_t>>();
    auto future = promise->get_future();
    PushDataCollectTask(object, eventList, devId, promise);
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait for result timeout");
        event.size = 0;
    } else {
        event.size = future.get();
    }
    SGLOGI("ReportObatinDataEvent");
    BigData::ReportObatinDataEvent(event);
    return SUCCESS;
}

void DataCollectManagerStub::PushDataCollectTask(sptr<IRemoteObject> &object,
    std::string eventList, std::string devId, std::shared_ptr<std::promise<int32_t>> &promise)
{
    TaskHandler::Task task = [=, &promise] () mutable {
        auto proxy = new (std::nothrow) DataCollectManagerCallbackProxy(object);
        if (proxy == nullptr) {
            promise->set_value(0);
            return;
        }
        std::vector<int64_t> eventListVec;
        ErrorCode code = ParseEventList(eventList, eventListVec);
        if (code != SUCCESS) {
            SGLOGE("ParseEventList error, code=%{public}d", code);
            std::string empty;
            proxy->ResponseRiskData(devId, empty, FINISH);
            promise->set_value(0);
            return;
        }

        std::vector<EventDataSt> events;
        DataManagerWrapper::GetInstance().GetEventDataById(eventListVec, events);
        int32_t curIndex = 0;
        int32_t lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        auto maxIndex = static_cast<int32_t>(events.size());
        promise->set_value(maxIndex);
        SGLOGI("events size=%{public}d", maxIndex);
        std::vector<EventDataSt> dispatchVec;

        while (lastIndex < maxIndex) {
            std::string dispatch;
            dispatchVec.assign(events.begin() + curIndex, events.begin() + lastIndex);
            for (const EventDataSt& event : dispatchVec) {
                nlohmann::json jsonObj(event);
                dispatch += jsonObj.dump();
            }

            (void) proxy->ResponseRiskData(devId, dispatch, CONTINUE);
            curIndex = lastIndex;
            lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        }

        // last dispatch
        std::string dispatch;
        dispatchVec.assign(events.begin() + curIndex, events.end());
        for (const EventDataSt &event : dispatchVec) {
            nlohmann::json jsonObj(event);
            dispatch += jsonObj.dump();
        }
        (void) proxy->ResponseRiskData(devId, dispatch, FINISH);
    };

    TaskHandler::GetInstance()->AddTask(task);
}

ErrorCode DataCollectManagerStub::ParseEventList(std::string eventList, std::vector<int64_t> &eventListVec)
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