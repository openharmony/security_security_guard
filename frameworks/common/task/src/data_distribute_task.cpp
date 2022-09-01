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

#include "data_distribute_task.h"

#include "iremote_broker.h"

#include <nlohmann/json.hpp>

#include "data_collect_manager_callback_proxy.h"
#include "data_manager_wrapper.h"
#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "risk_collect_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
using nlohmann::json;
DataDistributeTask::DataDistributeTask(std::string &devId, std::string &eventList, sptr<IRemoteObject> &obj)
    : devId_(devId), eventList_(eventList), obj_(obj)
{
}

void DataDistributeTask::OnExecute()
{
    auto proxy = new (std::nothrow) DataCollectManagerCallbackProxy(obj_);
    if (proxy == nullptr) {
        return;
    }
    std::vector<int64_t> eventListVec;
    ErrorCode code = ParseEventList(eventList_, eventListVec);
    if (code != SUCCESS) {
        SGLOGE("ParseEventList error, code=%{public}u", code);
        std::string empty;
        proxy->ResponseRiskData(devId_, empty, FINISH);
        return;
    }

    std::vector<EventDataSt> events;
    DataManagerWrapper::GetInstance().GetEventDataById(eventListVec, events);
    int32_t curIndex = 0;
    int32_t lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
    auto maxIndex = static_cast<int32_t>(events.size());
    SGLOGI("events size=%{public}u", maxIndex);
    std::vector<EventDataSt> dispatchVec;

    while (lastIndex < maxIndex) {
        std::string dispatch;
        dispatchVec.assign(events.begin() + curIndex, events.begin() + lastIndex);
        for (const EventDataSt& event : dispatchVec) {
            json jsonObj(event);
            dispatch += jsonObj.dump();
        }

        SGLOGI("dispatch=%{public}s", dispatch.c_str());
        (void) proxy->ResponseRiskData(devId_, dispatch, CONTINUE);
        curIndex = lastIndex;
        lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
    }

    // last dispatch
    std::string dispatch;
    dispatchVec.assign(events.begin() + curIndex, events.end());
    for (const EventDataSt &event : dispatchVec) {
        json jsonObj(event);
        dispatch += jsonObj.dump();
    }

    SGLOGI("last dispatch=%{public}s", dispatch.c_str());
    (void) proxy->ResponseRiskData(devId_, dispatch, FINISH);
}

ErrorCode DataDistributeTask::ParseEventList(std::string &eventList, std::vector<int64_t> &eventListVec)
{
    json jsonObj = json::parse(eventList, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("json parse error");
        return JSON_ERR;
    }

    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, EVENT_CFG_EVENT_ID_KEY, array, JSON_ERR);
    ErrorCode code = FAILED;
    json &eventListJson = jsonObj[EVENT_CFG_EVENT_ID_KEY];
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