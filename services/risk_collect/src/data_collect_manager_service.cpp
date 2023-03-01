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

#include "data_collect_manager_service.h"

#include <thread>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

#include "bigdata.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_format.h"
#include "data_manager_wrapper.h"
#include "hiview_collector.h"
#include "kernel_interface_adapter.h"
#include "model_analysis.h"
#include "risk_collect_define.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"
#include "uevent_listener.h"
#include "uevent_listener_impl.h"
#include "uevent_notify.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TWO_ARGS = 2;
    constexpr int32_t TIMEOUT_REPLY = 500;
    const std::string REPORT_PERMISSION = "ohos.permission.securityguard.REPORT_SECURITY_INFO";
    const std::string REQUEST_PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO";
}

REGISTER_SYSTEM_ABILITY_BY_ID(DataCollectManagerService, DATA_COLLECT_MANAGER_SA_ID, true);

DataCollectManagerService::DataCollectManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void DataCollectManagerService::OnStart()
{
    SGLOGI("%{public}s", __func__);
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }

    TaskHandler::Task loadDbTask = [] {
        DataManagerWrapper::GetInstance().LoadCacheData();
    };
    TaskHandler::GetInstance()->AddTask(loadDbTask);

    TaskHandler::Task listenerTask = [] {
        KernelInterfaceAdapter adapter;
        UeventNotify notify(adapter);
        std::vector<int64_t> whiteList = ModelAnalysis::GetInstance().GetAllEventIds();
        notify.AddWhiteList(whiteList);
        notify.NotifyScan();

        UeventListenerImpl impl(adapter);
        UeventListener listener(impl);
        listener.Start();
    };
    TaskHandler::GetInstance()->AddTask(listenerTask);
    TaskHandler::Task hiviewListenerTask = [] {
        auto collector = std::make_shared<HiviewCollector>();
        collector->Collect("SECURITY_GUARD", "RISK_ANALYSIS");
    };
    TaskHandler::GetInstance()->AddTask(hiviewListenerTask);
}

void DataCollectManagerService::OnStop()
{
}

int DataCollectManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    SGLOGI("DataCollectManagerService Dump");
    if (fd < 0) {
        return BAD_PARAM;
    }

    std::string arg0 = ((args.size() == 0) ? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -i <EVENT_ID>: dump special eventId\n");
    } else if (arg0.compare("-i") == 0) {
        if (args.size() < TWO_ARGS) {
            return BAD_PARAM;
        }

        int64_t eventId;
        bool isSuccess = SecurityGuardUtils::StrToI64(Str16ToStr8(args.at(1)), eventId);
        if (!isSuccess) {
            return BAD_PARAM;
        }

        DumpEventInfo(fd, eventId);
    }
    return ERR_OK;
}

void DataCollectManagerService::DumpEventInfo(int fd, int64_t eventId)
{
    std::vector<int64_t> eventIds {eventId};
    std::vector<EventDataSt> eventData;
    ErrorCode code = DataManagerWrapper::GetInstance().GetEventDataById(eventIds, eventData);
    if (code != SUCCESS || eventData.size() == 0) {
        SGLOGE("GetEventDataById error");
        return;
    }
    sort(eventData.begin(), eventData.end(),
        [] (const EventDataSt &a, const EventDataSt &b) -> bool {
            return a.date > b.date;
        });
    dprintf(fd, "eventId : %ld\n", eventData.at(0).eventId);
    dprintf(fd, "report time : %s\n", eventData.at(0).date.c_str());
    dprintf(fd, "report version : %s\n", eventData.at(0).version.c_str());
}

int32_t DataCollectManagerService::RequestDataSubmit(int64_t eventId, std::string version, std::string time,
    std::string content)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, REPORT_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
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

int32_t DataCollectManagerService::RequestRiskData(std::string &devId, std::string &eventList,
    const sptr<IRemoteObject> &callback)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, REQUEST_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
    ObatinDataEvent event;
    auto pid = IPCSkeleton::GetCallingPid();
    event.pid = pid;
    event.time = SecurityGuardUtils::GetData();
    SGLOGI("eventList=%{public}s", eventList.c_str());
    auto promise = std::make_shared<std::promise<int32_t>>();
    auto future = promise->get_future();
    PushDataCollectTask(callback, eventList, devId, promise);
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

void DataCollectManagerService::PushDataCollectTask(const sptr<IRemoteObject> &object,
    std::string eventList, std::string devId, std::shared_ptr<std::promise<int32_t>> &promise)
{
    TaskHandler::Task task = [=, &promise] () mutable {
        auto proxy = iface_cast<DataCollectManagerCallbackProxy>(object);
        if (proxy == nullptr) {
            promise->set_value(0);
            return;
        }
        std::vector<int64_t> eventListVec;
        ErrorCode code = DataFormat::ParseEventList(eventList, eventListVec);
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
}