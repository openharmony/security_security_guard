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

#include "acquire_data_subscribe_manager.h"
#include "bigdata.h"
#include "config_data_manager.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_format.h"
#include "database_manager.h"
#include "hiview_collector.h"
#include "kernel_interface_adapter.h"
#include "risk_collect_define.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "task_handler.h"
#include "uevent_listener.h"
#include "uevent_listener_impl.h"
#include "uevent_notify.h"

#include "risk_event_rdb_helper.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TWO_ARGS = 2;
    constexpr int32_t TIMEOUT_REPLY = 10000;
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

    DatabaseManager::GetInstance().Init(); // Make sure the database is ready

    AddSystemAbilityListener(RISK_ANALYSIS_MANAGER_SA_ID);
    AddSystemAbilityListener(SOFTBUS_SERVER_SA_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(DFX_SYS_HIVIEW_ABILITY_ID);
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
    SecEvent secEvent;
    int code = DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, secEvent);
    if (code != SUCCESS) {
        SGLOGE("query event error, code=%{public}d", code);
        return;
    }
    dprintf(fd, "eventId : %ld\n", secEvent.eventId);
    dprintf(fd, "report time : %s\n", secEvent.date.c_str());
    dprintf(fd, "report version : %s\n", secEvent.version.c_str());
}

int32_t DataCollectManagerService::RequestDataSubmit(int64_t eventId, std::string &version, std::string &time,
    std::string &content)
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
    SGLOGD("eventId=%{public}" PRId64 ", version=%{public}s, date=%{public}s", eventId, version.c_str(), time.c_str());
    SecEvent event {
        .eventId = eventId,
        .version = version,
        .date = time,
        .content = content
    };
    TaskHandler::Task task = [event] () mutable {
        int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, event);
        if (code != SUCCESS) {
            SGLOGE("insert event error, %{public}d", code);
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
    event.time = SecurityGuardUtils::GetDate();
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

std::vector<SecEvent> DataCollectManagerService::GetSecEventsFromConditions(RequestCondition &condition)
{
    std::vector<SecEvent> events;
    if (condition.beginTime.empty() && condition.endTime.empty()) {
        (void) DatabaseManager::GetInstance().QueryEventByEventId(RISK_TABLE, condition.riskEvent, events);
        (void) DatabaseManager::GetInstance().QueryEventByEventId(AUDIT_TABLE, condition.auditEvent, events);
    } else {
        (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(RISK_TABLE, condition.riskEvent, events,
            condition.beginTime, condition.endTime);
        (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(AUDIT_TABLE, condition.auditEvent, events,
            condition.beginTime, condition.endTime);
    }
    return events;
}

void DataCollectManagerService::PushDataCollectTask(const sptr<IRemoteObject> &object,
    std::string conditions, std::string devId, std::shared_ptr<std::promise<int32_t>> promise)
{
    TaskHandler::Task task = [object, conditions, devId, promise] () mutable {
        auto proxy = iface_cast<DataCollectManagerCallbackProxy>(object);
        if (proxy == nullptr) {
            promise->set_value(0);
            return;
        }
        RequestCondition reqCondition {};
        DataFormat::ParseConditions(conditions, reqCondition);
        if (reqCondition.riskEvent.empty() && reqCondition.auditEvent.empty()) {
            SGLOGE("reqCondition no permission");
            std::string empty;
            proxy->ResponseRiskData(devId, empty, FINISH);
            promise->set_value(0);
            return;
        }

        std::vector<SecEvent> events = GetSecEventsFromConditions(reqCondition);
        int32_t curIndex = 0;
        int32_t lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        auto maxIndex = static_cast<int32_t>(events.size());
        promise->set_value(maxIndex);
        SGLOGI("events size=%{public}d", maxIndex);
        std::vector<SecEvent> dispatchVec;
        while (lastIndex < maxIndex) {
            dispatchVec.assign(events.begin() + curIndex, events.begin() + lastIndex);
            std::string dispatch = nlohmann::json(dispatchVec).dump();
            SGLOGD("dispatch size=%{public}d", (int)dispatch.size());
            (void) proxy->ResponseRiskData(devId, dispatch, CONTINUE);
            curIndex = lastIndex;
            lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        }

        // last dispatch
        dispatchVec.assign(events.begin() + curIndex, events.end());
        std::string dispatch = nlohmann::json(dispatchVec).dump();
        (void) proxy->ResponseRiskData(devId, dispatch, FINISH);
        SGLOGI("ResponseRiskData FINISH");
    };
    TaskHandler::GetInstance()->AddTask(task);
}

void DataCollectManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGI("OnAddSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
    if (systemAbilityId == RISK_ANALYSIS_MANAGER_SA_ID) {
        TaskHandler::Task listenerTask = [] {
            KernelInterfaceAdapter adapter;
            UeventNotify notify(adapter);
            std::vector<int64_t> whiteList = ConfigDataManager::GetInstance().GetAllEventIds();
            notify.AddWhiteList(whiteList);
            notify.NotifyScan();

            UeventListenerImpl impl(adapter);
            UeventListener listener(impl);
            listener.Start();
        };
        TaskHandler::GetInstance()->AddTask(listenerTask);
        return;
    }
    if (systemAbilityId == SOFTBUS_SERVER_SA_ID || systemAbilityId == DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) {
        (void)DatabaseManager::GetInstance().InitDeviceId();
        return;
    }
    if (systemAbilityId == DFX_SYS_HIVIEW_ABILITY_ID) {
        TaskHandler::Task hiviewListenerTask = [] {
            auto collector = std::make_shared<HiviewCollector>();
            collector->Collect("PASTEBOARD", "USE_BEHAVIOUR");
        };
        TaskHandler::GetInstance()->AddTask(hiviewListenerTask);
        return;
    }
}

void DataCollectManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

int32_t DataCollectManagerService::Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGD("DataCollectManagerService, start subscribe");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, REPORT_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient(this);
        if (deathRecipient_ == nullptr) {
            SGLOGE("no memory");
            return NULL_OBJECT;
        }
    }
    callback->AddDeathRecipient(deathRecipient_);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, callback);

    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = subscribeInfo.GetEvent().eventId;
    event.ret = ret;
    SGLOGI("DataCollectManagerService, InsertSubscribeRecord eventId=%{public}" PRId64 "", event.eventId);
    BigData::ReportSgSubscribeEvent(event);

    return ret;
}

int32_t DataCollectManagerService::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, REPORT_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (deathRecipient_ != nullptr) {
        callback->RemoveDeathRecipient(deathRecipient_);
    }

    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(callback);
    SgUnsubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.ret = ret;
    SGLOGI("DataCollectManagerService, RemoveSubscribeRecord ret=%{ret}d", ret);
    BigData::ReportSgUnsubscribeEvent(event);
    return ret;
}

void DataCollectManagerService::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGE("enter");
    if (remote == nullptr) {
        SGLOGE("remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return;
    }
    sptr<DataCollectManagerService> service = service_.promote();
    if (service == nullptr) {
        SGLOGE("service is nullptr");
        return;
    }
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(object);
    if (object->IsProxyObject() && service->deathRecipient_ != nullptr) {
        object->RemoveDeathRecipient(service->deathRecipient_);
    }
    SGLOGE("end");
}
}
