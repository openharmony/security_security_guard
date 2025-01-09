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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

#include "acquire_data_subscribe_manager.h"
#include "bigdata.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_format.h"
#include "database_manager.h"
#include "data_collection.h"
#include "hiview_collector.h"
#include "risk_collect_define.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "task_handler.h"
#include "config_manager.h"
#include "risk_event_rdb_helper.h"
#include "model_cfg_marshalling.h"
#include "config_subscriber.h"


namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TWO_ARGS = 2;
    constexpr int32_t TIMEOUT_REPLY = 10000;
    const std::string REPORT_PERMISSION = "ohos.permission.securityguard.REPORT_SECURITY_INFO";
    const std::string REPORT_PERMISSION_NEW = "ohos.permission.REPORT_SECURITY_EVENT";
    const std::string REQUEST_PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO";
    const std::string MANAGE_CONFIG_PERMISSION = "ohos.permission.MANAGE_SECURITY_GUARD_CONFIG";
    const std::string QUERY_SECURITY_EVENT_PERMISSION = "ohos.permission.QUERY_SECURITY_EVENT";
    constexpr int32_t CFG_FILE_MAX_SIZE = 1 * 1024 * 1024;
    constexpr int32_t CFG_FILE_BUFF_SIZE = 1 * 1024 * 1024 + 1;
    const std::unordered_map<std::string, std::vector<std::string>> g_apiPermissionsMap {
        {"RequestDataSubmit", {REPORT_PERMISSION, REPORT_PERMISSION_NEW}},
        {"QuerySecurityEvent", {REPORT_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStart", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStop", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"Subscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"UnSubscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"ConfigUpdate", {MANAGE_CONFIG_PERMISSION}}
    };
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
    AddSystemAbilityListener(DFX_SYS_HIVIEW_ABILITY_ID);
    bool success = ConfigManager::InitConfig<EventConfig>();
        if (!success) {
        SGLOGE("init event config error");
    }
    std::vector<int64_t> eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    std::vector<int64_t> onStartEventList;
    for (int64_t eventId : eventIds) {
        EventCfg eventCfg;
        bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, eventCfg);
        if (!isSuccess) {
            SGLOGI("GetEventConfig error");
        } else if (eventCfg.collectOnStart == 1) {
            onStartEventList.push_back(eventId);
        }
    }
    SecurityCollector::DataCollection::GetInstance().SecurityGuardSubscribeCollector(onStartEventList);
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
    std::string &content, bool isSync)
{
    SGLOGD("enter DataCollectManagerService RequestDataSubmit");
    SGLOGD("isSync: %{public}s", isSync ? "true" : "false");
    int32_t ret = IsApiHasPermission("RequestDataSubmit");
    if (ret != SUCCESS) {
        return ret;
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
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            SGLOGE("not system app no permission");
            return NO_SYSTEMCALL;
        }
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
    } else {
        (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(RISK_TABLE, condition.riskEvent, events,
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
}

void DataCollectManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

int32_t DataCollectManagerService::Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGD("DataCollectManagerService, start subscribe");
    int32_t ret = IsApiHasPermission("Subscribe");
    if (ret != SUCCESS) {
        return ret;
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
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, callback);
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
    int32_t ret = IsApiHasPermission("UnSubscribe");
    if (ret != SUCCESS) {
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (deathRecipient_ != nullptr) {
        callback->RemoveDeathRecipient(deathRecipient_);
    }

    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(callback);
    SgUnsubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.ret = ret;
    SGLOGI("DataCollectManagerService, RemoveSubscribeRecord ret=%{public}d", ret);
    BigData::ReportSgUnsubscribeEvent(event);
    return ret;
}

bool DataCollectManagerService::QueryEventByRuler(sptr<ISecurityEventQueryCallback> proxy,
    SecurityCollector::SecurityEventRuler ruler)
{
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(ruler.GetEventId(), config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return true;
    }
    std::vector<SecurityCollector::SecurityEvent> replyEvents;
    std::vector<int64_t> eventIds{ruler.GetEventId()};
    SGLOGD("eventType is %{public}u", config.eventType);
    if (config.eventType == 1) { // query in collector
        int32_t code = SecurityCollector::CollectorManager::GetInstance().QuerySecurityEvent(
            {ruler}, replyEvents);
        if (code != SUCCESS) {
            proxy->OnError("QuerySecurityEvent failed");
            return false;
        }
        proxy->OnQuery(replyEvents);
    } else {
        std::vector<SecEvent> events;
        if (ruler.GetBeginTime().empty() && ruler.GetEndTime().empty()) {
            (void) DatabaseManager::GetInstance().QueryEventByEventId(ruler.GetEventId(), events);
        } else {
            (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(RISK_TABLE, eventIds, events,
                ruler.GetBeginTime(), ruler.GetEndTime());
        }
        std::transform(events.begin(), events.end(),
            std::back_inserter(replyEvents), [] (SecEvent event) {
            return SecurityCollector::SecurityEvent(event.eventId, event.version, event.content);
        });
        proxy->OnQuery(replyEvents);
    }
    return true;
}

int32_t DataCollectManagerService::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    const sptr<IRemoteObject> &callback)
{
    SGLOGE("enter QuerySecurityEvent");
    int32_t ret = IsApiHasPermission("QuerySecurityEvent");
    if (ret != SUCCESS) {
        return ret;
    }
    auto proxy = iface_cast<ISecurityEventQueryCallback>(callback);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return NULL_OBJECT;
    }

    TaskHandler::Task task = [proxy, rulers] {
        if (std::any_of(rulers.begin(), rulers.end(), [proxy] (auto const &ruler) {
                return !QueryEventByRuler(proxy, ruler);
            })) {
            return;
        }
        proxy->OnComplete();
    };

    TaskHandler::GetInstance()->AddTask(task);
    return SUCCESS;
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

int32_t DataCollectManagerService::CollectorStart(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter CollectorStart.");
    int32_t code = IsApiHasPermission("CollectorStart");
    if (code != SUCCESS) {
        return code;
    }
    code = SecurityCollector::CollectorManager::GetInstance().CollectorStart(subscribeInfo);
    if (code != SUCCESS) {
        SGLOGI("CollectorStart failed, code=%{public}d", code);
        return code;
    }
    return SUCCESS;
}

int32_t DataCollectManagerService::CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter CollectorStop.");
    int32_t code = IsApiHasPermission("CollectorStop");
    if (code != SUCCESS) {
        return code;
    }
    code = SecurityCollector::CollectorManager::GetInstance().CollectorStop(subscribeInfo);
    if (code != SUCCESS) {
        SGLOGI("CollectorStop failed, code=%{public}d", code);
        return code;
    }
    return SUCCESS;
}

int32_t DataCollectManagerService::IsApiHasPermission(const std::string &api)
{
    if (g_apiPermissionsMap.count(api) == 0) {
        SGLOGE("api not in map");
        return FAILED;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(g_apiPermissionsMap.at(api).cbegin(), g_apiPermissionsMap.at(api).cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
        if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
            uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
            if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
                SGLOGE("not system app no permission");
                return NO_SYSTEMCALL;
            }
        }
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

bool DataCollectManagerService::WriteRemoteFileToLocal(const SecurityGuard::SecurityConfigUpdateInfo &info,
    const std::string &realPath)
{
    int32_t fd = info.GetFd();
    int32_t outputFd = dup(fd);
    close(fd);
    if (outputFd == -1) {
        SGLOGE("dup fd fail reason %{public}s", strerror(errno));
        return FAILED;
    }
    int32_t inputFd = open(realPath.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (inputFd < 0) {
        close(outputFd);
        SGLOGE("open file fail reason %{public}s", strerror(errno));
        return FAILED;
    }
    auto buffer = std::make_unique<char []>(CFG_FILE_BUFF_SIZE);
    if (buffer == nullptr) {
        SGLOGE("new fail");
        return NULL_OBJECT;
    }
    int offset = -1;
    while ((offset = read(outputFd, buffer.get(), sizeof(buffer))) > 0) {
        if (offset > CFG_FILE_MAX_SIZE || offset == 0) {
            close(outputFd);
            close(inputFd);
            SGLOGE("file is empty or too large, len =  %{public}d", offset);
            return BAD_PARAM;
        }
        if (write(inputFd, buffer.get(), offset) < 0) {
            close(inputFd);
            close(outputFd);
            SGLOGE("write file to the tmp dir failed");
            return FAILED;
        }
    }
    close(inputFd);
    fsync(outputFd);
    close(outputFd);
    return SUCCESS;
}

int32_t DataCollectManagerService::ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &info)
{
    SGLOGI("enter ConfigUpdate.");
    int32_t code = IsApiHasPermission("ConfigUpdate");
    if (code != SUCCESS) {
        return code;
    }
    std::string realPath = CONFIG_ROOT_PATH + "tmp/" + info.GetFileName();
    SGLOGI("config file is %{public}s, fd is %{public}d", realPath.c_str(), info.GetFd());
    auto it = std::find_if(CONFIG_CACHE_FILES.begin(), CONFIG_CACHE_FILES.end(),
        [realPath](const std::string &path) { return path == realPath; });
    if (it ==  CONFIG_CACHE_FILES.end()) {
        SGLOGE("file name err");
        return BAD_PARAM;
    }
    int32_t ret = WriteRemoteFileToLocal(info, realPath);
    if (ret != SUCCESS) {
        SGLOGE("write remote file to local fail");
        return ret;
    }
    if (!ConfigSubscriber::UpdateConfig(realPath)) {
        SGLOGE("update config fail");
        return FAILED;
    }
    return SUCCESS;
}
}
