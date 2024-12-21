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
#include <cstdio>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cinttypes>
#include <unistd.h>
#include <unordered_set>
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "string_ex.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "acquire_data_subscribe_manager.h"
#include "bigdata.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager.h"
#include "data_format.h"
#include "database_manager.h"
#include "data_collection.h"
#include "model_cfg_marshalling.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "ffrt.h"
#include "config_manager.h"
#include "risk_event_rdb_helper.h"
#include "config_subscriber.h"
#include "model_manager.h"
#include "config_define.h"

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
        {"QuerySecurityEvent", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStart", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStop", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"Subscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"UnSubscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"ConfigUpdate", {MANAGE_CONFIG_PERMISSION}},
        {"QuerySecurityEventConfig", {MANAGE_CONFIG_PERMISSION}},
        {"Mute", {QUERY_SECURITY_EVENT_PERMISSION}},
        {"Unmute", {QUERY_SECURITY_EVENT_PERMISSION}},
    };
    std::unordered_set<std::string> g_configCacheFilesSet;
    constexpr uint32_t FINISH = 0;
    constexpr uint32_t CONTINUE = 1;
    constexpr size_t MAX_DISTRIBUTE_LENS = 100;
#ifndef SECURITY_GUARD_ENABLE_EXT
    const std::string TRUST_LIST_FILE_PATH = "/system/etc/config_update_trust_list.json";
#else
    const std::string TRUST_LIST_FILE_PATH = "/system/etc/config_update_trust_list_ext.json";
#endif
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
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }
}

void DataCollectManagerService::OnStop()
{
    SecurityCollector::DataCollection::GetInstance().CloseLib();
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
    auto task = [event] () mutable {
        int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, event, {});
        if (code != SUCCESS) {
            SGLOGE("insert event error, %{public}d", code);
        }
    };
    ffrt::submit(task);
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
    std::vector<SecEvent> events {};
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
    auto task = [object, conditions, devId, promise] () mutable {
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
        size_t curIndex = 0;
        size_t lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        size_t maxIndex = events.size();
        promise->set_value(maxIndex);
        SGLOGI("events size=%{public}zu", maxIndex);
        std::vector<SecEvent> dispatchVec;
        while (lastIndex < maxIndex) {
            dispatchVec.assign(events.begin() + curIndex, events.begin() + lastIndex);
            std::string dispatch = nlohmann::json(dispatchVec).dump();
            SGLOGD("dispatch size=%{public}zu", dispatch.size());
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
    ffrt::submit(task);
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
    int32_t ret = FAILED;
    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = subscribeInfo.GetEvent().eventId;
    if (subscribeInfo.GetEventGroup() == "") {
        ret = IsApiHasPermission("Subscribe");
    } else {
        ret = IsEventGroupHasPermission(subscribeInfo.GetEventGroup(), subscribeInfo.GetEvent().eventId);
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgSubscribeEvent(event);
        return ret;
    }
    ret = SetDeathCallBack(event, callback);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, callback);
    event.ret = ret;
    SGLOGI("DataCollectManagerService, InsertSubscribeRecord eventId=%{public}" PRId64, event.eventId);
    BigData::ReportSgSubscribeEvent(event);
    return ret;
}

int32_t DataCollectManagerService::Unsubscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    int32_t ret = FAILED;
    SgUnsubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    if (subscribeInfo.GetEventGroup() == "") {
        ret = IsApiHasPermission("Subscribe");
    } else {
        ret = IsEventGroupHasPermission(subscribeInfo.GetEventGroup(), subscribeInfo.GetEvent().eventId);
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgUnsubscribeEvent(event);
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (deathRecipient_ != nullptr) {
        callback->RemoveDeathRecipient(deathRecipient_);
    }

    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, callback);
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
        SGLOGE("GetEventConfig error, eventId is 0x%{public}" PRIx64, ruler.GetEventId());
        return true;
    }
    std::vector<SecurityCollector::SecurityEvent> replyEvents;
    std::vector<int64_t> eventIds{ruler.GetEventId()};
    SGLOGD("eventType is %{public}u", config.eventType);
    if (config.eventType == 1) { // query in collector
        int32_t code = SecurityCollector::CollectorManager::GetInstance().QuerySecurityEvent(
            {ruler}, replyEvents);
        if (code != SUCCESS) {
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
            return SecurityCollector::SecurityEvent(event.eventId, event.version, event.content, event.date);
        });
        proxy->OnQuery(replyEvents);
    }
    return true;
}

int32_t DataCollectManagerService::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerService QuerySecurityEvent");
    int32_t ret = IsApiHasPermission("QuerySecurityEvent");
    if (ret != SUCCESS) {
        return ret;
    }
    auto proxy = iface_cast<ISecurityEventQueryCallback>(callback);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return NULL_OBJECT;
    }

    auto task = [proxy, rulers] {
        std::string errEventIds;
        for (auto &ruler : rulers) {
            if (!QueryEventByRuler(proxy, ruler)) {
                errEventIds.append(std::to_string(ruler.GetEventId()) + " ");
            }
        }
        if (!errEventIds.empty()) {
            std::string message = "QuerySecurityEvent " + errEventIds + "failed";
            SGLOGE("QuerySecurityEvent failed");
            proxy->OnError(message);
            return;
        }
        proxy->OnComplete();
    };

    ffrt::submit(task);
    return SUCCESS;
}

void DataCollectManagerService::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("enter OnRemoteDied");
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
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecordOnRemoteDied(object);
    if (object->IsProxyObject() && service->deathRecipient_ != nullptr) {
        object->RemoveDeathRecipient(service->deathRecipient_);
    }
    SGLOGI("end OnRemoteDied");
}

int32_t DataCollectManagerService::CollectorStart(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerService CollectorStart.");
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
    SGLOGI("enter DataCollectManagerService CollectorStop.");
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

int32_t DataCollectManagerService::IsEventGroupHasPermission(const std::string &eventGroup, int64_t eventId)
{
    EventGroupCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventGroupConfig(eventGroup, config)) {
        SGLOGE("get event group config fail group = %{public}s", eventGroup.c_str());
        return BAD_PARAM;
    }
    if (config.eventList.count(eventId) == 0) {
        SGLOGE("eventid not in eventid list");
        return BAD_PARAM;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(config.permissionList.cbegin(), config.permissionList.cend(),
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
    int32_t inputFd = open(realPath.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (inputFd < 0) {
        close(outputFd);
        SGLOGE("open file fail reason %{public}s", strerror(errno));
        return FAILED;
    }
    auto buffer = std::make_unique<char[]> (CFG_FILE_BUFF_SIZE);
    int offset = -1;
    while ((offset = read(outputFd, buffer.get(), CFG_FILE_BUFF_SIZE)) > 0) {
        if (offset > CFG_FILE_MAX_SIZE) {
            close(outputFd);
            close(inputFd);
            SGLOGE("file is empty or too large, len = %{public}d", offset);
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

bool DataCollectManagerService::ParseTrustListFile(const std::string &trustListFile)
{
    if (trustListFile.empty()) {
        SGLOGE("path is empty");
        return false;
    }
    std::ifstream stream(trustListFile, std::ios::in);
    if (!stream.is_open()) {
        SGLOGE("stream error");
        return false;
    }
    stream.seekg(0, std::ios::end);
    std::ios::pos_type cfgFileMaxSize = 1 * 1024 * 1024;
    std::ios::pos_type len = stream.tellg();
    if (len == 0 || len > cfgFileMaxSize) {
        SGLOGE("stream is empty or too large");
        stream.close();
        return false;
    }
    stream.seekg(0, std::ios_base::beg);
    nlohmann::json jsonObj = nlohmann::json::parse(stream, nullptr, false);
    stream.close();
    if (jsonObj.is_discarded()) {
        SGLOGE("json is discarded");
        return false;
    }
    
    if (!jsonObj.contains("trust_list_config") || !jsonObj["trust_list_config"].is_array()) {
        return false;
    }
 
    for (const auto &ele : jsonObj["trust_list_config"]) {
        if (!ele.contains("name")) {
            return false;
        }
        g_configCacheFilesSet.emplace(ele["name"]);
    }
 
    return true;
}

int32_t DataCollectManagerService::ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &info)
{
    SGLOGI("enter DataCollectManagerService ConfigUpdate.");
    int32_t code = IsApiHasPermission("ConfigUpdate");
    if (code != SUCCESS) {
        return code;
    }
    if (!ParseTrustListFile(TRUST_LIST_FILE_PATH)) {
        return BAD_PARAM;
    }
    if (g_configCacheFilesSet.empty() || !g_configCacheFilesSet.count(info.GetFileName())) {
        return BAD_PARAM;
    }
    const uint32_t modelId = 3001000008;
    if (info.GetFileName() == "related_event_analysis.json" &&
        !FileExists("/data/service/el1/public/security_guard/related_event_analysis.json")) {
        ModelManager::GetInstance().InitModel(modelId);
    }
    const std::string &realPath = CONFIG_ROOT_PATH + "tmp/" + info.GetFileName();
    SGLOGI("config file is %{public}s, fd is %{public}d", realPath.c_str(), info.GetFd());
    std::string tmpPath = realPath + ".t";
    int32_t ret = WriteRemoteFileToLocal(info, tmpPath);
    if (ret != SUCCESS) {
        SGLOGE("write remote file to local fail");
        return ret;
    }
    if (rename(tmpPath.c_str(), realPath.c_str()) != 0) {
        SGLOGE("remote file rename fail");
        (void)unlink(tmpPath.c_str());
        return FAILED;
    }
    (void)unlink(tmpPath.c_str());
 
    if (!ConfigSubscriber::UpdateConfig(realPath)) {
        SGLOGE("update config fail");
        return FAILED;
    }
    return SUCCESS;
}

int32_t DataCollectManagerService::QueryEventConfig(std::string &result)
{
    SGLOGI("Start DataCollectManagerService::QueryEventConfig");
    std::vector<EventCfg> eventConfigs = ConfigDataManager::GetInstance().GetAllEventConfigs();
    nlohmann::json resultObj = nlohmann::json::array();
    for (const auto& event : eventConfigs) {
        nlohmann::json jObject;
        jObject["eventId"] = event.eventId;
        jObject["eventName"] = event.eventName;
        jObject["version"] = event.version;
        jObject["eventType"] = event.eventType;
        jObject["collectOnStart"] = event.collectOnStart;
        jObject["dataSensitivityLevel"] = event.dataSensitivityLevel;
        jObject["storageRamNums"] = event.storageRamNums;
        jObject["storageRomNums"] = event.storageRomNums;
        jObject["storageTime"] = event.storageTime;
        jObject["owner"] = event.owner;
        jObject["source"] = event.source;
        jObject["dbTable"] = event.dbTable;
        jObject["prog"] = event.prog;
        resultObj.push_back(jObject);
    }
    result = resultObj.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    return SUCCESS;
}

int32_t DataCollectManagerService::QuerySecurityEventConfig(std::string &result)
{
    SGLOGI("enter QuerySecurityEventConfig");
    int32_t ret = IsApiHasPermission("QuerySecurityEventConfig");
    if (ret != SUCCESS) {
        return ret;
    }
    return QueryEventConfig(result);
}

int32_t DataCollectManagerService::Mute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    SGLOGI("enter DataCollectManagerService Mute.");
    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = subscribeMute.GetMuteFilter().eventId;
    if (subscribeMute.GetMuteFilter().eventGroup == "") {
        SGLOGE("event group empty");
        event.ret = BAD_PARAM;
        BigData::ReportSetMuteEvent(event);
        return BAD_PARAM;
    }
    int32_t ret = IsEventGroupHasPermission(subscribeMute.GetMuteFilter().eventGroup,
        subscribeMute.GetMuteFilter().eventId);
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSetMuteEvent(event);
        return ret;
    }
    ret = SetDeathCallBack(event, callback);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMutue(subscribeMute, callback, sdkFlag);
    event.ret = ret;
    BigData::ReportSetMuteEvent(event);
    return ret;
}

int32_t DataCollectManagerService::Unmute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    SGLOGI("enter DataCollectManagerService Unmute.");
    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = subscribeMute.GetMuteFilter().eventId;
    if (subscribeMute.GetMuteFilter().eventGroup == "") {
        SGLOGE("event group empty");
        event.ret = BAD_PARAM;
        BigData::ReportSetUnMuteEvent(event);
        return BAD_PARAM;
    }
    int32_t ret = IsEventGroupHasPermission(subscribeMute.GetMuteFilter().eventGroup,
        subscribeMute.GetMuteFilter().eventId);
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSetUnMuteEvent(event);
        return ret;
    }
    ret = SetDeathCallBack(event, callback);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMutue(subscribeMute, callback, sdkFlag);
    event.ret = ret;
    BigData::ReportSetUnMuteEvent(event);
    return ret;
}

int32_t DataCollectManagerService::SetDeathCallBack(SgSubscribeEvent event, const sptr<IRemoteObject> &callback)
{
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient(this);
        if (deathRecipient_ == nullptr) {
            SGLOGE("no memory");
            event.ret = NULL_OBJECT;
            BigData::ReportSgSubscribeEvent(event);
            return NULL_OBJECT;
        }
    }
    callback->AddDeathRecipient(deathRecipient_);
    return SUCCESS;
}
}