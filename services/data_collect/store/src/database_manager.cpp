/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "database_manager.h"

#include "device_manager.h"
#include "os_account_manager.h"

#include "audit_event_mem_rdb_helper.h"
#include "audit_event_rdb_helper.h"
#include "config_data_manager.h"
#include "preferences_wrapper.h"
#include "risk_event_rdb_helper.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "store_define.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr const char *PKG_NAME = "ohos.security.securityguard";
    constexpr const char *AUDIT_SWITCH = "audit_switch";
    constexpr int32_t AUDIT_SWITCH_OFF = 0;
    constexpr int32_t AUDIT_SWITCH_ON = 1;
}

class InitCallback : public DistributedHardware::DmInitCallback {
public:
    ~InitCallback() override = default;
    void OnRemoteDied() override {};
};

void DatabaseManager::Init()
{
    // init database
    int32_t ret = RiskEventRdbHelper::GetInstance().Init();
    SGLOGI("risk event rdb init result is %{public}d", ret);
    
    // init audit according to audit switch state
    if (PreferenceWrapper::GetInt(AUDIT_SWITCH, AUDIT_SWITCH_OFF) == AUDIT_SWITCH_ON) {
        (void)OpenAudit();
    }
}

int32_t DatabaseManager::InitDeviceId()
{
    if (PreferenceWrapper::GetInt(AUDIT_SWITCH, AUDIT_SWITCH_OFF) == AUDIT_SWITCH_OFF || !deviceId_.empty()) {
        SGLOGI("audit function not open, or already init device info");
        return SUCCESS;
    }
    auto callback = std::make_shared<InitCallback>();
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, callback);
    if (ret != SUCCESS) {
        SGLOGI("init device manager failed, result is %{public}d", ret);
        return ret;
    }

    DistributedHardware::DmDeviceInfo deviceInfo;
    ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, deviceInfo);
    if (ret != SUCCESS) {
        SGLOGE("get local device info error, code=%{public}d", ret);
        return ret;
    }
    deviceId_ = deviceInfo.deviceId;
    SGLOGI("init device info success");
    return SUCCESS;
}

int32_t DatabaseManager::OpenAudit()
{
    int32_t ret = AuditEventRdbHelper::GetInstance().Init();
    SGLOGI("audit event rdb init result is %{public}d", ret);
    ret = AuditEventMemRdbHelper::GetInstance().Init();
    SGLOGI("audit event mem rdb init result is %{public}d", ret);
    return InitDeviceId();
}

int32_t DatabaseManager::CloseAudit()
{
    AuditEventRdbHelper::GetInstance().Release();
    AuditEventMemRdbHelper::GetInstance().Release();
    auto callback = std::make_shared<InitCallback>();
    int ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(PKG_NAME);
    if (ret != SUCCESS) {
        SGLOGI("init device manager failed, result is %{public}d", ret);
    }
    return SUCCESS;
}

int32_t DatabaseManager::SetAuditState(bool enable)
{
    int state = PreferenceWrapper::GetInt(AUDIT_SWITCH, AUDIT_SWITCH_OFF);
    if ((state == AUDIT_SWITCH_OFF && !enable) || (state == AUDIT_SWITCH_ON && enable)) {
        SGLOGI("the switch state does not change.");
        return SUCCESS;
    }
    if (enable) {
        PreferenceWrapper::PutInt(AUDIT_SWITCH, AUDIT_SWITCH_ON);
        OpenAudit();
    } else {
        CloseAudit();
        PreferenceWrapper::PutInt(AUDIT_SWITCH, AUDIT_SWITCH_OFF);
    }
    return SUCCESS;
}

void DatabaseManager::FillUserIdAndDeviceId(SecEvent& event)
{
    std::vector<int32_t> ids;
    int32_t code = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (code == ERR_OK && !ids.empty()) {
        SGLOGD("query active os accountIds success");
        event.userId = ids[0];
    }

    event.deviceId = deviceId_;
}

int DatabaseManager::InsertEvent(uint32_t source, SecEvent& event)
{
    EventCfg config;
    bool success = ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config);
    if (!success) {
        SGLOGE("not found event, id=%{public}" PRId64 "", event.eventId);
        return NOT_FOUND;
    }

    if (config.source == source) {
        std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(event.eventId);
        SGLOGD("table=%{public}s, eventId=%{public}" PRId64 "", table.c_str(), config.eventId);
        if (table == AUDIT_TABLE) {
            SGLOGD("audit event insert");
            DbChanged(IDbListener::INSERT, event);
            return SUCCESS;
        }
        SGLOGD("risk event insert, eventId=%{public}" PRId64 "", event.eventId);
        // Check whether the upper limit is reached.
        int64_t count = RiskEventRdbHelper::GetInstance().CountEventByEventId(event.eventId);
        if (count >= config.storageRomNums) {
            (void) RiskEventRdbHelper::GetInstance().DeleteOldEventByEventId(event.eventId,
                count + 1 - config.storageRomNums);
        }
        return RiskEventRdbHelper::GetInstance().InsertEvent(event);
    }

    // notify changed
    DbChanged(IDbListener::INSERT, event);
    return SUCCESS;
}

int DatabaseManager::QueryAllEvent(std::string table, std::vector<SecEvent> &events)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryAllEvent(events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryAllEvent(events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryAllEventFromMem(std::vector<SecEvent> &events)
{
    return AuditEventMemRdbHelper::GetInstance().QueryAllEventFromMem(events);
}

int DatabaseManager::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryRecentEventByEventId(std::string table, const std::vector<int64_t> &eventId,
    std::vector<SecEvent> &event)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryRecentEventByEventId(eventId, event);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventIdAndDate(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events, std::string beginTime, std::string endTime)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByEventIdAndDate(eventIds, events, beginTime, endTime);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventIdAndDate(eventIds, events, beginTime, endTime);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByEventId(eventId, events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventId(eventId, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventId(std::string table, std::vector<int64_t> &eventIds,
    std::vector<SecEvent> &events)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByEventId(eventIds, events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventId(eventIds, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByEventType(std::string table, int32_t eventType, std::vector<SecEvent> &events)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByEventType(eventType, events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByEventType(eventType, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByLevel(std::string table, int32_t level, std::vector<SecEvent> &events)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByLevel(level, events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByLevel(level, events);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::QueryEventByOwner(std::string table, std::string owner, std::vector<SecEvent> &events)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().QueryEventByOwner(owner, events);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().QueryEventByOwner(owner, events);
    }
    return NOT_SUPPORT;
}

int64_t DatabaseManager::CountAllEvent(std::string table)
{
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().CountAllEvent();
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().CountAllEvent();
    }
    return NOT_SUPPORT;
}

int64_t DatabaseManager::CountEventByEventId(int64_t eventId)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().CountEventByEventId(eventId);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().CountEventByEventId(eventId);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().DeleteOldEventByEventId(eventId, count);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().DeleteOldEventByEventId(eventId, count);
    }
    return NOT_SUPPORT;
}

int DatabaseManager::DeleteAllEventByEventId(int64_t eventId)
{
    std::string table = ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    if (table == AUDIT_TABLE) {
        return AuditEventRdbHelper::GetInstance().DeleteAllEventByEventId(eventId);
    } else if (table == RISK_TABLE) {
        return RiskEventRdbHelper::GetInstance().DeleteAllEventByEventId(eventId);
    }
    return NOT_SUPPORT;
}

int32_t DatabaseManager::SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    SGLOGI("__FUNC__=%{public}s", __func__);
    if (listener == nullptr) {
        SGLOGE("listener is nullptr");
        return NULL_OBJECT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (int64_t eventId : eventIds) {
        SGLOGI("SubscribeDb EVENTID %{public}" PRId64 "", eventId);
        listenerMap_[eventId].insert(listener);
    }
    return SUCCESS;
}

int32_t DatabaseManager::UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener)
{
    SGLOGI("__FUNC__=%{public}s", __func__);
    if (listener == nullptr) {
        return NULL_OBJECT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (int64_t eventId : eventIds) {
        listenerMap_[eventId].erase(listener);
        SGLOGI("size=%{public}u", static_cast<int32_t>(listenerMap_[eventId].size()));
        if (listenerMap_[eventId].size() == 0) {
            listenerMap_.erase(eventId);
        }
    }
    return SUCCESS;
}

void DatabaseManager::DbChanged(int32_t optType, const SecEvent &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::shared_ptr<IDbListener>> listeners = listenerMap_[event.eventId];
    SGLOGI("eventId=%{public}" PRId64 ", listener size=%{public}u",
        event.eventId, static_cast<int32_t>(listeners.size()));
    for (auto &listener : listeners) {
        if (listener != nullptr) {
            listener->OnChange(optType, event);
        }
    }
}
} // namespace OHOS::Security::SecurityGuard