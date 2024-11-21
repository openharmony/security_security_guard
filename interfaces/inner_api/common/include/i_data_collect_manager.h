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

#ifndef SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H
#define SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H

#include <cstdint>

#include "iremote_broker.h"

#include "data_collect_manager_service_ipc_interface_code.h"
#include "security_collector_subscribe_info.h"
#include "security_event_ruler.h"
#include "security_event.h"
#include "security_config_update_info.h"
#include "security_event_config.h"
namespace OHOS::Security::SecurityGuard {
constexpr int32_t DATA_COLLECT_MANAGER_SA_ID = 3524;

class IDataCollectManager : public IRemoteBroker {
public:
    using InterfaceCode = DataCollectManagerInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager");
    enum {
        CMD_DATA_COLLECT = static_cast<uint32_t>(InterfaceCode::CMD_DATA_COLLECT),
        CMD_DATA_REQUEST = static_cast<uint32_t>(InterfaceCode::CMD_DATA_REQUEST),
        CMD_DATA_SUBSCRIBE = static_cast<uint32_t>(InterfaceCode::CMD_DATA_SUBSCRIBE),
        CMD_DATA_UNSUBSCRIBE = static_cast<uint32_t>(InterfaceCode::CMD_DATA_UNSUBSCRIBE),
        CMD_SECURITY_EVENT_QUERY = static_cast<uint32_t>(InterfaceCode::CMD_SECURITY_EVENT_QUERY),
        CMD_SECURITY_COLLECTOR_START = static_cast<uint32_t>(InterfaceCode::CMD_SECURITY_COLLECTOR_START),
        CMD_SECURITY_COLLECTOR_STOP = static_cast<uint32_t>(InterfaceCode::CMD_SECURITY_COLLECTOR_STOP),
        CMD_SECURITY_CONFIG_UPDATE = static_cast<uint32_t>(InterfaceCode::CMD_SECURITY_CONFIG_UPDATE),
        CMD_SECURITY_EVENT_CONFIG_QUERY = static_cast<uint32_t>(InterfaceCode::CMD_SECURITY_EVENT_CONFIG_QUERY),
    };

    virtual int32_t RequestDataSubmit(int64_t eventId, std::string &version, std::string &time,
        std::string &content, bool isSync = true) = 0;
    virtual int32_t RequestRiskData(std::string &devId, std::string &eventList,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t Unsubscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &updateInfo) = 0;
    virtual int32_t QuerySecurityEventConfig(std::string &result) = 0;
};

class IDataCollectManagerCallback : public IRemoteBroker {
public:
    using InterfaceCode = DataCollectManagerCallbackInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager.Callback");
    enum {
        CMD_SET_REQUEST_DATA = static_cast<uint32_t>(InterfaceCode::CMD_SET_REQUEST_DATA),
    };

    virtual int32_t ResponseRiskData(std::string &devId, std::string &riskData, uint32_t status,
        const std::string& errMsg = "") = 0;
};

class IAcquireDataCallback : public IRemoteBroker {
public:
    using InterfaceCode = DataCollectManagerCallbackInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.AcquireData.Callback");
    enum {
        CMD_DATA_SUBSCRIBE_CALLBACK = static_cast<uint32_t>(InterfaceCode::CMD_DATA_SUBSCRIBE_CALLBACK),
    };

    virtual int32_t OnNotify(const std::vector<SecurityCollector::Event> &events) = 0;
};

class ISecurityEventQueryCallback : public IRemoteBroker {
public:
    using InterfaceCode = SecurityEventQueryCallbackInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.SecurityEventQuery.Callback");
    enum {
        CMD_ON_QUERY = static_cast<uint32_t>(InterfaceCode::CMD_ON_QUERY),
        CMD_ON_COMPLETE = static_cast<uint32_t>(InterfaceCode::CMD_ON_COMPLETE),
        CMD_ON_ERROR = static_cast<uint32_t>(InterfaceCode::CMD_ON_ERROR),
    };

    virtual void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) = 0;
    virtual void OnComplete() = 0;
    virtual void OnError(const std::string &message) = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H