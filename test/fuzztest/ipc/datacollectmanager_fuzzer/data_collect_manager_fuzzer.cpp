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

#include "data_collect_manager_fuzzer.h"

#include <string>

#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_service.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityGuard {
DataCollectManagerService g_service(DATA_COLLECT_MANAGER_SA_ID, true);
constexpr int32_t REMAINDER_VALUE = 9;
constexpr int32_t CMD_DATA_COLLECT_VALUE = 0;
constexpr int32_t CMD_DATA_REQUEST_VALUE = 1;
constexpr int32_t CMD_DATA_SUBSCRIBE = 2;
constexpr int32_t CMD_DATA_UNSUBSCRIBE_VALUE = 3;
constexpr int32_t CMD_SECURITY_EVENT_QUERY_VALUE = 4;
constexpr int32_t CMD_SECURITY_COLLECTOR_START = 5;
constexpr int32_t CMD_SECURITY_COLLECTOR_STOP = 6;
constexpr int32_t CMD_SECURITY_CONFIG_UPDATE = 7;
constexpr int32_t CMD_SECURITY_EVENT_CONFIG_QUERY = 8;

void OnRemoteCollectRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteRequestRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteSubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteUnsubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteSecurityEventQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteStart(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteStop(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteConfigUpdate(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteSecurityEventConfigQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    if (size % REMAINDER_VALUE == CMD_DATA_COLLECT_VALUE) {
        // handle data collect cmd
        OnRemoteCollectRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_DATA_REQUEST_VALUE) {
        // handle data request cmd
        OnRemoteRequestRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_DATA_SUBSCRIBE) {
        // handle data subscribe cmd
        OnRemoteSubscribeRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_DATA_UNSUBSCRIBE_VALUE) {
        // handle data unsubscribe cmd
        OnRemoteUnsubscribeRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_EVENT_QUERY_VALUE) {
        // handle security event query cmd
        OnRemoteSecurityEventQuery(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_COLLECTOR_START) {
        // handle collector start cmd
        OnRemoteStart(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_COLLECTOR_STOP) {
        // handle collector stop cmd
        OnRemoteStop(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_CONFIG_UPDATE) {
        // handle collector stop cmd
        OnRemoteConfigUpdate(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_EVENT_CONFIG_QUERY) {
        // handle collector stop cmd
        OnRemoteSecurityEventConfigQuery(data, size, &datas, &reply, &option);
        return;
    }
}

void OnRemoteCollectRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    datas->WriteInt64(eventId);
    datas->WriteString(string);
    datas->WriteString(string);
    datas->WriteString(string);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_COLLECT, *datas, *reply, *option);
}

void OnRemoteRequestRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr) {
        return;
    }
    std::string string(reinterpret_cast<const char *>(data), size);
    datas->WriteString(string);
    datas->WriteString(string);
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_REQUEST, *datas, *reply, *option);
}

void OnRemoteSubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr || size < sizeof(int64_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t duration = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    SecurityCollector::Event event;
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_SUBSCRIBE, *datas, *reply, *option);
}

void OnRemoteUnsubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_UNSUBSCRIBE, *datas, *reply, *option);
}

void OnRemoteSecurityEventQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    uint32_t rulerSize = uint32 >= MAX_QUERY_EVENT_SIZE ? MAX_QUERY_EVENT_SIZE : uint32;
    datas->WriteUint32(rulerSize);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    for (uint32_t i = 0; i < rulerSize; i++) {
        SecurityCollector::SecurityEventRuler ruler =
            SecurityCollector::SecurityEventRuler(eventId, string, string, string);
        datas->WriteParcelable(&ruler);
    }
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_SECURITY_EVENT_QUERY, *datas, *reply, *option);
}

void OnRemoteStart(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    int64_t duration = static_cast<int64_t>(size);
    SecurityCollector::Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_SECURITY_COLLECTOR_START, *datas, *reply, *option);
}

void OnRemoteStop(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    int64_t duration = static_cast<int64_t>(size);
    SecurityCollector::Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_SECURITY_COLLECTOR_STOP, *datas, *reply, *option);
}

void OnRemoteConfigUpdate(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int32_t fd = static_cast<int32_t>(size);
    std::string fileName(reinterpret_cast<const char *>(data), size);
    datas->WriteFileDescriptor(fd);
    datas->WriteString(fileName);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_SECURITY_CONFIG_UPDATE, *datas, *reply, *option);
}

void OnRemoteSecurityEventConfigQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_SECURITY_EVENT_CONFIG_QUERY, *datas, *reply, *option);
}

}  // namespace OHOS::Security::SecurityGuard

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityGuard::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
