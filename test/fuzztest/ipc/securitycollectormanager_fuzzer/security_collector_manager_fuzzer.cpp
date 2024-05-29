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

#include "security_collector_manager_fuzzer.h"

#include <string>

#include "security_collector_manager_callback_service.h"
#include "security_collector_manager_service.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityCollector {
SecurityCollectorManagerService g_service(SECURITY_COLLECTOR_MANAGER_SA_ID, true);
constexpr int32_t REMAINDER_VALUE = 5;
constexpr int32_t CMD_COLLECTOR_SUBCRIBE_VALUE = 0;
constexpr int32_t CMD_COLLECTOR_UNSUBCRIBE_VALUE = 1;
constexpr int32_t CMD_COLLECTOR_START_VALUE = 2;
constexpr int32_t CMD_COLLECTOR_STOP_VALUE = 3;
constexpr int32_t CMD_SECURITY_EVENT_QUERY_VALUE = 4;
void OnRemoteSubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteUnsubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteStartRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteStopRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);
void OnRemoteSecurityEventQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option);

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    if (size % REMAINDER_VALUE == CMD_COLLECTOR_SUBCRIBE_VALUE) {
        // handle data collect cmd
        OnRemoteSubscribeRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_COLLECTOR_UNSUBCRIBE_VALUE) {
        // handle data request cmd
        OnRemoteUnsubscribeRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_COLLECTOR_START_VALUE) {
        // handle data subscribe cmd
        OnRemoteStartRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_COLLECTOR_STOP_VALUE) {
        // handle data unsubscribe cmd
        OnRemoteStopRequest(data, size, &datas, &reply, &option);
        return;
    } else if (size % REMAINDER_VALUE == CMD_SECURITY_EVENT_QUERY_VALUE) {
        // handle security event query cmd
        OnRemoteSecurityEventQuery(data, size, &datas, &reply, &option);
        return;
    }
}

void OnRemoteSubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    int64_t duration = static_cast<int64_t>(size);
    Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    datas->WriteParcelable(&subscriberInfo);
    sptr<SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_COLLECTOR_SUBCRIBE, *datas, *reply, *option);
}

void OnRemoteUnsubscribeRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollectorSubscribeInfo subscriberInfo{event, -1, true};
    datas->WriteParcelable(&subscriberInfo);
    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_COLLECTOR_UNSUBCRIBE, *datas, *reply, *option);
}

void OnRemoteStartRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    int64_t duration = static_cast<int64_t>(size);
    Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    datas->WriteParcelable(&subscriberInfo);
    sptr<SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_COLLECTOR_START, *datas, *reply, *option);
}

void OnRemoteStopRequest(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    int64_t eventId = static_cast<int64_t>(size);
    std::string version(reinterpret_cast<const char *>(data), size);
    std::string content(reinterpret_cast<const char *>(data), size);
    std::string extra(reinterpret_cast<const char *>(data), size);
    Event event;
    event.eventId = eventId;
    event.version = version;
    event.content = content;
    event.extra = extra;
    SecurityCollectorSubscribeInfo subscriberInfo{event, -1, true};
    datas->WriteParcelable(&subscriberInfo);
    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_COLLECTOR_STOP, *datas, *reply, *option);
}

void OnRemoteSecurityEventQuery(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    uint32_t rulerSize = size >= MAX_QUERY_EVENT_SIZE ? MAX_QUERY_EVENT_SIZE : static_cast<uint32_t>(size);
    datas->WriteUint32(rulerSize);
    for (uint32_t i = 0; i < rulerSize; i++) {
        int64_t eventId = static_cast<int64_t>(size);
        std::string beginTime(reinterpret_cast<const char *>(data), size);
        std::string endTime(reinterpret_cast<const char *>(data), size);
        std::string param(reinterpret_cast<const char *>(data), size);
        SecurityEventRuler ruler =
            SecurityEventRuler(eventId, beginTime, endTime, param);
        datas->WriteParcelable(&ruler);
    }
    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_SECURITY_EVENT_QUERY, *datas, *reply, *option);
}

}  // namespace OHOS::Security::SecurityCollector

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityCollector::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
