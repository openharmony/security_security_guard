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
    if (data == nullptr || size < sizeof(int64_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    int64_t duration = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    Event event;
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
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
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    Event event;
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
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
    if (data == nullptr || size < sizeof(int64_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    int64_t duration = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    Event event;
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
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
    if (data == nullptr || size < sizeof(int64_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    Event event;
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
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
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data));
    uint32_t rulerSize = uint32 >= MAX_QUERY_EVENT_SIZE ? MAX_QUERY_EVENT_SIZE : uint32;
    datas->WriteUint32(rulerSize);
    offset += sizeof(uint32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    for (uint32_t i = 0; i < rulerSize; i++) {
        SecurityEventRuler ruler =
            SecurityEventRuler(eventId, string, string, string);
        datas->WriteParcelable(&ruler);
    }
    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(nullptr);
    datas->WriteRemoteObject(callback);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_SECURITY_EVENT_QUERY, *datas, *reply, *option);
}

void OnRemoteMute(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    offset += sizeof(uint32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    SecurityCollectorEventMuteFilter info {};
    info.eventId = eventId;
    info.mutes.insert(string);
    SecurityCollectorEventFilter filter(info);
    datas->WriteParcelable(&filter);
    datas->WriteString(string);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_SECURITY_EVENT_MUTE, *datas, *reply, *option);
}

void OnRemoteUnmute(const uint8_t* data, size_t size, MessageParcel* datas,
    MessageParcel* reply, MessageOption* option)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    offset += sizeof(uint32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    SecurityCollectorEventMuteFilter info {};
    info.eventId = eventId;
    info.mutes.insert(string);
    SecurityCollectorEventFilter filter(info);
    datas->WriteParcelable(&filter);
    datas->WriteString(string);
    g_service.OnRemoteRequest(SecurityCollectorManagerStub::CMD_SECURITY_EVENT_UNMUTE, *datas, *reply, *option);
}
}  // namespace OHOS::Security::SecurityCollector

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityCollector::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
