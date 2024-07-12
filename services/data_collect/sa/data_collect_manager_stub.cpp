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

#include "data_collect_manager_stub.h"

#include "string_ex.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t DataCollectManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    SGLOGD("%{public}s", __func__);
    do {
        if (IDataCollectManager::GetDescriptor() != data.ReadInterfaceToken()) {
            SGLOGE("descriptor error, %{public}s", Str16ToStr8(data.ReadInterfaceToken()).c_str());
            break;
        }

        switch (code) {
            case CMD_DATA_COLLECT: {
                return HandleDataCollectCmd(data, reply);
            }
            case CMD_DATA_REQUEST: {
                return HandleDataRequestCmd(data, reply);
            }
            case CMD_DATA_SUBSCRIBE: {
                return HandleDataSubscribeCmd(data, reply);
            }
            case CMD_DATA_UNSUBSCRIBE: {
                return HandleDataUnsubscribeCmd(data, reply);
            }
            case CMD_SECURITY_EVENT_QUERY: {
                return HandleSecurityEventQueryCmd(data, reply);
            }
            case CMD_SECURITY_COLLECTOR_START: {
                return HandleStartCmd(data, reply);
            }
            case CMD_SECURITY_COLLECTOR_STOP: {
                return HandleStopCmd(data, reply);
            }
            case CMD_SECURITY_CONFIG_UPDATE: {
                return HandleConfigUpdateCmd(data, reply);
            }
            default: {
                break;
            }
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DataCollectManagerStub::HandleStartCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("in HandleStartCmd");
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollector::SecurityCollectorSubscribeInfo> info(
        data.ReadParcelable<SecurityCollector::SecurityCollectorSubscribeInfo>());
    if (!info) {
        SGLOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = CollectorStart(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DataCollectManagerStub::HandleStopCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollector::SecurityCollectorSubscribeInfo> info(
        data.ReadParcelable<SecurityCollector::SecurityCollectorSubscribeInfo>());
    if (!info) {
        SGLOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = CollectorStop(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DataCollectManagerStub::HandleDataCollectCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    uint32_t expected = sizeof(int64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    int64_t eventId = data.ReadInt64();
    std::string version = data.ReadString();
    std::string time = data.ReadString();
    std::string content = data.ReadString();
    return RequestDataSubmit(eventId, version, time, content);
}

int32_t DataCollectManagerStub::HandleDataRequestCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    const uint32_t expected = 4;
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string devId = data.ReadString();
    std::string eventList = data.ReadString();
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return BAD_PARAM;
    }
    return RequestRiskData(devId, eventList, object);
}

int32_t DataCollectManagerStub::HandleDataSubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollector::SecurityCollectorSubscribeInfo> info(
        data.ReadParcelable<SecurityCollector::SecurityCollectorSubscribeInfo>());
    if (!info) {
        SGLOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = Subscribe(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DataCollectManagerStub::HandleDataUnsubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }
    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }

    int32_t ret = Unsubscribe(callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DataCollectManagerStub::HandleSecurityEventQueryCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint32_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        SGLOGE("failed to get the event size");
        return BAD_PARAM;
    }

    if (size > MAX_QUERY_EVENT_SIZE) {
        SGLOGE("the event size error");
        return BAD_PARAM;
    }
    std::vector<SecurityCollector::SecurityEventRuler> rulers;
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<SecurityCollector::SecurityEventRuler> event(
            data.ReadParcelable<SecurityCollector::SecurityEventRuler>());
        if (event == nullptr) {
            SGLOGE("failed read security event");
            return BAD_PARAM;
        }
        rulers.emplace_back(*event);
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }

    int32_t ret = QuerySecurityEvent(rulers, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t DataCollectManagerStub::HandleConfigUpdateCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string fileName = data.ReadString();
    if (fileName.empty()) {
        SGLOGE("failed to read fileName for config update");
        return BAD_PARAM;
    }
    int32_t fd = data.ReadFileDescriptor();
    if (fd < 0) {
        SGLOGE("failed to read file fd for config update");
        return BAD_PARAM;
    }
    SecurityGuard::SecurityConfigUpdateInfo info(fd, fileName);
    int32_t ret = ConfigUpdate(info);
    reply.WriteInt32(ret);
    return ret;
}
}