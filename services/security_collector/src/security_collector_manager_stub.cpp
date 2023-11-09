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

#include "security_collector_manager_stub.h"

#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
int32_t SecurityCollectorManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    LOGD("%{public}s", __func__);
    do {
        if (ISecurityCollectorManager::GetDescriptor() != data.ReadInterfaceToken()) {
            break;
        }

        switch (code) {
            case CMD_COLLECTOR_SUBCRIBE: {
                return HandleSubscribeCmd(data, reply);
            }
            case CMD_COLLECTOR_UNSUBCRIBE: {
                return HandleUnsubscribeCmd(data, reply);
            }
            default: {
                break;
            }
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SecurityCollectorManagerStub::HandleSubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollectorSubscribeInfo> info(data.ReadParcelable<SecurityCollectorSubscribeInfo>());
    if (!info) {
        LOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = Subscribe(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t SecurityCollectorManagerStub::HandleUnsubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }

    int32_t ret = Unsubscribe(callback);
    reply.WriteInt32(ret);
    return ret;
}
}