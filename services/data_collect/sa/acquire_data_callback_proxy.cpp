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

#include "acquire_data_callback_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t AcquireDataCallbackProxy::OnNotify(const std::vector<SecurityCollector::Event> &events)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_OPERATION;
    }
    if (!data.WriteUint32(events.size())) {
        SGLOGE("failed to WriteInt32 for parcelable vector size");
        return WRITE_ERR;
    }

    for (const auto &event : events) {
        data.WriteInt64(event.eventId);
        data.WriteString(event.version);
        data.WriteString(event.content);
        data.WriteString(event.extra);
        data.WriteString(event.timestamp);
        data.WriteInt32(event.userId);
        data.WriteString(event.deviceId);
        if (!data.WriteUint32(event.eventSubscribes.size())) {
            SGLOGE("failed to write eventSubscribes size");
            return WRITE_ERR;
        }
        for (auto iter : event.eventSubscribes) {
            if (!data.WriteString(iter)) {
                SGLOGE("failed to write eventSubscribes");
                return WRITE_ERR;
            }
        }
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("remote is nullptr, code = %{public}u", static_cast<uint32_t>(CMD_DATA_SUBSCRIBE_CALLBACK));
        return NULL_OBJECT;
    }

    MessageOption option = { MessageOption::TF_ASYNC };
    SGLOGD("batch callback event num of records= %{public}zu", events.size());
    return remote->SendRequest(CMD_DATA_SUBSCRIBE_CALLBACK, data, reply, option);
}

}