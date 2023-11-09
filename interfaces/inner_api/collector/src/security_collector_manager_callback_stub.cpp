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

#include "security_collector_manager_callback_stub.h"

#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
int32_t SecurityCollectorManagerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (SecurityCollectorManagerCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        LOGE("Descriptor error");
        return NO_PERMISSION;
    }

    if (code == SecurityCollectorManagerCallbackStub::CMD_COLLECTOR_NOTIFY) {
        uint32_t expected = sizeof(uint64_t);
        uint32_t actual = data.GetReadableBytes();
        if (expected >= actual) {
            LOGE("actual length error, value=%{public}u", actual);
            return BAD_PARAM;
        }

        Event event;
        event.eventId = data.ReadInt64();
        event.version = data.ReadString();
        event.content = data.ReadString();
        event.extra = data.ReadString();

        OnNotify(event);
        return SUCCESS;
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
}