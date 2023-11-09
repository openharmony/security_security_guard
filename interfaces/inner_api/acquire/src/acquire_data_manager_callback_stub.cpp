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

#include "acquire_data_manager_callback_stub.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t AcquireDataManagerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (AcquireDataManagerCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        SGLOGE("Descriptor error");
        return NO_PERMISSION;
    }

    if (code == AcquireDataManagerCallbackStub::CMD_DATA_SUBSCRIBE_CALLBACK) {
        uint32_t expected = sizeof(uint32_t);
        uint32_t actual = data.GetReadableBytes();
        if (expected >= actual) {
            SGLOGE("actual length error, value=%{public}u", actual);
            return BAD_PARAM;
        }

        SecurityCollector::Event event;
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