/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_event_query_callback_stub.h"

#include <cstdint>
#include <string>
#include <vector>

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t SecurityEventQueryCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    if (SecurityEventQueryCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        SGLOGE("Descriptor error");
        return NO_PERMISSION;
    }
    SGLOGD("OnRemoteRequest, code=%{public}u", code);

    switch (code) {
        case CMD_ON_QUERY: {
            uint32_t size = 0;
            if (!data.ReadUint32(size)) {
                SGLOGE("failed to get the event size");
                return BAD_PARAM;
            }

            if (size > MAX_QUERY_EVENT_SIZE) {
                SGLOGE("the event size error");
                return BAD_PARAM;
            }
            std::vector<SecurityCollector::SecurityEvent> events;
            for (uint32_t index = 0; index < size; index++) {
                std::shared_ptr<SecurityCollector::SecurityEvent> event(
                    data.ReadParcelable<SecurityCollector::SecurityEvent>());
                if (event == nullptr) {
                    SGLOGE("failed read security event");
                    return BAD_PARAM;
                }
                events.emplace_back(*event);
            }
            OnQuery(events);
            return SUCCESS;
        }
        case CMD_ON_COMPLETE: {
            OnComplete();
            return SUCCESS;
        }
        case CMD_ON_ERROR: {
            std::string message = data.ReadString();
            OnError(message);
            return SUCCESS;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
} // namespace OHOS::Security::SecurityGuard
