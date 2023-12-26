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
int32_t AcquireDataCallbackProxy::OnNotify(const SecurityCollector::Event &event)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_OPERATION;
    }

    data.WriteInt64(event.eventId);
    data.WriteString(event.version);
    data.WriteString(event.content);
    data.WriteString(event.extra);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("remote is nullptr, code = %{public}u", static_cast<uint32_t>(CMD_DATA_SUBSCRIBE_CALLBACK));
        return NULL_OBJECT;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    return Remote()->SendRequest(CMD_DATA_SUBSCRIBE_CALLBACK, data, reply, option);
}
}