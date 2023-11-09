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

#include "security_collector_manager_callback_proxy.h"
#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {

int32_t SecurityCollectorManagerCallbackProxy::OnNotify(const Event &event)
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
        LOGE("remote is nullptr, code = %{public}u", static_cast<uint32_t>(CMD_COLLECTOR_NOTIFY));
        return NULL_OBJECT;
    }

    MessageOption option = { MessageOption::TF_ASYNC };
    return Remote()->SendRequest(CMD_COLLECTOR_NOTIFY, data, reply, option);
}
}