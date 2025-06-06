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

#include "data_collect_manager_callback_proxy.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DataCollectManagerCallbackProxy::DataCollectManagerCallbackProxy(const sptr<OHOS::IRemoteObject> &impl)
    : IRemoteProxy<IDataCollectManagerCallback>(impl)
{
}

int32_t DataCollectManagerCallbackProxy::ResponseRiskData(std::string &devId, std::string &riskData,
    uint32_t status, const std::string& errMsg)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_OPERATION;
    }
    SGLOGE("start ResponseRiskData");
    data.WriteString(riskData);
    data.WriteUint32(status);
    data.WriteString(errMsg);
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    if (remote == nullptr) {
        SGLOGE("remote is nullptr");
        return NULL_OBJECT;
    }
    return remote->SendRequest(CMD_SET_REQUEST_DATA, data, reply, option);
}
}