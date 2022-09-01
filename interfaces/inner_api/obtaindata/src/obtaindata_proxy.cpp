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

#include "obtaindata_proxy.h"
#include "sg_obtaindata_client.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
ObtainDataProxy::ObtainDataProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDataCollectManager>(impl)
{
}

int32_t ObtainDataProxy::RequestRiskData(std::string &devId,
    std::string &eventList, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
    data.WriteString(devId);
    data.WriteString(eventList);
    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_DATA_REQUEST, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }

    ret = reply.ReadInt32();
    SGLOGI("reply=%{public}d", ret);
    return ret;
}
}