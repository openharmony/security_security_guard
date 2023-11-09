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

#include "security_collector_manager_proxy.h"

#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
SecurityCollectorManagerProxy::SecurityCollectorManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISecurityCollectorManager>(impl)
{
}

int32_t SecurityCollectorManagerProxy::Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        LOGE("failed to write parcelable for subscribeInfo");
        return WRITE_ERR;
    }

    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

int32_t SecurityCollectorManagerProxy::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_COLLECTOR_UNSUBCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

}