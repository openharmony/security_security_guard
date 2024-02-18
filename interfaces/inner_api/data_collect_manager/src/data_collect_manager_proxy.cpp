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

#include "data_collect_manager_proxy.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DataCollectManagerProxy::DataCollectManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDataCollectManager>(impl)
{
}

int32_t DataCollectManagerProxy::RequestDataSubmit(int64_t eventId, std::string &version,
    std::string &time, std::string &content)
{
    SGLOGD("eventId=%{public}" PRId64 ", version=%{public}s", eventId, version.c_str());
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
    data.WriteInt64(eventId);
    data.WriteString(version);
    data.WriteString(time);
    data.WriteString(content);

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_DATA_COLLECT, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::RequestRiskData(std::string &devId, std::string &eventList,
    const sptr<IRemoteObject> &callback)
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_DATA_REQUEST, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGI("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        SGLOGE("failed to write parcelable for subscribeInfo");
        return WRITE_ERR;
    }

    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_DATA_SUBSCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    int ret = Remote()->SendRequest(CMD_DATA_UNSUBSCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}
}