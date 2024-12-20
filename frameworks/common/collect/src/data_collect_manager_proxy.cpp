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
#include <cinttypes>
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DataCollectManagerProxy::DataCollectManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDataCollectManager>(impl)
{
}

int32_t DataCollectManagerProxy::RequestDataSubmit(int64_t eventId, std::string &version,
    std::string &time, std::string &content, bool isSync)
{
    SGLOGD("enter DataCollectManagerProxy RequestDataSubmit");
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

    MessageOption option = { isSync ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC };
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
    if (isSync) {
        ret = reply.ReadInt32();
        SGLOGD("reply=%{public}d", ret);
    }
    return ret;
}

int32_t DataCollectManagerProxy::RequestRiskData(std::string &devId, std::string &eventList,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerProxy RequestRiskData");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
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
    SGLOGI("enter DataCollectManagerProxy Subscribe");
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_DATA_SUBSCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::Unsubscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerProxy Unsubscribe");
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_DATA_UNSUBSCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerProxy QuerySecurityEvent");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteUint32(rulers.size())) {
        SGLOGE("failed to WriteInt32 for parcelable vector size");
        return WRITE_ERR;
    }

    for (const auto &ruler : rulers) {
        if (!data.WriteParcelable(&ruler)) {
            SGLOGE("failed to WriteParcelable for parcelable");
            return WRITE_ERR;
        }
    }

    data.WriteRemoteObject(callback);

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_EVENT_QUERY, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerProxy CollectorStart");
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_COLLECTOR_START, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    SGLOGI("enter DataCollectManagerProxy CollectorStop");
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_COLLECTOR_STOP, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &updateInfo)
{
    SGLOGI("enter DataCollectManagerProxy ConfigUpdate");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteString(updateInfo.GetFileName())) {
        SGLOGE("failed to write string for config update");
        return WRITE_ERR;
    }
    if (!data.WriteFileDescriptor(updateInfo.GetFd())) {
        SGLOGE("failed to write file descriptor for config update");
        return WRITE_ERR;
    }
    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_CONFIG_UPDATE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}

int32_t DataCollectManagerProxy::QuerySecurityEventConfig(std::string &result)
{
    SGLOGI("Start DataCollectManagerProxy QuerySecurityEventConfig");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    
    MessageOption option = { MessageOption::TF_SYNC };
    int ret = remote->SendRequest(CMD_SECURITY_EVENT_CONFIG_QUERY, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }

    if (!reply.ReadString(result)) {
        SGLOGE("Failed to get the system integrity result");
        return BAD_PARAM;
    }
    return SUCCESS;
}

int32_t DataCollectManagerProxy::Mute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    SGLOGI("Start DataCollectManagerProxy Mute");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeMute)) {
        SGLOGE("failed to write parcelable for subscribeMute");
        return WRITE_ERR;
    }

    if (!data.WriteString(sdkFlag)) {
        SGLOGE("failed to write sdkFlag for subscribeMute");
        return WRITE_ERR;
    }
    data.WriteRemoteObject(callback);
    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_EVENT_MUTE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}
int32_t DataCollectManagerProxy::Unmute(const SecurityEventFilter &subscribeMute,
    const sptr<IRemoteObject> &callback, const std::string &sdkFlag)
{
    SGLOGI("Start DataCollectManagerProxy Unmute");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeMute)) {
        SGLOGE("failed to write parcelable for subscribeMute");
        return WRITE_ERR;
    }

    if (!data.WriteString(sdkFlag)) {
        SGLOGE("failed to write sdkFlag for Unmute");
        return WRITE_ERR;
    }
    data.WriteRemoteObject(callback);
    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_EVENT_UNMUTE, data, reply, option);
    if (ret != ERR_NONE) {
        SGLOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    SGLOGD("reply=%{public}d", ret);
    return ret;
}
}