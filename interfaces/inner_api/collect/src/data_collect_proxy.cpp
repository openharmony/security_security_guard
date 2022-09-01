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

#include <chrono>
#include <ctime>

#include "data_collect_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TIME_BUF_LEN = 32;
}

DataCollectProxy::DataCollectProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IDataCollectManager>(impl)
{
}

std::string DataCollectProxy::GetData()
{
    time_t timestamp = time(nullptr);
    struct tm timeInfo{};
    localtime_r(&timestamp, &timeInfo);
    char buf[TIME_BUF_LEN] = {};
    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &timeInfo) == 0) {
        return "";
    }
    std::string data(buf);
    return data;
}

int32_t DataCollectProxy::RequestDataSubmit(const std::shared_ptr<EventInfo> &info)
{
    if (info == nullptr) {
        SGLOGE("info error");
        return NULL_OBJECT;
    }
    SGLOGE("eventId=%{public}ld, version=%{public}s",
        info->GetEventId(), info->GetVersion().c_str());
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }
    data.WriteInt64(info->GetEventId());
    data.WriteString(info->GetVersion());
    data.WriteString(GetData());
    data.WriteString(info->GetContent());

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
}