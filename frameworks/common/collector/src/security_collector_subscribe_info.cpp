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

#include "security_collector_subscribe_info.h"

#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
namespace {
}

bool SecurityCollectorSubscribeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt64(duration_)) {
        LOGE("failed to write duration_");
        return false;
    }
    if (!parcel.WriteBool(isNotify_)) {
        LOGE("failed to write isNotify_");
        return false;
    }

    if (!parcel.WriteInt64(event_.eventId)) {
        LOGE("failed to write eventId");
        return false;
    }
    if (!parcel.WriteString(event_.version)) {
        LOGE("failed to write version");
        return false;
    }
    if (!parcel.WriteString(event_.content)) {
        LOGE("failed to write content");
        return false;
    }
    if (!parcel.WriteString(event_.extra)) {
        LOGE("failed to write extra");
        return false;
    }
   
    return true;
}

bool SecurityCollectorSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(duration_)) {
        LOGE("failed to read duration_");
        return false;
    }
    if (!parcel.ReadBool(isNotify_)) {
        LOGE("failed to read isNotify_");
        return false;
    }

    if (!parcel.ReadInt64(event_.eventId)) {
        LOGE("failed to read .eventId");
        return false;
    }
    if (!parcel.ReadString(event_.version)) {
        LOGE("failed to read version");
        return false;
    }
    if (!parcel.ReadString(event_.content)) {
        LOGE("failed to read content");
        return false;
    }
    if (!parcel.ReadString(event_.extra)) {
        LOGE("failed to read extra");
        return false;
    }

    return true;
}

SecurityCollectorSubscribeInfo *SecurityCollectorSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    SecurityCollectorSubscribeInfo *subscribeInfo = new (std::nothrow) SecurityCollectorSubscribeInfo();

    if (subscribeInfo && !subscribeInfo->ReadFromParcel(parcel)) {
        LOGE("failed to read from parcel");
        delete subscribeInfo;
        subscribeInfo = nullptr;
    }

    return subscribeInfo;
}
}