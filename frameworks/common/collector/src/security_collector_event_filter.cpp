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

#include "security_collector_event_filter.h"
#include "security_collector_log.h"
namespace {
    constexpr size_t MAX_MUTE_SIZE = 10;
}
namespace OHOS::Security::SecurityCollector {
bool SecurityCollectorEventFilter::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt64(filter_.eventId)) {
        LOGE("failed to write eventId");
        return false;
    }
    if (!parcel.WriteInt64(filter_.type)) {
        LOGE("failed to write type");
        return false;
    }
    if (!parcel.WriteBool(filter_.isInclude)) {
        LOGE("failed to write type");
        return false;
    }
    if (filter_.mutes.size() > MAX_MUTE_SIZE) {
        LOGE("the mutes size err");
        return false;
    }
    if (!parcel.WriteUint32(filter_.mutes.size())) {
        LOGE("failed to write mutes size");
        return false;
    }
    for (const auto &iter : filter_.mutes) {
        if (!parcel.WriteString(iter)) {
            LOGE("failed to write mute");
            return false;
        }
    }
    return true;
};

bool SecurityCollectorEventFilter::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(filter_.eventId)) {
        LOGE("failed to read eventId");
        return false;
    }
    if (!parcel.ReadInt64(filter_.type)) {
        LOGE("failed to read type");
        return false;
    }
    if (!parcel.ReadBool(filter_.isInclude)) {
        LOGE("failed to read isInclude");
        return false;
    }
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        LOGE("failed to read mutes size");
        return false;
    }
    if (size > MAX_MUTE_SIZE) {
        LOGE("the event size error");
        return false;
    }
    for (uint32_t index = 0; index < size; index++) {
        std::string tmp;
        if (!parcel.ReadString(tmp)) {
            LOGE("failed to read mute");
            return false;
        }
        filter_.mutes.emplace_back(tmp);
    }
    return true;
};

SecurityCollectorEventFilter* SecurityCollectorEventFilter::Unmarshalling(Parcel& parcel)
{
    SecurityCollectorEventFilter *filter = new (std::nothrow) SecurityCollectorEventFilter();
    if (filter != nullptr && !filter->ReadFromParcel(parcel)) {
        delete filter;
        filter = nullptr;
    }
    return filter;
};

SecurityCollectorEventMuteFilter SecurityCollectorEventFilter::GetMuteFilter() const
{
    return filter_;
}
}