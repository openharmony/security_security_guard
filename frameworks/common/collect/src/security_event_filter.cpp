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

#include "security_event_filter.h"
#include "security_guard_log.h"
namespace {
    constexpr size_t MAX_MUTE_SIZE = 10;
}
namespace OHOS::Security::SecurityGuard {
bool SecurityEventFilter::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt64(filter_.eventId)) {
        SGLOGE("failed to write eventId");
        return false;
    }
    if (!parcel.WriteInt64(filter_.type)) {
        SGLOGE("failed to write type");
        return false;
    }
    if (!parcel.WriteBool(filter_.isInclude)) {
        SGLOGE("failed to write isInclude");
        return false;
    }
    if (filter_.mutes.size() > MAX_MUTE_SIZE) {
        SGLOGE("the mutes size err");
        return false;
    }
    uint32_t size = static_cast<uint32_t>(filter_.mutes.size());
    if (!parcel.WriteUint32(size)) {
        SGLOGE("failed to write mutes size");
        return false;
    }
    for (const auto &iter : filter_.mutes) {
        if (!parcel.WriteString(iter)) {
            SGLOGE("failed to write mute");
            return false;
        }
    }
    return true;
};

bool SecurityEventFilter::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(filter_.eventId)) {
        SGLOGE("failed to read eventId");
        return false;
    }
    if (!parcel.ReadInt64(filter_.type)) {
        SGLOGE("failed to read type");
        return false;
    }
    if (!parcel.ReadBool(filter_.isInclude)) {
        SGLOGE("failed to read isInclude");
        return false;
    }
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        SGLOGE("failed to read mutes size");
        return false;
    }
    if (size > MAX_MUTE_SIZE) {
        SGLOGE("the event size error");
        return false;
    }
    for (uint32_t index = 0; index < size; index++) {
        std::string tmp;
        if (!parcel.ReadString(tmp)) {
            SGLOGE("failed to read mute");
            return false;
        }
        filter_.mutes.insert(tmp);
    }
    return true;
};

SecurityEventFilter* SecurityEventFilter::Unmarshalling(Parcel& parcel)
{
    SecurityEventFilter *filter = new (std::nothrow) SecurityEventFilter();
    if (filter != nullptr && !filter->ReadFromParcel(parcel)) {
        delete filter;
        filter = nullptr;
    }
    return filter;
};

EventMuteFilter SecurityEventFilter::GetMuteFilter() const
{
    return filter_;
}
}