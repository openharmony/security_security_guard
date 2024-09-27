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

#include "security_event.h"

namespace OHOS::Security::SecurityCollector {
bool SecurityEvent::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt64(eventId_)) {
        return false;
    }
    if (!parcel.WriteString(version_)) {
        return false;
    }
    if (!parcel.WriteString(content_)) {
        return false;
    }
    if (!parcel.WriteString(timestamp_)) {
        return false;
    }
    return true;
};

bool SecurityEvent::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(eventId_)) {
        return false;
    }
    if (!parcel.ReadString(version_)) {
        return false;
    }
    if (!parcel.ReadString(content_)) {
        return false;
    }
    if (!parcel.ReadString(timestamp_)) {
        return false;
    }
    return true;
};

SecurityEvent* SecurityEvent::Unmarshalling(Parcel &parcel)
{
    SecurityEvent *event = new (std::nothrow) SecurityEvent();
    if (event != nullptr && !event->ReadFromParcel(parcel)) {
        delete event;
        event = nullptr;
    }

    return event;
};
}