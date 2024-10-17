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

#include "security_event_ruler.h"

namespace OHOS::Security::SecurityCollector {
bool SecurityEventRuler::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt64(eventId_)) {
        return false;
    }
    if (!parcel.WriteString(beginTime_)) {
        return false;
    }
    if (!parcel.WriteString(endTime_)) {
        return false;
    }
    if (!parcel.WriteString(param_)) {
        return false;
    }
    return true;
};

bool SecurityEventRuler::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(eventId_)) {
        return false;
    }
    if (!parcel.ReadString(beginTime_)) {
        return false;
    }
    if (!parcel.ReadString(endTime_)) {
        return false;
    }
    if (!parcel.ReadString(param_)) {
        return false;
    }
    return true;
};

SecurityEventRuler* SecurityEventRuler::Unmarshalling(Parcel& parcel)
{
    SecurityEventRuler *ruler = new (std::nothrow) SecurityEventRuler();
    if (ruler != nullptr && !ruler->ReadFromParcel(parcel)) {
        delete ruler;
        ruler = nullptr;
    }
    return ruler;
};
}