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

#ifndef SECURITY_GUARD_EVENT_FILTER_H
#define SECURITY_GUARD_EVENT_FILTER_H

#include <string>
#include "parcel.h"
#include "event_info.h"
namespace OHOS::Security::SecurityGuard {
class SecurityEventFilter : public Parcelable {
public:
    SecurityEventFilter() = default;
    SecurityEventFilter(const EventMuteFilter &filter) :filter_(filter){}
    bool Marshalling(Parcel& parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static SecurityEventFilter* Unmarshalling(Parcel& parcel);
    EventMuteFilter GetMuteFilter() const;
private:
    EventMuteFilter filter_;
};
}
#endif // SECURITY_GUARD_EVENT_FILTER_H