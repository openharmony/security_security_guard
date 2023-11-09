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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBE_INFO_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBE_INFO_H

#include "parcel.h"
#include "event_define.h"

namespace OHOS::Security::SecurityCollector {
class SecurityCollectorSubscribeInfo : public Parcelable {
public:
    SecurityCollectorSubscribeInfo() {}
    SecurityCollectorSubscribeInfo(const Event &event, int64_t duration = -1, bool isNotify = false)
        : event_(event), duration_(duration), isNotify_(isNotify) {}
    ~SecurityCollectorSubscribeInfo() override = default;

    Event GetEvent() const { return event_; };
    int64_t GetDuration() const { return duration_; };
    bool IsNotify() const { return isNotify_; };
    bool Marshalling(Parcel &parcel) const override;
    static SecurityCollectorSubscribeInfo *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);
    Event event_{};
    int64_t duration_{};
    bool isNotify_{};
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBE_INFO_H