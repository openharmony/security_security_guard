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

#ifndef SECURITY_COLLECTOR_EVENT_FILTER_H
#define SECURITY_COLLECTOR_EVENT_FILTER_H

#include <string>
#include "parcel.h"
#include "event_define.h"
namespace OHOS::Security::SecurityCollector {
class SecurityCollectorEventFilter : public Parcelable {
public:
    SecurityCollectorEventFilter() = default;
    SecurityCollectorEventFilter(const SecurityCollectorEventMuteFilter &filter) :filter_(filter) {}
    bool Marshalling(Parcel& parcel) const override {return true;};
    bool ReadFromParcel(Parcel &parcel) {return true;};
    static SecurityCollectorEventFilter* Unmarshalling(Parcel& parcel) {return {};};
private:
    SecurityCollectorEventMuteFilter filter_;
};
}
#endif // SECURITY_COLLECTOR_SECURITY_EVENT_FILTER_H