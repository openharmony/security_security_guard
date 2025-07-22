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

#ifndef SECURITY_COLLECTOR_SECURITY_EVENT_H
#define SECURITY_COLLECTOR_SECURITY_EVENT_H

#include <string>

#include "parcel.h"

namespace OHOS::Security::SecurityCollector {
class SecurityEvent : public Parcelable {
public:
    SecurityEvent() = default;
    SecurityEvent(int64_t eventId, const std::string &version = "",
        const std::string &content = "", const std::string &timestamp = "", int32_t userId = -1)
        : eventId_(eventId), version_(version), content_(content), timestamp_(timestamp), userId_(userId) {};
    ~SecurityEvent() override = default;

    int64_t GetEventId() const { return eventId_; };
    std::string GetVersion() const { return version_; };
    std::string GetContent() const { return content_; };
    std::string GetTimestamp() const { return timestamp_; };
    int32_t GetUserId() const { return userId_; };
    bool Marshalling(Parcel& parcel) const override { return true; };
    bool ReadFromParcel(Parcel &parcel) { return true; };
    static SecurityEvent* Unmarshalling(Parcel& parcel) { return {}; };

private:
    int64_t eventId_;
    std::string version_;
    std::string content_;
    std::string timestamp_;
    int32_t userId_;
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_COLLECTOR_SECURITY_EVENT_H
