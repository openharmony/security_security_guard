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

#ifndef SECURITY_GUARD_EVENT_INFO_H
#define SECURITY_GUARD_EVENT_INFO_H

#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <functional>
namespace OHOS::Security::SecurityGuard {
using EventMuteFilter = struct {
    int64_t eventId;
    bool isInclude;
    int64_t type;
    std::set<std::string> mutes;
};
class EventInfo {
public:
    EventInfo() = default;
    EventInfo(int64_t eventId, std::string version, std::string content);
    int64_t GetEventId() const;
    std::string GetVersion() const;
    std::string GetContent() const;

private:
    int64_t eventId_{};
    std::string version_{};
    std::string content_{};
};

using ClientSubScribeEventInfo = struct {
    int64_t eventId;
    std::string eventGroup;
};
using RequestRiskDataCallback = std::function<int32_t(std::string &, std::string &, uint32_t, const std::string &)>;
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_EVENT_INFO_H