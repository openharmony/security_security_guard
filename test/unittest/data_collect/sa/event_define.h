/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_COLLECTOR_EVENT_DEFINE_H
#define SECURITY_COLLECTOR_EVENT_DEFINE_H

#include <cstdint>
#include <string>
#include <set>
namespace OHOS::Security::SecurityCollector {
enum EventId : int64_t {
    PASTEBOARD_EVENTID = 1011015000,
    ACCOUNT_EVENTID,
    WINDOW_EVENTID,
    VOLUMN_EVENTID,
    PRINTER_EVENTID,
    FILE_EVENTID,
    PROCESS_EVENTID,
    NETWORK_EVENTID,
    FILE_GUARD_EVENTID,
    CAMERA_EVENTID,
    APPLICATION_EVENTID,
    MOUSE_EVENTID,
    KEYBOARD_EVENTID,
};

struct Event {
    int64_t eventId;
    std::string version;
    std::string content;
    std::string extra;
    std::string timestamp;
    std::set<std::string> eventSubscribes;
};

using SecurityCollectorEventMuteType = enum {
    EVENT_TYPE_EQUAL = 0,
    EVENT_SUB_TYPE_EQUAL = 1,
    PID_EQUAL = 2,
    FILE_PATH_EQUAL = 3,
    FILE_PATH_PREFIX = 4,
};

using SecurityCollectorEventMuteFilter = struct {
    int64_t eventId;
    SecurityCollectorEventMuteType type;
    std::vector<std::string> mutes;
    bool isSetMute;
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_COLLECTOR_EVENT_INFO_H