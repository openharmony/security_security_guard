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

#include "event_info.h"

namespace OHOS::Security::SecurityGuard {
EventInfo::EventInfo(int64_t eventId, std::string version, std::string content)
{
    eventId_ = eventId;
    version_ = version;
    content_ = content;
}

int64_t EventInfo::GetEventId() const
{
    return eventId_;
}

std::string EventInfo::GetVersion() const
{
    return version_;
}

std::string EventInfo::GetContent() const
{
    return content_;
}
}