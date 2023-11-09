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

#ifndef SECURITY_COLLECTOR_SUBSCRIBER_H
#define SECURITY_COLLECTOR_SUBSCRIBER_H

#include <vector>

#include "security_collector_subscribe_info.h"

namespace OHOS::Security::SecurityCollector {
class ICollectorSubscriber {
public:
    ICollectorSubscriber(const Event &event, int64_t duration = -1, bool isNotify = false)
        : subscribeInfo_(event, duration, isNotify) {}
    virtual ~ICollectorSubscriber() = default;
    virtual int32_t OnNotify(const Event &event) = 0;
    SecurityCollectorSubscribeInfo GetSubscribeInfo() { return subscribeInfo_; }

private:
    SecurityCollectorSubscribeInfo subscribeInfo_;
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_COLLECTOR_SUBSCRIBER_H