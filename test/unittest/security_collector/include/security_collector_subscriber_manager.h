/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H

#include <map>
#include <set>
#include <mutex>
#include <memory>
#include "timer.h"

#include "i_collector_fwk.h"
#include "i_event_filter.h"
#include "i_event_wrapper.h"
#include "security_collector_subscriber.h"
#include "security_collector_event_filter.h"

namespace OHOS::Security::SecurityCollector {
typedef SecurityCollector::IEventFilter* (*GetEventFilterFunc)();
typedef SecurityCollector::IEventWrapper* (*GetEventWrapperFunc)();
class SecurityCollectorSubscriberManager {
public:
    using UnsubscribeHandler = std::function<void (const sptr<IRemoteObject> &remote)>;
    static SecurityCollectorSubscriberManager &GetInstance()
    {
        static SecurityCollectorSubscriberManager instance;
        return instance;
    }
    SecurityCollectorSubscriberManager() = default;
    bool SubscribeCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) { return false; };
    bool UnsubscribeCollector(const sptr<IRemoteObject> &remote) { return false; };
    void SetUnsubscribeHandler(UnsubscribeHandler handler) { };
    int32_t AddFilter(const SecurityCollectorEventFilter &subscribeMute) { return 0; };
    int32_t RemoveFilter(const SecurityCollectorEventFilter &subscribeMute) { return 0; };
    void RemoveAllFilter() {};
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H