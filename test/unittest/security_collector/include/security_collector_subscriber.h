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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_H

#include "iremote_object.h"
#include "event_define.h"
#include "security_collector_subscribe_info.h"

namespace OHOS::Security::SecurityCollector {
class SecurityCollectorSubscriber {
public:
    using EventHandler = std::function<void(const std::string &appName,
        const sptr<IRemoteObject> &remote, const Event &event)>;

    SecurityCollectorSubscriber(const std::string &appName,
        const SecurityCollectorSubscribeInfo &subseciberInfo,
        const sptr<IRemoteObject> &remote, EventHandler eventHandler)
        : appName_(appName), subseciberInfo_(subseciberInfo), remote_(remote), eventHandler_(eventHandler) {}

    void OnChange(const Event &event)
    {
        if (eventHandler_ != nullptr) {
            eventHandler_(appName_, remote_, event);
        }
    }

    sptr<IRemoteObject> GetRemote() const { return remote_; }
    SecurityCollectorSubscribeInfo GetSecurityCollectorSubscribeInfo() const { return subseciberInfo_; }
    std::string GetAppName() const { return appName_; }
private:
    std::string appName_;
    SecurityCollectorSubscribeInfo subseciberInfo_;
    sptr<IRemoteObject> remote_;
    EventHandler eventHandler_;
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_H
