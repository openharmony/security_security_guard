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

#ifndef SECURITY_GUARD_CONFIG_SUBSCRIBER_H
#define SECURITY_GUARD_CONFIG_SUBSCRIBER_H

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"

namespace OHOS::Security::SecurityGuard {
class ConfigSubscriber : public EventFwk::CommonEventSubscriber {
public:
    explicit ConfigSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : EventFwk::CommonEventSubscriber(subscriberInfo) {};
    ~ConfigSubscriber() override;
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
    static bool Subscribe(void);

private:
    static bool UnSubscribe(void);
    static std::shared_ptr<ConfigSubscriber> subscriber_;
    static std::mutex mutex_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_SUBSCRIBER_H