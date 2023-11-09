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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_SERVICE_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_SERVICE_H

#include "security_collector_manager_callback_stub.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityCollector {
class SecurityCollectorManagerCallbackService : public SecurityCollectorManagerCallbackStub {
public:
    explicit SecurityCollectorManagerCallbackService(const std::shared_ptr<ICollectorSubscriber> &subscriber)
        : subscriber_(subscriber) {}
    ~SecurityCollectorManagerCallbackService() override = default;

    int32_t OnNotify(const Event &event) override;

private:
    std::shared_ptr<ICollectorSubscriber> subscriber_;
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_SERVICE_H