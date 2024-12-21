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

#ifndef SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H
#define SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H

#include <string>
#include <vector>

#include "security_event_query_callback.h"
#include "security_event_query_callback_stub.h"
#include "security_event.h"

namespace OHOS::Security::SecurityGuard {
class SecurityEventQueryCallbackService : public SecurityEventQueryCallbackStub {
public:
    explicit SecurityEventQueryCallbackService(const std::shared_ptr<SecurityEventQueryCallback> callback)
        : queryCallback(callback) {}
    virtual ~SecurityEventQueryCallbackService() {}

    void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) override;

    void OnComplete() override;

    void OnError(const std::string &message) override;

private:
    std::shared_ptr<SecurityEventQueryCallback> queryCallback;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H
