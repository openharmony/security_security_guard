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

#ifndef REQUEST_SECURITY_EVENT_INFO_NAPI_H
#define REQUEST_SECURITY_EVENT_INFO_NAPI_H

#include "event_info.h"
#include "event_define.h"
#include "security_guard_define.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS::Security::SecurityGuard {
class SecurityGuardSdkAdaptor {
public:
    static int32_t RequestSecurityEventInfo(std::string &devId, std::string &eventList,
        RequestRiskDataCallback callback);
    static int32_t RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
        const std::string &param, ResultCallback callback);
    static int32_t ReportSecurityInfo(const std::shared_ptr<EventInfo> &info);
    static int32_t SetModelState(uint32_t modelId, bool enable);
    static int32_t NotifyCollector(const SecurityCollector::Event &event, int64_t duration);

private:
    SecurityGuardSdkAdaptor() = delete;
    ~SecurityGuardSdkAdaptor() = delete;
};
} // OHOS::Security::SecurityGuard

#endif // REQUEST_SECURITY_EVENT_INFO_NAPI_H