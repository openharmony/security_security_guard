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

#ifndef SECURITY_COLLECTOR_NOTIFIER_FWK_H
#define SECURITY_COLLECTOR_NOTIFIER_FWK_H

#include "event_define.h"

namespace OHOS::Security::SecurityCollector {
class ICollectorFwk {
public:
    virtual ~ICollectorFwk() = default;
    virtual std::string GetExtraInfo() { return {}; };
    virtual void OnNotify(const Event &event) = 0; // { return Singleton<>().CollectorManager; };
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_COLLECTOR_NOTIFIER_FWK_H