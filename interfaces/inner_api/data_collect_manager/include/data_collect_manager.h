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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_H

#include <map>
#include <mutex>
#include "singleton.h"
#include "i_collector_subscriber.h"
#include "security_event_query_callback.h"
#include "data_collect_manager_callback_service.h"

namespace OHOS::Security::SecurityGuard {
class DataCollectManager : public Singleton<DataCollectManager> {
public:
    int32_t QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
                            std::shared_ptr<SecurityEventQueryCallback> callback);
};
}  // namespace OHOS::Security::SecurityGuard
#endif  // SECURITY_GUARD_DATA_COLLECT_MANAGER_H