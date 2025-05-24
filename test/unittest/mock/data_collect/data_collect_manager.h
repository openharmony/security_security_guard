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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_H

#include "gmock/gmock.h"
#include <string>

#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {
class BaseDataCollectManager {
public:
    virtual int32_t QuerySecurityEventConfig(std::string &result) = 0;
    virtual int32_t Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
};

class DataCollectManager : public BaseDataCollectManager {
public:
    static DataCollectManager &GetInstance()
    {
        static DataCollectManager instance;
        return instance;
    }
    MOCK_METHOD1(QuerySecurityEventConfig, int32_t(std::string &result));
    MOCK_METHOD1(Subscribe, int32_t(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber));
};

} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H