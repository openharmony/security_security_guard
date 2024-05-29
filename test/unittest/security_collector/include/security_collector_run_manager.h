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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_RUN_MANAGER_MOCK_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_RUN_MANAGER_MOCK_H

#include <map>
#include <set>
#include <mutex>
#include <memory>

#include "gmock/gmock.h"

#include "i_collector_fwk.h"
#include "security_collector_subscriber.h"


namespace OHOS::Security::SecurityCollector {
class BaseSecurityCollectorRunManager {
public:
    virtual ~BaseSecurityCollectorRunManager() = default;
    virtual bool StartCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) = 0;
    virtual bool StopCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) = 0;
};

class SecurityCollectorRunManager : public BaseSecurityCollectorRunManager {
public:
    static SecurityCollectorRunManager &GetInstance()
    {
        static SecurityCollectorRunManager instance;
        return instance;
    };
    SecurityCollectorRunManager() = default;
    ~SecurityCollectorRunManager() override = default;
    MOCK_METHOD1(StartCollector, bool(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber));
    MOCK_METHOD1(StopCollector, bool (const std::shared_ptr<SecurityCollectorSubscriber> &subscriber));

    class CollectorListenner : public ICollectorFwk {
    public:
        CollectorListenner(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) : subscriber_(subscriber) {}
        std::string GetExtraInfo() override
        {
            if (subscriber_) {
                return subscriber_->GetSecurityCollectorSubscribeInfo().GetEvent().extra;
            }
            return {};
        };
        void OnNotify(const Event &event) override {};
    private:
        std::shared_ptr<SecurityCollectorSubscriber> subscriber_;
    };
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_RUN_MANAGER_MOCK_H