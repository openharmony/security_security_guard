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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_RUN_MANAGER_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_RUN_MANAGER_H

#include <map>
#include <set>
#include <mutex>
#include <memory>
#include "singleton.h"
#include "timer.h"

#include "i_collector_fwk.h"
#include "security_collector_subscriber.h"


namespace OHOS::Security::SecurityCollector {

class SecurityCollectorRunManager : public Singleton<SecurityCollectorRunManager> {
public:
    SecurityCollectorRunManager();
    bool StartCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber);
    bool StopCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber);
    void NotifySubscriber(const Event &event);
private:
    class CollectorListenner : public ICollectorFwk {
    public:
        CollectorListenner(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) : subscriber_(subscriber) {}
        std::string GetExtraInfo() override;
        void OnNotify(const Event &event) override;
    private:
        std::shared_ptr<SecurityCollectorSubscriber> subscriber_;
    };
    std::mutex collectorRunMutex_{};
    std::map<int64_t, std::shared_ptr<SecurityCollectorSubscriber>> collectorRunManager_{};
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H