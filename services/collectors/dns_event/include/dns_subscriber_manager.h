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

#ifndef SECURITY_GUARD_DNS_SUBSCRIBER_MANAGER_H
#define SECURITY_GUARD_DNS_SUBSCRIBER_MANAGER_H

#include <mutex>
#include <map>

#include "i_collector.h"
#include "i_collector_fwk.h"
#include "netsys_dns_report_callback.h"
#include "singleton.h"

namespace OHOS::Security::SecurityGuard {
class DnsSubscriberManager : public SecurityCollector::ICollector,
                            public Singleton<DnsSubscriberManager> {
public:
    ~DnsSubscriberManager() { Stop(); } // 析构时，如果已经注册事件监听，则主动注销
    int Start(std::shared_ptr<SecurityCollector::ICollectorFwk> api) override;
    int Stop() override;

private:
    std::map<uint32_t, std::string> ParseExtra(const std::string& extra);
    sptr<OHOS::NetManagerStandard::NetsysDnsReportCallback> dnsSubscriber_{nullptr};
    std::mutex subscriberMutex_{};
};
} // OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DNS_SUBSCRIBER_MANAGER_H