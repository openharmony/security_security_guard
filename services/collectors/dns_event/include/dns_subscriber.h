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

#ifndef SECURITY_GUARD_DNS_SUBCCRIBER_H
#define SECURITY_GUARD_DNS_SUBCCRIBER_H

#include <list>
#include <map>

#include "netsys_dns_report_callback.h"

#include "i_collector_fwk.h"
#include "event_define.h"

#include "dns_cache.h"

namespace OHOS::Security::SecurityGuard {
namespace   {
    const std::string DNS_VERSION = "1.0";
    constexpr int64_t DNS_EVENT_ID = 1037000001;
}
class DnsSubscriber : public NetManagerStandard::NetsysDnsReportCallback {
public:
    explicit DnsSubscriber(std::shared_ptr<SecurityCollector::ICollectorFwk>, std::map<uint32_t, std::string>&);
    int32_t OnDnsResultReport(uint32_t, const std::list<NetsysNative::NetDnsResultReport>) override;
private:
    void ReportAll();
    void Report(const std::string& bundleName, const DnsResult& result);
    std::shared_ptr<SecurityCollector::ICollectorFwk> api_{};
    std::map<uint32_t, std::string> uidBundlename_{};
    DnsCache cache_{};
    SecurityCollector::Event reportEvent_ = {
        .eventId = DNS_EVENT_ID,
        .version = DNS_VERSION
    };
    std::chrono::steady_clock::time_point startTime_{};
};
} // OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DNS_SUBCCRIBER_H
