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

#include <map>
#include <chrono>
#include <thread>
#include <nlohmann/json.hpp>

#include "hilog/log.h"

#include "dns_subscriber.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F07, "SG_DNS_COLLECTOR" };
    constexpr int SUCCESS = 0;
    constexpr long long DURATION_SECONDS = 10 * 60;
    constexpr uint32_t MAX_HOST = 100;
    const std::string BUNDLENAME = "pkg";
    const std::string IPV6_ADDR = "ip6_addr";
    const std::string IPV4_ADDR = "ip4_addr";
    const std::string HOST = "host";
}
DnsSubscriber::DnsSubscriber(std::shared_ptr<SecurityCollector::ICollectorFwk> api,
    std::map<uint32_t, std::string>& uidBundlename)
    : uidBundlename_(uidBundlename), startTime_(std::chrono::steady_clock::now())
{
    if (!api) {
        HiviewDFX::HiLog::Error(LABEL, "Null reporter");
    }
    api_ = api;
}

int32_t DnsSubscriber::OnDnsResultReport(uint32_t size,
    const std::list<NetsysNative::NetDnsResultReport> netDnsResultReport)
{
    HiviewDFX::HiLog::Info(LABEL, "On DnsResult listening ...");
    for (auto &it : netDnsResultReport) {
        if (uidBundlename_.find(it.uid_) == uidBundlename_.end()) {
            HiviewDFX::HiLog::Debug(LABEL, "Invalid uid");
            continue;
        }
        cache_.Add(it);
    }
    auto duration = std::chrono::duration_cast<std::chrono::seconds>
        (std::chrono::steady_clock::now() - startTime_).count();
    if (duration >= DURATION_SECONDS || cache_.Length() >= MAX_HOST) {
        HiviewDFX::HiLog::Info(LABEL, "Reporting DNS resolution result, %{public}zu items, duration %{public}lld s.",
            cache_.Length(), duration);
        ReportAll();
        cache_.Clear();
        startTime_ = std::chrono::steady_clock::now();
    }
    HiviewDFX::HiLog::Info(LABEL, "DnsResult listen end ...");
    return SUCCESS;
}

void DnsSubscriber::ReportAll()
{
    HiviewDFX::HiLog::Info(LABEL, "Reporting DnsResult ...");
    for (auto& [uid, bundlename] : uidBundlename_) {
        DnsResult re = cache_.GetDnsResult(uid);
        if (!re.host.empty()) {
            Report(bundlename, re);
        }
    }
    HiviewDFX::HiLog::Info(LABEL, "Report DnsResult end");
}

void DnsSubscriber::Report(const std::string& bundleName, const DnsResult& result)
{
    nlohmann::json jsonObj {
        {BUNDLENAME, bundleName},
        {HOST, result.host},
        {IPV4_ADDR, result.ipv4Addr},
        {IPV6_ADDR, result.ipv6Addr}
    };
    reportEvent_.content = jsonObj.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    api_->OnNotify(reportEvent_);
}
} // OHOS::Security::SecurityGuard
