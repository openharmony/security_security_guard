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
#include <set>
#include <list>
#include <string>

#include "hilog/log.h"
#include "netsys_net_dns_result_data.h"

#include "dns_cache.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F07, "SG_DNS_COLLECTOR" };
}
bool DnsCache::Add(const NetsysNative::NetDnsResultReport& result)
{
    HiviewDFX::HiLog::Info(LABEL, "Cache adding ...");
    if (result.queryresult_ != 0) {
        HiviewDFX::HiLog::Debug(LABEL, "Invalid result");
        return false;
    }
    if (cache_.find(result.host_) == cache_.end()) {
        HiviewDFX::HiLog::Info(LABEL, "New host");
        UidIp uidIp{};
        cache_[result.host_] = uidIp;
    }
    cache_[result.host_].uid.insert(result.uid_);
    for (auto &it : result.addrlist_) {
        if (it.type_ == NetsysNative::ADDR_TYPE_IPV4) {
            cache_[result.host_].ipv4Addr.insert(it.addr_);
        } else if (it.type_ == NetsysNative::ADDR_TYPE_IPV6) {
            cache_[result.host_].ipv6Addr.insert(it.addr_);
        }
    }
    HiviewDFX::HiLog::Info(LABEL, "Cache add end");
    return true;
}

DnsResult DnsCache::GetDnsResult(uint32_t uid) const
{
    HiviewDFX::HiLog::Info(LABEL, "Getting DNS result ...");
    DnsResult dnsResult;
    for (auto &[host, uidIp] : cache_) {
        if (uidIp.uid.find(uid) == uidIp.uid.end()) {
            continue;
        }
        dnsResult.host.insert(host);
        dnsResult.ipv4Addr.insert(uidIp.ipv4Addr.begin(), uidIp.ipv4Addr.end());
        dnsResult.ipv6Addr.insert(uidIp.ipv6Addr.begin(), uidIp.ipv6Addr.end());
    }
    HiviewDFX::HiLog::Info(LABEL, "Get DNS result end");
    return dnsResult;
}

size_t DnsCache::Length() const
{
    return cache_.size();
}

void DnsCache::Clear()
{
    cache_.clear();
}
} // OHOS::Security::SecurityGuard