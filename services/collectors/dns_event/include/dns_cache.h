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

#ifndef SECURITY_GUARD_DNS_CACHE_H
#define SECURITY_GUARD_DNS_CACHE_H

#include <map>
#include <set>
#include <string>

#include "netsys_net_dns_result_data.h"

namespace OHOS::Security::SecurityGuard {
struct DnsResult {
    std::set<std::string> host;
    std::set<std::string> ipv4Addr;
    std::set<std::string> ipv6Addr;
};

class DnsCache {
public:
    explicit DnsCache() {};
    bool Add(const NetsysNative::NetDnsResultReport&);
    DnsResult GetDnsResult(uint32_t) const;
    void Clear();
    size_t Length() const;
private:
    struct UidIp {
        std::set<uint32_t> uid;
        std::set<std::string> ipv4Addr;
        std::set<std::string> ipv6Addr;
    };
    std::map<std::string, UidIp> cache_{};
};
} // OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DNS_CACHE_H