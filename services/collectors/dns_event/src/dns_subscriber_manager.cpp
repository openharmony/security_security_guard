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

#include <mutex>

#include "nlohmann/json.hpp"

#include "hilog/log.h"
#include "netsys_controller.h"
#include "dns_subscriber_manager.h"

#include "dns_subscriber.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F07, "SG_DNS_COLLECTOR" };
    constexpr int FAILED = -1;
    constexpr int SUCCESS = 0;
}
int DnsSubscriberManager::Start(std::shared_ptr<SecurityCollector::ICollectorFwk> api)
{
    HiviewDFX::HiLog::Info(LABEL, "Start DNS resolution audit ...");
    if (!api) {
        HiviewDFX::HiLog::Error(LABEL, "Reporter null");
        return FAILED;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    if (dnsSubscriber_) {
        HiviewDFX::HiLog::Error(LABEL, "Restart DNS resolution audit");
        return FAILED;
    }
    std::map<uint32_t, std::string> uidBundlename = ParseExtra(api->GetExtraInfo());
    if (uidBundlename.empty()) {
        HiviewDFX::HiLog::Error(LABEL, "Extra error");
        return FAILED;
    }
    dnsSubscriber_ = new(std::nothrow) DnsSubscriber(api, uidBundlename);
    if (!dnsSubscriber_) {
        HiviewDFX::HiLog::Error(LABEL, "Get subscriber failed");
        return FAILED;
    }
    int32_t regDnsResult =
        NetManagerStandard::NetsysController::GetInstance().RegisterDnsResultCallback(dnsSubscriber_, 0);
    if (regDnsResult != 0) {
        HiviewDFX::HiLog::Info(LABEL, "Register dns result callback failed");
        return FAILED;
    }
    HiviewDFX::HiLog::Error(LABEL, "Start DNS resolution seccuss, register dns result callback");
    return SUCCESS;
}

int DnsSubscriberManager::Stop()
{
    HiviewDFX::HiLog::Info(LABEL, "Stop DNS resolution audit ...");
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    if (!dnsSubscriber_) {
        HiviewDFX::HiLog::Error(LABEL, "Restop DNS resolution audit");
        return FAILED;
    }
    int32_t regDnsResult =
        NetManagerStandard::NetsysController::GetInstance().UnregisterDnsResultCallback(dnsSubscriber_);
    if (regDnsResult != 0) {
        dnsSubscriber_ = nullptr;
        HiviewDFX::HiLog::Info(LABEL, "Unregister dns result callback failed");
        return FAILED;
    }
    dnsSubscriber_ = nullptr;
    HiviewDFX::HiLog::Error(LABEL, "Stop DNS resolution seccuss, unregister dns result callback");
    return SUCCESS;
}

std::map<uint32_t, std::string> DnsSubscriberManager::ParseExtra(const std::string& extra)
{
    HiviewDFX::HiLog::Info(LABEL, "On Parse Extra");
    nlohmann::json extraJson = nlohmann::json::parse(extra, nullptr, false);
    if (extraJson.is_discarded()) {
        HiviewDFX::HiLog::Error(LABEL, "Parse Extra error");
        return {};
    }
    std::map<uint32_t, std::string> result{};
    for (auto& [key, val] : extraJson.items()) {
        if (key.empty()) {
            HiviewDFX::HiLog::Error(LABEL, "Parse Extra key empty");
            continue;
        }
        if (val.empty() || !val.is_number_unsigned()) {
            HiviewDFX::HiLog::Error(LABEL, "Parse Extra value error");
            continue;
        }
        result[val.get<uint32_t>()] = key;
    }
    HiviewDFX::HiLog::Info(LABEL, "Extra parsed");
    return result;
}
} // OHOS::Security::SecurityGuard