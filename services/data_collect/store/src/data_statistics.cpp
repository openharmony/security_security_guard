/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <atomic>
#include <cstdint>
#include <chrono>
#include <string>
#include <sstream>
#include "ffrt.h"
#include "security_guard_log.h"
#include "data_statistics.h"

namespace OHOS::Security::SecurityGuard {

DataStatistics &DataStatistics::GetInstance()
{
    static DataStatistics instance;
    return instance;
}

void DataStatistics::IncrementRequestDataSubmit(uint64_t count)
{
    requestDataSubmitDropCounters_.fetch_add(count);
}

void DataStatistics::IncrementInsertEvents(uint64_t count)
{
    insertEventsCounters_.fetch_add(count);
}

DataStatistics::DataStatistics()
{
    running_ = true;
    ffrt::submit([this]() { RunLoop(); });
}

DataStatistics::~DataStatistics()
{
    running_ = false;
}

void DataStatistics::RunLoop()
{
    constexpr int64_t PRINT_INTERVAL_SECONDS = 300;
    while (running_) {
        ffrt::this_task::sleep_for(std::chrono::seconds(PRINT_INTERVAL_SECONDS));
        std::stringstream ss;
        ss << "DataStatistics requestDataSubmitDropCounters = "
           << requestDataSubmitDropCounters_.load()
           << ", insertEventsCounters = "
           << insertEventsCounters_.load();
        SGLOGI("%{public}s", ss.str().c_str());
    }
}
} // namespace OHOS::Security::SecurityGuard