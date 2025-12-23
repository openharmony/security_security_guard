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
}

void DataStatistics::IncrementInsertEvents(uint64_t count)
{
}

void DataStatistics::IncrementPublishEvents(uint64_t count)
{
}

DataStatistics::DataStatistics()
{}

DataStatistics::~DataStatistics()
{}

void DataStatistics::RunLoop()
{}
} // namespace OHOS::Security::SecurityGuard