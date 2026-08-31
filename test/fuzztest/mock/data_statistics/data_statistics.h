/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef TEST_FUZZTEST_MOCK_DATA_STATISTICS_DATA_STATISTICS_H
#define TEST_FUZZTEST_MOCK_DATA_STATISTICS_DATA_STATISTICS_H

#include <cstdint>

namespace OHOS::Security::SecurityGuard {

class DataStatistics final {
public:
    static DataStatistics &GetInstance();
    void IncrementRequestDataSubmit(uint64_t count = 1);
    void IncrementInsertEvents(uint64_t count = 1);
    void IncrementPublishEvents(uint64_t count = 1);

private:
    DataStatistics();
    ~DataStatistics();
    DataStatistics(const DataStatistics &) = delete;
    DataStatistics &operator=(const DataStatistics &) = delete;

    void RunLoop();
};
} // namespace OHOS::Security::SecurityGuard
#endif  // TEST_FUZZTEST_MOCK_DATA_STATISTICS_DATA_STATISTICS_H
