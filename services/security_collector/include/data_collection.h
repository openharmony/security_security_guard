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

#ifndef DATA_COLLECTION_H
#define DATA_COLLECTION_H

#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include "nlohmann/json.hpp"

#include "lib_loader.h"
#include "i_collector_fwk.h"

namespace OHOS::Security::SecurityCollector {

class DataCollection {
public:
    static DataCollection &GetInstance();
    bool StartCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api);
    bool StopCollectors(const std::vector<int64_t>& eventIds);

private:
    DataCollection() = default;
    ErrorCode LoadCollector(int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api);
    ErrorCode GetCollectorPath(int64_t eventId, std::string& path);
    ErrorCode CheckFileStream(std::ifstream &stream);
    bool IsCollectorStarted(int64_t eventId);
    std::mutex mutex_;
    std::unordered_map<int64_t, std::unique_ptr<LibLoader>> eventIdToLoaderMap_;
};
}
#endif // DATA_COLLECTION_H