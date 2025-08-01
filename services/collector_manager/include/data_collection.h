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
#include <sstream>
#include "nlohmann/json.hpp"

#include "lib_loader.h"
#include "i_collector_fwk.h"
#include "security_event.h"
#include "security_event_ruler.h"

namespace OHOS::Security::SecurityCollector {

class DataCollection {
public:
    static DataCollection &GetInstance();
    bool StartCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api);
    bool StopCollectors(const std::vector<int64_t> &eventIds);
    bool SubscribeCollectors(const std::vector<int64_t> &eventIds, std::shared_ptr<ICollectorFwk> api);
    bool UnsubscribeCollectors(const std::vector<int64_t> &eventIds);
    ErrorCode GetCollectorType(int64_t eventId, int32_t &collectorType);
    int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
                               std::vector<SecurityEvent> &events);
    bool SecurityGuardSubscribeCollector(const std::vector<int64_t> &eventIds);
    void CloseLib();
    int32_t AddFilter(const SecurityCollectorEventMuteFilter &filter);
    int32_t RemoveFilter(const SecurityCollectorEventMuteFilter &filter);
private:
    DataCollection() = default;
    ErrorCode LoadCollector(int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api);
    ErrorCode LoadCollector(std::string path, const SecurityEventRuler &ruler, std::vector<SecurityEvent> &events);
    ErrorCode GetCollectorPath(int64_t eventId, std::string& path);
    ErrorCode CheckFileStream(std::ifstream &stream);
    bool IsCollectorStarted(int64_t eventId);
    std::mutex mutex_;
    std::mutex closeLibmutex_;
    std::unordered_map<int64_t, LibLoader> eventIdToLoaderMap_;
    std::unordered_map<int64_t, LibLoader> needCloseLibMap_;
};
}
#endif // DATA_COLLECTION_H