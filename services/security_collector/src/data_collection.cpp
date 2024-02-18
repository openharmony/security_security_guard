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

#include "data_collection.h"

#include "json_cfg.h"
#include "security_collector_log.h"
#include "collector_cfg_marshalling.h"
#include "i_collector.h"

namespace OHOS::Security::SecurityCollector {
namespace {
    const char* SA_CONFIG_PATH = "/system/etc/security_audit.cfg";
}

DataCollection &DataCollection::GetInstance()
{
    static DataCollection instance;
    return instance;
}

bool DataCollection::StartCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api)
{
    LOGI("StartCollectors start");
    if (eventIds.empty() || !api) {
        LOGE("Invalid input parameter");
        return false;
    }
    std::vector<int64_t> loadedEventIds_;
    for (int64_t eventId : eventIds) {
        LOGI("StartCollectors eventId is %{public}" PRId64 "", eventId);
        if (IsCollectorStarted(eventId)) {
            LOGI("Collector already started, eventId is %{public}" PRId64 "", eventId);
            continue;
        }
        std::string collectorPath;
        ErrorCode ret = GetCollectorPath(eventId, collectorPath);
        if (ret != SUCCESS) {
            LOGE("GetCollectorPath failed, eventId is %{public}" PRId64 "", eventId);
            StopCollectors(loadedEventIds_);
            return false;
        }
        ret = LoadCollector(eventId, collectorPath, api);
        if (ret != SUCCESS) {
            LOGE("Load collector failed, eventId is %{public}" PRId64 "", eventId);
            StopCollectors(loadedEventIds_);
            return false;
        }
        loadedEventIds_.push_back(eventId);
    }
    LOGI("StartCollectors finish");
    return true;
}

bool DataCollection::IsCollectorStarted(int64_t eventId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eventIdToLoaderMap_.find(eventId);
    return it != eventIdToLoaderMap_.end();
}

bool DataCollection::StopCollectors(const std::vector<int64_t>& eventIds)
{
    LOGI("StopCollectors start");
    if (eventIds.empty()) {
        LOGW("The eventId list is empty");
        return true;
    }
    bool ret = true;
    std::lock_guard<std::mutex> lock(mutex_);
    for (int64_t eventId : eventIds) {
        LOGI("StopCollectors eventId is %{public}" PRId64 "", eventId);
        auto loader = eventIdToLoaderMap_.find(eventId);
        if (loader == eventIdToLoaderMap_.end()) {
            LOGI("Collector not found, eventId is %{public}" PRId64 "", eventId);
            continue;
        }
        ICollector* collector = loader->second->CallGetCollector();
        if (collector == nullptr) {
            LOGE("CallGetCollector error");
            ret = false;
        } else {
            int result = collector->Stop();
            if (result != 0) {
                LOGE("Failed to stop collector, eventId is %{public}" PRId64 "", eventId);
                ret = false;
            }
            LOGI("Stop collector");
            eventIdToLoaderMap_.erase(loader);
        }
    }
    LOGI("StopCollectors finish");
    return ret;
}

ErrorCode DataCollection::LoadCollector(int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api)
{
    LOGI("Start LoadCollector");
    std::unique_ptr<LibLoader> loader = std::make_unique<LibLoader>(path);
    ErrorCode ret = loader->LoadLib();
    if (ret != SUCCESS) {
        LOGE("LoadLib error, ret=%{public}d", ret);
        return FAILED;
    }
    ICollector* collector = loader->CallGetCollector();
    if (collector == nullptr) {
        LOGE("CallGetCollector error");
        return FAILED;
    }
    int result = collector->Start(api);
    if (result != 0) {
        LOGE("Failed to start collector");
        return FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    eventIdToLoaderMap_[eventId] = std::move(loader);
    LOGI("End LoadCollector");
    return SUCCESS;
}

ErrorCode DataCollection::GetCollectorPath(int64_t eventId, std::string& path)
{
    LOGI("Start GetCollectorPath");
    std::ifstream stream(SA_CONFIG_PATH, std::ios::in);
    if (!stream) {
        LOGE("stream error, %{public}s", strerror(errno));
        return STREAM_ERROR;
    }

    ErrorCode ret = CheckFileStream(stream);
    if (ret != SUCCESS) {
        LOGE("check file stream error, ret=%{public}d", ret);
        stream.close();
        return ret;
    }
    nlohmann::json json;
    stream >> json;
    stream.close();

    if (json.is_discarded()) {
        LOGE("parse json error");
        return JSON_ERR;
    }

    std::vector<ModuleCfgSt> moduleCfgs;
    if (!SecurityGuard::JsonCfg::Unmarshal<ModuleCfgSt>(moduleCfgs, json, MODULES)) {
        LOGE("Unmarshal moduleCfgs error");
        return JSON_ERR;
    }

    auto it = std::find_if(moduleCfgs.begin(), moduleCfgs.end(),
        [eventId] (const ModuleCfgSt &module) { return module.eventId == eventId;});
    if (it != moduleCfgs.end()) {
        path = it->modulePath + it->moduleName;
        return SUCCESS;
    }

    LOGE("The eventId does not exist");
    return FAILED;
}

ErrorCode DataCollection::CheckFileStream(std::ifstream &stream)
{
    if (!stream.is_open()) {
        LOGE("stream open error, %{public}s", strerror(errno));
        return STREAM_ERROR;
    }

    stream.seekg(0, std::ios::end);
    int len = static_cast<int>(stream.tellg());
    if (len == 0) {
        LOGE("stream is empty");
        return STREAM_ERROR;
    }
    stream.seekg(0, std::ios::beg);
    return SUCCESS;
}
}