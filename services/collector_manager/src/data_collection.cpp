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
#include <cinttypes>
#include "json_cfg.h"
#include "security_collector_log.h"
#include "collector_cfg_marshalling.h"
#include "i_collector.h"
#include "event_define.h"

namespace OHOS::Security::SecurityCollector {
namespace {
#ifndef SECURITY_GUARD_ENABLE_EXT
    const char* SA_CONFIG_PATH = "/system/etc/security_audit.cfg";
#else
    const char* SA_CONFIG_PATH = "/system/etc/security_audit_ext.cfg";
#endif
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
        LOGI("StartCollectors eventId is 0x%{public}" PRIx64, eventId);
        if (IsCollectorStarted(eventId)) {
            LOGI("Collector already started, eventId is 0x%{public}" PRIx64, eventId);
            continue;
        }
        std::string collectorPath;
        ErrorCode ret = GetCollectorPath(eventId, collectorPath);
        if (ret != SUCCESS) {
            LOGE("GetCollectorPath failed, eventId is 0x%{public}" PRIx64, eventId);
            StopCollectors(loadedEventIds_);
            return false;
        }
        ret = LoadCollector(eventId, collectorPath, api);
        if (ret != SUCCESS) {
            LOGE("Load collector failed, eventId is 0x%{public}" PRIx64, eventId);
            StopCollectors(loadedEventIds_);
            return false;
        }
        loadedEventIds_.push_back(eventId);
    }
    LOGI("StartCollectors finish");
    return true;
}

bool DataCollection::SecurityGuardSubscribeCollector(const std::vector<int64_t>& eventIds)
{
    LOGI("Start to subscribe collectors start");
    for (int64_t eventId : eventIds) {
        LOGI("StartCollectors eventId is 0x%{public}" PRIx64, eventId);
        if (IsCollectorStarted(eventId)) {
            LOGI("Collector already started, eventId is 0x%{public}" PRIx64, eventId);
            continue;
        }
        std::string collectorPath;
        ErrorCode ret = GetCollectorPath(eventId, collectorPath);
        if (ret != SUCCESS) {
            LOGE("GetCollectorPath failed, eventId is 0x%{public}" PRIx64, eventId);
            continue;
        }
        ret = LoadCollector(eventId, collectorPath, nullptr);
        if (ret != SUCCESS) {
            LOGE("LoadCollector failed, eventId is 0x%{public}" PRIx64, eventId);
            continue;
        }
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
        LOGI("StopCollectors eventId is 0x%{public}" PRIx64, eventId);
        auto loader = eventIdToLoaderMap_.find(eventId);
        if (loader == eventIdToLoaderMap_.end()) {
            LOGI("Collector not found, eventId is 0x%{public}" PRIx64, eventId);
            continue;
        }
        ICollector* collector = loader->second.CallGetCollector();
        if (collector == nullptr) {
            LOGE("CallGetCollector error");
            ret = false;
        } else {
            int result = collector->Stop();
            int isStartWithSub = collector->IsStartWithSub();
            if (isStartWithSub == 1) {
                result = collector->Unsubscribe(eventId);
            }
            if (result != 0) {
                LOGE("Failed to stop collector, eventId is 0x%{public}" PRIx64, eventId);
                ret = false;
            }
            LOGI("Stop collector");
            eventIdToLoaderMap_.erase(loader);
        }
    }
    LOGI("StopCollectors finish");
    return ret;
}

void DataCollection::CloseLib()
{
    std::lock_guard<std::mutex> lock(closeLibmutex_);
    for (auto &it : needCloseLibMap_) {
        it.second.UnLoadLib();
    }
    needCloseLibMap_.clear();
}
ErrorCode DataCollection::LoadCollector(int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api)
{
    LOGI("Start LoadCollector");
    LibLoader loader(path);
    ErrorCode ret = loader.LoadLib();
    if (ret != SUCCESS) {
        LOGE("LoadLib error, ret=%{public}d, path : %{public}s", ret, path.c_str());
        return FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(closeLibmutex_);
        needCloseLibMap_.emplace(eventId, loader);
    }
    ICollector* collector = loader.CallGetCollector();
    if (collector == nullptr) {
        LOGE("CallGetCollector error");
        return FAILED;
    }
    int result = collector->Start(api);
    int isStartWithSub = collector->IsStartWithSub();
    if (isStartWithSub == 1) {
        result = collector->Subscribe(eventId);
    }
    if (result != 0) {
        LOGE("Failed to start collector");
        return FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    eventIdToLoaderMap_.emplace(eventId, loader);
    LOGI("End LoadCollector");
    return SUCCESS;
}

ErrorCode DataCollection::GetCollectorPath(int64_t eventId, std::string& path)
{
    LOGI("Start GetCollectorPath");
    std::ifstream stream(SA_CONFIG_PATH, std::ios::in);
    if (!stream.is_open()) {
        LOGE("Stream error, %{public}s", strerror(errno));
        return STREAM_ERROR;
    }
    ErrorCode ret = CheckFileStream(stream);
    if (ret != SUCCESS) {
        LOGE("check file stream error, ret=%{public}d", ret);
        stream.close();
        return ret;
    }
    nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    stream.close();

    if (json.is_discarded()) {
        LOGE("json is discarded");
        return JSON_ERR;
    }

    std::vector<ModuleCfgSt> moduleCfgs;
    if (!SecurityGuard::JsonCfg::Unmarshal<ModuleCfgSt>(moduleCfgs, json, MODULES)) {
        LOGE("Unmarshal moduleCfgs error");
        return JSON_ERR;
    }

    auto it = std::find_if(moduleCfgs.begin(), moduleCfgs.end(),
        [eventId] (const ModuleCfgSt &module) {
            auto ifIt = std::find(module.eventId.begin(), module.eventId.end(), eventId);
            if (ifIt != module.eventId.end()) {
                LOGI("success to find the event id: 0x%{public}" PRIx64, eventId);
                return true;
            } else {
                return false;
            }
        });
    if (it != moduleCfgs.end()) {
        path = it->modulePath + it->moduleName;
        return SUCCESS;
    }

    LOGE("The eventId does not exist");
    return FAILED;
}

ErrorCode DataCollection::GetCollectorType(int64_t eventId, int32_t& collectorType)
{
    LOGI("Start GetCollectorType");
    std::ifstream stream(SA_CONFIG_PATH, std::ios::in);
    if (!stream.is_open()) {
        LOGE("Stream error, %{public}s", strerror(errno));
        return STREAM_ERROR;
    }

    ErrorCode ret = CheckFileStream(stream);
    if (ret != SUCCESS) {
        LOGE("check file stream error, ret=%{public}d", ret);
        stream.close();
        return ret;
    }
    
    nlohmann::json json = nlohmann::json::parse(stream, nullptr, false);
    stream.close();

    if (json.is_discarded()) {
        LOGE("json is discarded");
        return JSON_ERR;
    }

    std::vector<ModuleCfgSt> moduleCfgs;
    if (!SecurityGuard::JsonCfg::Unmarshal<ModuleCfgSt>(moduleCfgs, json, MODULES)) {
        LOGE("Unmarshal moduleCfgs error");
        return JSON_ERR;
    }

    auto it = std::find_if(moduleCfgs.begin(), moduleCfgs.end(),
        [eventId] (const ModuleCfgSt &module) {
            auto ifIt = std::find(module.eventId.begin(), module.eventId.end(), eventId);
            if (ifIt != module.eventId.end()) {
                return true;
            } else {
                return false;
            }
        });
    if (it != moduleCfgs.end()) {
        collectorType = it->collectorType;
        LOGI("get event 0x%{public}" PRIx64 "collector type is %{public}d.", eventId, collectorType);
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
    std::ios::pos_type len = stream.tellg();
    if (len == 0) {
        LOGE("stream is empty");
        return STREAM_ERROR;
    }
    stream.seekg(0, std::ios::beg);
    return SUCCESS;
}

ErrorCode DataCollection::LoadCollector(std::string path, const SecurityEventRuler &ruler,
    std::vector<SecurityEvent> &events)
{
    LOGI("Start LoadCollector");
    LibLoader loader(path);
    ErrorCode ret = loader.LoadLib();
    if (ret != SUCCESS) {
        LOGE("LoadLib error, ret=%{public}d", ret);
        return FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(closeLibmutex_);
        needCloseLibMap_.emplace(ruler.GetEventId(), loader);
    }
    ICollector* collector = loader.CallGetCollector();
    if (collector == nullptr) {
        LOGE("CallGetCollector error");
        return FAILED;
    }
    int result = collector->Query(ruler, events);
    if (result != 0) {
        LOGE("Failed to start collector");
        return FAILED;
    }
    LOGI("End LoadCollector");
    return SUCCESS;
}

int32_t DataCollection::QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    LOGI("QuerySecurityEvent start");
    if (rulers.empty()) {
        LOGE("Invalid input parameter");
        return false;
    }
    for (const auto &ruler : rulers) {
        LOGI("QuerySecurityEvent eventId is 0x%{public}" PRIx64, ruler.GetEventId());
        std::string collectorPath;
        ErrorCode ret = GetCollectorPath(ruler.GetEventId(), collectorPath);
        if (ret != SUCCESS) {
            LOGE("GetCollectorPath failed, eventId is 0x%{public}" PRIx64, ruler.GetEventId());
            return false;
        }
        ret = LoadCollector(collectorPath, ruler, events);
        if (ret != SUCCESS) {
            LOGE("Load collector failed, eventId is 0x%{public}" PRIx64, ruler.GetEventId());
            return false;
        }
    }
    LOGI("StartCollectors finish");
    return true;
}

bool DataCollection::Mute(const SecurityCollectorEventMuteFilter &filter, const std::string &sdkFlag)
{
    if (!IsCollectorStarted(filter.eventId)) {
        LOGE("collector not start, eventId is 0x%{public}" PRIx64, filter.eventId);
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto loader = eventIdToLoaderMap_.at(filter.eventId);
    ICollector* collector = loader.CallGetCollector();
    if (collector == nullptr) {
        LOGE("CallGetCollector error");
        return false;
    }
    if (collector->Mute(filter, sdkFlag) != 0) {
        LOGE("fail to set mute to collector, eventId is 0x%{public}" PRIx64, filter.eventId);
        return false;
    }
    return true;
}

bool DataCollection::Unmute(const SecurityCollectorEventMuteFilter &filter, const std::string &sdkFlag)
{
    if (!IsCollectorStarted(filter.eventId)) {
        LOGE("collector not start, eventId is 0x%{public}" PRIx64, filter.eventId);
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto loader = eventIdToLoaderMap_.at(filter.eventId);
    ICollector* collector = loader.CallGetCollector();
    if (collector == nullptr) {
        LOGE("CallGetCollector error");
        return false;
    }
    if (collector->Unmute(filter, sdkFlag) != 0) {
        LOGE("fail to set unmute to collector, eventId is 0x%{public}" PRIx64, filter.eventId);
        return false;
    }
    return true;
}
}