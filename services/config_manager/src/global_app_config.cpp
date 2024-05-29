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
#include "global_app_config.h"
#include <unordered_set>
#include "app_info_rdb_helper.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "security_guard_define.h"
#include "file_ex.h"
#include "json_cfg.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const char* APPS = "apps";
    const char* NAME = "name";
    const char* FINGERPRINTER = "fingerprint";
    const char* ATTRIBUTE = "attribute";
    constexpr uint32_t HASHLENGTH = 64;
    constexpr uint32_t MAXAPPNAMELENGTH = 256;
}
bool GlobalAppConfig::Load(int mode)
{
    std::string path;
    if (mode == INIT_MODE) {
        if (FileExists(CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX])) {
            path = CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX];
        } else {
            return true;
        }
    }
    if (mode == UPDATE_MODE) {
        if (FileExists(CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX])) {
            path = CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX];
        }
    }
    SGLOGD("path=%{public}s", path.c_str());
    if (path.empty()) {
        SGLOGE("path is empty");
        return false;
    }
    stream_ = std::ifstream(path, std::ios::in);
    if (!stream_.is_open() || !stream_) {
        SGLOGE("stream error, %{public}s", strerror(errno));
        return false;
    }
    return true;
}
bool GlobalAppConfig::Parse()
{
    return true;
}
bool GlobalAppConfig::Update()
{
    if (!stream_.is_open() || !stream_) {
        SGLOGE("stream error");
        return false;
    }
    nlohmann::json jsonObj = nlohmann::json::parse(stream_, nullptr, false);
    stream_.close();
    if (jsonObj.is_discarded()) {
        SGLOGE("Parse GlobalAppConfig json error");
        return false;
    }
    std::vector<AppInfo> configs;
    if (!ParseAppListConfig(configs, jsonObj)) {
        SGLOGE("parse GlobalAppConfig error");
        return false;
    }
    for (size_t i = 0; i < configs.size(); i++) {
        for (size_t j = i + 1; j < configs.size(); j++) {
            if (configs[i].appName == configs[j].appName) {
                SGLOGE("app%{public}s name repeate", configs[i].appName.c_str());
                return false;
            }
        }
    }
    if (AppInfoRdbHelper::GetInstance().DeleteAppInfoByIsGlobalApp(1) != SUCCESS) {
        SGLOGE("DeleteAppInfoByIsGlobalApp error");
        return false;
    }
    if (AppInfoRdbHelper::GetInstance().InsertAllAppInfo(configs)) {
        SGLOGE("InsertAllAppInfo error");
        return false;
    }
    SecurityGuardUtils::CopyFile(CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX], CONFIG_UPTATE_FILES[GLOBAL_APP_CFG_INDEX]);
    return true;
}

bool GlobalAppConfig::ParseAppListConfig(std::vector<AppInfo>& configs, const nlohmann::json& json)
{
    if (json.find(APPS) == json.end() || !json.at(APPS).is_array()) {
        SGLOGE("check %{public}s error", APPS);
        return false;
    }
    for (auto it : json.at(APPS)) {
        AppInfo config {};
        config.isGlobalApp = 1;
        if (!JsonCfg::Unmarshal(config.appHash, it, FINGERPRINTER) || config.appHash.size() != HASHLENGTH) {
            SGLOGE("parse %{public}s error", FINGERPRINTER);
            return false;
        }
        if (!JsonCfg::Unmarshal(config.appName, it, NAME) || config.appName.size() > MAXAPPNAMELENGTH ||
            config.appName.empty()) {
            SGLOGE("parse %{public}s error", NAME);
            return false;
        }
        std::unordered_set<std::string> tmp = {"monitoring", "payment", "malicious"};
        if (!JsonCfg::Unmarshal(config.attrs, it, ATTRIBUTE) || config.attrs.size() >= ATTRMAX) {
            SGLOGE("parse %{public}s error", ATTRIBUTE);
            return false;
        }
        for (auto iter : config.attrs) {
            if (tmp.count(iter) == 0) {
                SGLOGE("check %{public}s error", ATTRIBUTE);
                return false;
            }
        }
        configs.emplace_back(config);
    }
    return true;
}
}
