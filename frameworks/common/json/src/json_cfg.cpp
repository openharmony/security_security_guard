/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "json_cfg.h"

namespace OHOS::Security::SecurityGuard {
bool JsonCfg::Unmarshal(uint64_t &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, number, false);
    data = jsonObj.at(key).get<uint64_t>();
    return true;
}

bool JsonCfg::Unmarshal(int64_t &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, number, false);
    data = jsonObj.at(key).get<int64_t>();
    return true;
}

bool JsonCfg::Unmarshal(uint32_t &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, number, false);
    data = jsonObj.at(key).get<uint32_t>();
    return true;
}

bool JsonCfg::Unmarshal(int32_t &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, number, false);
    data = jsonObj.at(key).get<int32_t>();
    return true;
}

bool JsonCfg::Unmarshal(std::string &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, string, false);
    data = jsonObj.at(key).get<std::string>();
    return true;
}

bool JsonCfg::Unmarshal(std::vector<int32_t> &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, array, false);
    nlohmann::json arrays = jsonObj.at(key);
    for (const auto &element : arrays) {
        if (!element.is_number()) {
            return false;
        }
        data.emplace_back(element.get<int32_t>());
    }
    return true;
}

bool JsonCfg::Unmarshal(std::vector<std::string> &data, nlohmann::json jsonObj, std::string key)
{
    JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, array, false);
    nlohmann::json arrays = jsonObj.at(key);
    for (const auto &element : arrays) {
        if (!element.is_string()) {
            return false;
        }
        data.emplace_back(element.get<std::string>());
    }
    return true;
}
} // namespace OHOS::Security::SecurityGuard