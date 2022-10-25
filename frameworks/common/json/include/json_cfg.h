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

#ifndef SECURITY_GUARD_JSON_CFG_H
#define SECURITY_GUARD_JSON_CFG_H

#include "nlohmann/json.hpp"

namespace OHOS::Security::SecurityGuard {
#define JSON_CHECK_HELPER_RETURN_IF_FAILED(json, key, type, code) \
    do { \
        if ((json).find((key)) == (json).end()) { \
            return (code); \
        } \
        if (!(json).at((key)).is_##type()) { \
            return (code); \
        } \
    } while (0)

class JsonCfg {
public:
    static bool Unmarshal(uint64_t &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(int64_t &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(uint32_t &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(int32_t &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(std::string &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(std::vector<int32_t> &data, nlohmann::json jsonObj, std::string key);
    static bool Unmarshal(std::vector<std::string> &data, nlohmann::json jsonObj, std::string key);
    template<typename T>
    static bool Unmarshal(T &data, nlohmann::json jsonObj, std::string key)
    {
        JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, object, false);
        data = jsonObj.at(key).get<T>();
        return true;
    }

    template<typename T>
    static bool Unmarshal(std::vector<T> &data, nlohmann::json jsonObj, std::string key)
    {
        JSON_CHECK_HELPER_RETURN_IF_FAILED(jsonObj, key, array, false);
        nlohmann::json arrays = jsonObj.at(key);
        for (const auto &element : arrays) {
            if (!element.is_object()) {
                return false;
            }
            data.emplace_back(element.get<T>());
        }
        return true;
    }

private:
    JsonCfg() = default;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_JSON_CFG_H
