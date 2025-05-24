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

#ifndef SECURITY_GUARD_JSON_UTIL_H
#define SECURITY_GUARD_JSON_UTIL_H
#include <string>
#include <cstdint>
#include "cJSON.h"

namespace OHOS::Security::SecurityGuard {
namespace JsonUtil {
    bool GetNumberInt32(const cJSON *inJson, const std::string &item, int32_t &ret);
    bool GetNumberInt64(const cJSON *inJson, const std::string &item, int64_t &ret);
    bool GetString(const cJSON *inJson, const std::string &item, std::string &ret);
    bool GetBool(const cJSON *inJson, const std::string &item, bool &ret);
    bool AddString(cJSON *outJson, const std::string &item, const std::string &str);
    bool AddNumberInt32(cJSON *outJson, const std::string &item, const int32_t &num);
    bool AddNumberInt64(cJSON *outJson, const std::string &item, const int64_t &num);
    bool AddStrArrayInfo(cJSON *object, const std::vector<std::string> &inVector, const char &strKey);
    bool GetStringNokey(const cJSON *inJson, std::string &ret);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_JSON_UTIL_H