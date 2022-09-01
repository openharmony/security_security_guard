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

#include "security_guard_utils.h"

#include <cerrno>

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t DEC_RADIX = 10;
}

bool SecurityGuardUtils::StrToU32(const std::string &str, uint32_t &value)
{
    unsigned long tmp = 0;
    bool isOK = StrToUL(str, tmp);
    value = tmp;
    return isOK && (tmp <= UINT32_MAX);
}

bool SecurityGuardUtils::StrToI64(const std::string &str, int64_t &value)
{
    long long tmp = 0;
    bool isOK = StrToLL(str, tmp);
    value = tmp;
    return isOK && (tmp >= INT64_MIN && tmp <= INT64_MAX);
}

bool SecurityGuardUtils::StrToLL(const std::string &str, long long &value)
{
    auto add = str.c_str();
    char *end = nullptr;
    errno = 0;
    value = strtoll(add, &end, DEC_RADIX);
    if ((errno == ERANGE && (value == LLONG_MAX || value == LLONG_MIN))
        || (errno != 0 && value == 0)) {
        SGLOGE("converse error");
        return false;
    } else if (end == add) {
        SGLOGE("no digit find");
        return false;
    } else if (end[0] != '\0') {
        SGLOGE("no all digit");
        return false;
    }

    return true;
}

bool SecurityGuardUtils::StrToUL(const std::string &str, unsigned long &value)
{
    auto add = str.c_str();
    char *end = nullptr;
    errno = 0;
    value = strtoll(add, &end, DEC_RADIX);
    if ((errno == ERANGE && value == ULONG_MAX)
        || (errno != 0 && value == 0)) {
        SGLOGE("converse error");
        return false;
    } else if (end == add) {
        SGLOGE("no digit find");
        return false;
    } else if (end[0] != '\0') {
        SGLOGE("no all digit");
        return false;
    }

    return true;
}
}