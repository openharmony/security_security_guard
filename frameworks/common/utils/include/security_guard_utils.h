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

#ifndef SECURITY_GUARD_SECURITY_GUARD_UTILS_H
#define SECURITY_GUARD_SECURITY_GUARD_UTILS_H

#include <string>

namespace OHOS::Security::SecurityGuard {
class SecurityGuardUtils {
public:
    static bool StrToU32(const std::string &str, uint32_t &value);
    static bool StrToI64(const std::string &str, int64_t &value);
    static bool StrToLL(const std::string &str, long long &value);
    static bool StrToULL(const std::string &str, unsigned long long &value);
    static std::string GetDate();
    static bool CopyFile(const std::string &srcPath, const std::string &dstPath);

private:
    SecurityGuardUtils() = default;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SECURITY_GUARD_UTILS_H
