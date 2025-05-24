/*
* Copyright(c) 2025 Huawei Device Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "lisence");
* you may not use this file except in compliance with the license;
* you may botain a copy of th license at
*
*     http://www.apache.org/license/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writting, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRINGS OR CONDITIONS OF ANY KIND, either express or implied
* See the License for the specific language governing premission and
* limitations under the License.
*/

#ifndef SECURITY_GUARD_FILE_UTIL_H
#define SECURITY_GUARD_FILE_UTIL_H

#include <cstdint>
#include <string>
#include <fstream>
#include <sstream>

namespace OHOS::Security::SecurityGuard {
namespace FileUtil {
    bool ReadFileToStr(const std::string &fileName, const std::ios::pos_type fileMaxSize, std::string &str);
}
} // namespace OHOS::Security::SecurityGuard

#endif