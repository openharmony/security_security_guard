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

#include "base_config.h"

#include "nlohmann/json.hpp"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t CFG_FILE_MAX_SIZE = 1 * 1024 * 1024; // byte
}

bool BaseConfig::Check()
{
    if (!stream_.is_open() ||!stream_) {
        SGLOGE("stream error");
        return false;
    }

    stream_.seekg(0, std::ios::end);
    int len = static_cast<int>(stream_.tellg());
    if (len == 0 || len > CFG_FILE_MAX_SIZE) {
        SGLOGE("stream is empty or too large, len = %{public}d", len);
        stream_.close();
        return false;
    }
    stream_.seekg(0, std::ios::beg);
    return true;
}

BaseConfig::~BaseConfig()
{
    if (stream_.is_open()) {
        stream_.close();
    }
}
} // OHOS::Security::SecurityGuard
