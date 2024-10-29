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

#ifndef SECURITY_GUARD_CONFIG_DEFINE_H
#define SECURITY_GUARD_CONFIG_DEFINE_H

#include <string>
#include <vector>

namespace OHOS::Security::SecurityGuard {
using LoadMode = enum {
    INIT_MODE,
    UPDATE_MODE
};

using PathIndex = enum {
    EVENT_CFG_INDEX,
    MODEL_CFG_INDEX
};

const std::vector<std::string> CONFIG_CACHE_FILES = {
    "/data/app/el1/100/base/com.ohos.security.hsdr/cache/security_guard/security_guard/security_guard_event.json",
    "/data/app/el1/100/base/com.ohos.security.hsdr/cache/security_guard/security_guard/security_guard_model.cfg"
};

const std::vector<std::string> CONFIG_UPTATE_FILES = {
    "/data/service/el1/public/security_guard/security_guard_event.json",
    "/data/service/el1/public/security_guard/security_guard_model.cfg"
};

const std::vector<std::string> CONFIG_PRESET_FILES = {
    "/system/etc/security_guard_event.json",
    "/system/etc/security_guard_model.cfg"
};

const std::string CONFIG_ROOT_PATH = "/data/app/el1/100/base/com.ohos.security.hsdr/cache/";
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DEFINE_H
