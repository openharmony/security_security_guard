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

namespace {
#ifndef SECURITY_GUARD_ENABLE_EXT
    const std::string &SECURITY_GUARD_EVENT_CFG_FILE = "security_guard_event.json";
    const std::string &SECURITY_GUARD_MODEL_CFG_FILE = "security_guard_model.cfg";
#else
    const std::string &SECURITY_GUARD_EVENT_CFG_FILE = "security_guard_event_ext.json";
    const std::string &SECURITY_GUARD_MODEL_CFG_FILE = "security_guard_model_ext.cfg";
#endif
}

namespace OHOS::Security::SecurityGuard {

using LoadMode = enum {
    INIT_MODE,
    UPDATE_MODE
};

using PathIndex = enum {
    EVENT_CFG_INDEX,
    MODEL_CFG_INDEX,
    SIG_RULE_CFG_INDEX,
    URL_RULE_CFG_INDEX,
    LOCAL_APP_CFG_INDEX,
    GLOBAL_APP_CFG_INDEX,
    RELATED_EVENT_ANALYSIS_CFG_INDEX
};

const std::vector<std::string> CONFIG_CACHE_FILES = {
    "/data/service/el1/public/security_guard/tmp/" + SECURITY_GUARD_EVENT_CFG_FILE,
    "/data/service/el1/public/security_guard/tmp/" + SECURITY_GUARD_MODEL_CFG_FILE,
    "/data/service/el1/public/security_guard/tmp/signature_rule.json",
    "/data/service/el1/public/security_guard/tmp/url_rule.json",
    "/data/service/el1/public/security_guard/tmp/local_app_attribute.json",
    "/data/service/el1/public/security_guard/tmp/global_app_attribute.json",
    "/data/service/el1/public/security_guard/tmp/related_event_analysis.json"
};

const std::vector<std::string> CONFIG_UPTATE_FILES = {
    "/data/service/el1/public/security_guard/" + SECURITY_GUARD_EVENT_CFG_FILE,
    "/data/service/el1/public/security_guard/" + SECURITY_GUARD_MODEL_CFG_FILE,
    "/data/service/el1/public/security_guard/signature_rule.json",
    "/data/service/el1/public/security_guard/url_rule.json",
    "/data/service/el1/public/security_guard/local_app_attr.json",
    "/data/service/el1/public/security_guard/global_app_attr.json",
    "/data/service/el1/public/security_guard/related_event_analysis.json"
};

const std::vector<std::string> CONFIG_PRESET_FILES = {
    "/system/etc/" + SECURITY_GUARD_EVENT_CFG_FILE,
    "/system/etc/" + SECURITY_GUARD_MODEL_CFG_FILE
};

const std::string CONFIG_ROOT_PATH = "/data/service/el1/public/security_guard/";
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DEFINE_H
