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
using ModelCfg = struct {
    uint32_t modelId;
    std::string path;
    std::string format;
    uint32_t startMode;
    std::vector<int64_t> preload;
    std::vector<int64_t> eventList;
    std::string permissions;
    std::string dbTable;
    uint32_t runningCntl;
    std::vector<std::string> caller;
};

using EventCfg = struct {
    int64_t eventId;
    std::string eventName;
    uint32_t version;
    uint32_t eventType;
    uint32_t collectOnStart;
    uint32_t dataSensitivityLevel;
    uint32_t storageRamNums;
    uint32_t storageRomNums;
    int32_t storageTime;
    std::vector<std::string> owner;
    uint32_t source;
};

using DataMgrCfgSt = struct {
    uint32_t deviceRom;
    uint32_t deviceRam;
    uint32_t eventMaxRamNum;
    uint32_t eventMaxRomNum;
};

using EventContentSt = struct {
    uint32_t status;
    uint32_t cred;
    std::string extra;
};

using SecEvent = struct {
    int64_t eventId;
    std::string version;
    std::string date;
    std::string content;
    int32_t eventType;
    int32_t dataSensitivityLevel;
    std::string owner;
    int32_t userId;
    std::string deviceId;
};

using StartMode = enum {
    NOT_SUPPORT,
    START_ON_STARTUP,
    START_ON_DEMAND
};

using DataSource = enum {
    USER_SOURCE,
    KERNEL_SOURCE,
    MODEL_SOURCE,
    HIVIEW_SOURCE
};

using AppAttribute = enum {
    NORMAL,
    PAYMENT,
    MALICIOUS,
    MONITORING,
    ATTRMAX
};

using AppInfo = struct {
    std::string appName;
    std::string appHash;
    std::vector<std::string> attrs;
    int isGlobalApp;
    int isUpdate;
};

using LoadMode = enum {
    INIT_MODE,
    UPDATE_MODE
};

using PathIndex = enum {
    EVENT_CFG_INDEX,
    MODEL_CFG_INDEX
};

const std::vector<std::string> CONFIG_CACHE_FILES = {
    "/data/app/el1/100/base/com.ohos.security.hsdr/cache/security_guard/security_guard/security_guard_event.cfg",
    "/data/app/el1/100/base/com.ohos.security.hsdr/cache/security_guard/security_guard/security_guard_model.cfg"
};

const std::vector<std::string> CONFIG_UPTATE_FILES = {
    "/data/service/el1/public/security_guard/security_guard_event.cfg",
    "/data/service/el1/public/security_guard/security_guard_model.cfg"
};

const std::vector<std::string> CONFIG_PRESET_FILES = {
    "/system/etc/security_guard_event.cfg",
    "/system/etc/security_guard_model.cfg"
};

const std::string CONFIG_ROOT_PATH = "/data/app/el1/100/base/com.ohos.security.hsdr/cache/";
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DEFINE_H
