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

#ifndef SECURITY_GUARD_MODEL_INFO_H
#define SECURITY_GUARD_MODEL_INFO_H

#include <string>
#include <vector>

namespace OHOS::Security::SecurityGuard {
using Field = struct {
    std::string fieldName;
    std::string fieldType;
    std::string value;
};

using Rule = struct {
    int64_t eventId;
    std::vector<Field> fields;
    std::string fieldsRelation;
};

using BuildInDetectionCfg = struct {
    std::vector<Rule> rules;
    std::string rulesRelation;
    std::string trueResult;
    std::string falseResult;
};

using AppDetectionCfg = struct {
    std::string detectionCategory;
    std::string configFileName;
    std::string trueResult;
    std::string falseResult;
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
    std::string type;
    BuildInDetectionCfg config;
    AppDetectionCfg appDetectionConfig;
};

enum class EventTypeEnum {
    NORMALE_COLL = 0,
    QUERY_COLL = 1,
    START_STOP_COLL = 2,
    SUBSCRIBE_COLL = 3
};


using DataMgrCfgSt = struct {
    uint32_t deviceRom;
    uint32_t deviceRam;
    uint32_t eventMaxRamNum;
    uint32_t eventMaxRomNum;
    std::string prog;
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

} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_INFO_H
