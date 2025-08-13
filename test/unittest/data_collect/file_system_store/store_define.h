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

#ifndef SECURITY_GUARD_STORE_DEFINE_H
#define SECURITY_GUARD_STORE_DEFINE_H

#include <string>
#include <vector>

namespace OHOS::Security::SecurityGuard {
constexpr int INVALID_INDEX = -1;
constexpr int DB_VERSION = 1;
constexpr const char *ID = "id";
constexpr const char *USER_ID = "user_id";
constexpr const char *DEVICE_ID = "device_id";
constexpr const char *EVENT_ID = "event_id";
constexpr const char *VERSION = "version";
constexpr const char *DATE = "date";
constexpr const char *CONTENT = "content";
constexpr const char *TIMESTAMP = "timestamp";
constexpr const char *EVENT_TYPE = "event_type";
constexpr const char *DATA_SENSITIVITY_LEVEL = "data_sensitivity_level";
constexpr const char *OWNER = "owner";
constexpr const char *AUDIT_TABLE = "audit_event";
constexpr const char *FILE_SYSTEM = "file_system";
constexpr const char *RISK_TABLE = "risk_event";
constexpr const char *APP_INFO_TABLE = "app_info";

constexpr const char *APP_NAME = "app_name";
constexpr const char *APP_FINGERPRINT = "app_fingerprint";
constexpr const char *APP_ATTRIBUTES = "app_attributes";
constexpr const char *IS_GLOBAL_APP = "is_global_app";
constexpr size_t SINGLE_FILE_SIZE = 1024 * 1024 * 8;
constexpr size_t BUF_LEN = 2048;
constexpr int32_t MAX_ON_QUERY_SIZE = 100;
constexpr size_t MAX_QUERY_EVENTS_SIZE = 100000;
constexpr size_t MAX_STORE_FILE_COUNT = 128;

const std::string FOLDER_PATH = "/data/service/el1/public/database/security_guard_service/";
const std::string STORE_FILE_FOLDER_PATH = "/data/service/el1/public/database/security_guard_service/file_store/";
const std::string STORE_FILE_NAME = "sgevent.gz";
const std::string STORE_FILE_NAME_PREFIX = "sgevent_";
const std::string STORE_FILE_NAME_SUFFIX = ".gz";
const std::string STORE_FILE_EVENT_FIRST_DELIMITER = "|";
const std::string STORE_FILE_EVENT_SECOND_DELIMITER = "||";
const std::string STORE_FILE_EVENT_THRID_DELIMITER = "|||";
const std::string MIN_START_TIME = "19700101000000";

using SecEventTableInfo = struct {
    int32_t rowCount;
    int32_t columnCount;
    int32_t primaryKeyIndex;
    int32_t eventIdIndex;
    int32_t versionIndex;
    int32_t dateIndex;
    int32_t contentIndex;
    int32_t eventTypeIndex;
    int32_t dataSensitivityLevelIndex;
    int32_t ownerIndex;
    int32_t userIdIndex;
    int32_t deviceIdIndex;
};

using AppInfoTableInfo = struct {
    int32_t rowCount;
    int32_t columnCount;
    int32_t primaryKeyIndex;
    int32_t appNameIndex;
    int32_t appHashIndex;
    int32_t appAttrIndex;
    int32_t appIsGlobalAppIndex;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_STORE_DEFINE_H
