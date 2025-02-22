/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_FILE_SYSTEM_STORE_HELPER_H
#define SECURITY_GUARD_FILE_SYSTEM_STORE_HELPER_H

#include <mutex>
#include "i_model_info.h"
#include "i_data_collect_manager.h"
#include "json_cfg.h"
#include "store_define.h"
#include "security_event_ruler.h"
#include "security_event.h"

namespace OHOS::Security::SecurityGuard {
class FileSystemStoreHelper {
public:
    static FileSystemStoreHelper &GetInstance();
    int32_t InsertEvent(const SecEvent& event);
    int32_t QuerySecurityEvent(const SecurityCollector::SecurityEventRuler ruler,
        sptr<ISecurityEventQueryCallback> proxy);

private:
    FileSystemStoreHelper() = default;
    ~FileSystemStoreHelper() = default;
    std::mutex mutex_;
    bool IsGzFile(const std::string& filename);
    size_t GetFileSize(const std::string& filepath);
    int32_t GetStoreFileList(std::vector<std::string>& storeFiles);
    int32_t GetQueryStoreFileList(std::vector<std::string>& storeFiles,
        const std::string& startTime, const std::string& endTime);
    SecurityCollector::SecurityEvent IsWantDate(const std::string& filename, int64_t eventid,
        std::string startTime, std::string endTime);
    SecurityCollector::SecurityEvent SecurityEventFromJson(nlohmann::json jsonObj);
    std::string GetTimestampFromFileName(const std::string& filename);
    std::string CreateNewStoreFile(const std::string& startTime);
    std::string GetLatestStoreFile();
    std::string GetEndTImeFromFileName(const std::string& fileTime);
    void WriteEventToGzFile(const std::string& filepath, const std::string& data);
    void RenameStoreFile(const std::string& oldFilepath, const std::string& startTime, const std::string& endTime);
    void DeleteOldestStoreFile();
    void QuerySecurityEventCallBack(sptr<ISecurityEventQueryCallback> proxy,
        std::vector<SecurityCollector::SecurityEvent> events);
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_FILE_SYSTEM_STORE_HELPER_H