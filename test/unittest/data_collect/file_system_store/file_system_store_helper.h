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
#include <zlib.h>
#include "ffrt.h"
#include "i_model_info.h"
#include "i_data_collect_manager.h"
#include "json_cfg.h"
#include "store_define.h"
#include "security_event_ruler.h"
#include "security_event.h"

namespace OHOS::Security::SecurityGuard {
struct QueryRange {
    int64_t eventId;
    std::string startTime;
    std::string endTime;
};
class FileSystemStoreHelper {
public:
    static FileSystemStoreHelper &GetInstance();
    virtual int32_t InsertEvent(const SecEvent& event);
    virtual int32_t InsertEvents(const std::vector<SecEvent>& events);
    virtual int32_t QuerySecurityEvent(const SecurityCollector::SecurityEventRuler& ruler,
        sptr<ISecurityEventQueryCallback> proxy);

private:
    FileSystemStoreHelper();
    ~FileSystemStoreHelper();
    FileSystemStoreHelper(const FileSystemStoreHelper&) = delete;
    FileSystemStoreHelper& operator=(const FileSystemStoreHelper&) = delete;
    
    ffrt::mutex mutex_;
    gzFile currentGzFile_;           // 当前打开的文件句柄
    std::string currentFilePath_;     // 当前文件路径
    std::string currentEventFile_;    // 当前事件文件名
    std::string eventStartTime_;      // 事件开始时间
    
    virtual bool IsGzFile(const std::string& filename);
    virtual size_t GetFileSize(const std::string& filepath);
    virtual int32_t GetStoreFileList(std::vector<std::string>& storeFiles);
    virtual int32_t GetQueryStoreFileList(std::vector<std::string>& storeFiles,
        const std::string& startTime, const std::string& endTime);
    virtual SecurityCollector::SecurityEvent IsWantDate(const std::string& filename, const QueryRange& range);
    virtual std::string GetTimestampFromFileName(const std::string& filename);
    virtual std::string GetShortFileName(const std::string& filename);
    virtual std::string CreateNewStoreFile(const std::string& startTime);
    virtual std::string GetLatestStoreFile();
    virtual std::string GetBeginTimeFromFileName(const std::string& filename);
    virtual std::string GetEndTimeFromFileName(const std::string& filename);
    virtual void RenameStoreFile(const std::string& oldFilepath, const std::string& startTime,
        const std::string& endTime);
    virtual void DeleteOldestStoreFile();
    virtual uint32_t ProcessStoreFile(const std::string& filepath, const QueryRange& range,
        sptr<ISecurityEventQueryCallback> proxy, std::vector<SecurityCollector::SecurityEvent>& events);

    virtual bool OpenGzFile(const std::string& filepath);
    virtual void CloseGzFile();
    virtual void EnsureGzFileOpen(const std::string& filepath);
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_FILE_SYSTEM_STORE_HELPER_H