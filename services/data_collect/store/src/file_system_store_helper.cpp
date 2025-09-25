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

#include "file_system_store_helper.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <dirent.h>
#include <zlib.h>
#include <sys/stat.h>
#include <algorithm>
#include "bigdata.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "security_guard_define.h"
#include "data_statistics.h"

namespace OHOS::Security::SecurityGuard {
FileSystemStoreHelper::FileSystemStoreHelper() : currentGzFile_(nullptr)
{
}

FileSystemStoreHelper::~FileSystemStoreHelper()
{
    CloseGzFile();
}

FileSystemStoreHelper& FileSystemStoreHelper::GetInstance()
{
    static FileSystemStoreHelper instance;
    return instance;
}

size_t FileSystemStoreHelper::GetFileSize(const std::string& filepath)
{
    struct stat stat_buf;
    int rc = stat(filepath.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : 0;
}

// 获取最新的未写满的日志文件
std::string FileSystemStoreHelper::GetLatestStoreFile()
{
    SGLOGI("Enter FileSystemStoreHelper GetLatestStoreFile");
    std::vector<std::string> storeFiles;
    if (GetStoreFileList(storeFiles) != SUCCESS) {
        return "";
    }
    if (storeFiles.empty()) {
        return "";
    }
    std::sort(storeFiles.begin(), storeFiles.end(), std::greater<std::string>());
    for (const auto& filename : storeFiles) {
        std::string filepath = STORE_FILE_FOLDER_PATH + filename;
        if (GetFileSize(filepath) < SINGLE_FILE_SIZE) {
            return filepath;
        }
        std::string fileTime = GetTimestampFromFileName(filepath);
        size_t startPos = fileTime.find("_");
        if (startPos == std::string::npos) {
            RenameStoreFile(filepath, fileTime, SecurityGuardUtils::GetDate());
        }
        return "";
    }
    return "";
}

std::string FileSystemStoreHelper::CreateNewStoreFile(const std::string& startTime)
{
    std::string filename = STORE_FILE_FOLDER_PATH + STORE_FILE_NAME_PREFIX + startTime + STORE_FILE_NAME_SUFFIX;
    return filename;
}

std::string FileSystemStoreHelper::GetShortFileName(const std::string& filename)
{
    if (filename.empty()) {
        return "";
    }
    size_t startPos = filename.find(STORE_FILE_NAME_PREFIX);
    if (startPos == std::string::npos) {
        return "";
    }
    return filename.substr(startPos, filename.size() - startPos);
}

void FileSystemStoreHelper::RenameStoreFile(const std::string& oldFilepath, const std::string& startTime,
    const std::string& endTime)
{
    std::string newFilepath = STORE_FILE_FOLDER_PATH + STORE_FILE_NAME_PREFIX + startTime + "_" + endTime +
        STORE_FILE_NAME_SUFFIX;
    if (rename(oldFilepath.c_str(), newFilepath.c_str()) != 0) {
        std::string mesg = strerror(errno);
        SGLOGE("Failed to rename file:%{public}s, error msg:%{public}s",
            GetShortFileName(oldFilepath).c_str(), mesg.c_str());
        BigData::ReportFileSystemStoreEvent({"rename", GetShortFileName(oldFilepath), mesg});
    }
}

int32_t FileSystemStoreHelper::GetStoreFileList(std::vector<std::string>& storeFiles)
{
    DIR* dir = opendir(STORE_FILE_FOLDER_PATH.c_str());
    if (nullptr == dir) {
        SGLOGE("Store file dir is not exist!");
        return FILE_ERR;
    }
    dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string filename(ent->d_name);
        if (IsGzFile(filename)) {
            storeFiles.push_back(filename);
        }
    }
    closedir(dir);
    return SUCCESS;
}

// LCOV_EXCL_START
void FileSystemStoreHelper::DeleteOldestStoreFile()
{
    SGLOGI("Enter FileSystemStoreHelper DeleteOldestStoreFile");
    std::vector<std::string> storeFiles;
    if (GetStoreFileList(storeFiles) != SUCCESS) {
        return;
    }
    if (storeFiles.empty() || storeFiles.size() < MAX_STORE_FILE_COUNT) {
        SGLOGI("No need to delete oldest store file");
        return;
    }
    std::sort(storeFiles.begin(), storeFiles.end());
    for (size_t i = 0; i <= storeFiles.size() - MAX_STORE_FILE_COUNT; ++i) {
        std::string oldestFile = STORE_FILE_FOLDER_PATH + storeFiles[i];
        if (remove(oldestFile.c_str())) {
            std::string mesg = strerror(errno);
            SGLOGE("Failed to delete file:%{public}s, error msg:%{public}s",
                GetShortFileName(oldestFile).c_str(), mesg.c_str());
            BigData::ReportFileSystemStoreEvent({"delete", GetShortFileName(oldestFile), mesg});
        } else {
            SGLOGI("Deleted oldest log file:%{public}s", GetShortFileName(oldestFile).c_str());
        }
    }
}
// LCOV_EXCL_STOP

int32_t FileSystemStoreHelper::InsertEvent(const SecEvent& event)
{
    return InsertEvents({event});
}

int32_t FileSystemStoreHelper::InsertEvents(const std::vector<SecEvent>& events)
{
    SGLOGD("Enter FileSystemStoreHelper InsertEvents, size=%{public}zu", events.size());
    DataStatistics::GetInstance().IncrementInsertEvents(events.size());
    if (events.empty()) {
        return SUCCESS;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    
    // 检查文件是否存在，如果不存在则创建
    SGLOGD("CurrentEventFile:%{public}s", GetShortFileName(currentEventFile_).c_str());
    
    // 如果当前日志文件为空，尝试加载最新的未写满的文件
    if (currentEventFile_.empty()) {
        currentEventFile_ = GetLatestStoreFile();
        if (!currentEventFile_.empty()) {
            // 从文件名中提取起始时间
            eventStartTime_ = GetTimestampFromFileName(currentEventFile_);
        } else {
            // 没有未写满的文件，创建新文件
            eventStartTime_ = SecurityGuardUtils::GetDate();
        }
    }
    size_t curFileSize = GetFileSize(currentEventFile_);
    if (curFileSize == 0) {
        currentEventFile_ = CreateNewStoreFile(eventStartTime_);
        // 关闭旧文件句柄，新文件会在WriteEventToGzFile中打开
        CloseGzFile();
    } else if (curFileSize >= SINGLE_FILE_SIZE) {
        // 如果当前文件大小超过限制，创建新文件
        std::string endTime = SecurityGuardUtils::GetDate();
        RenameStoreFile(currentEventFile_, eventStartTime_, endTime);
        DeleteOldestStoreFile();
        eventStartTime_ = SecurityGuardUtils::GetDate();
        currentEventFile_ = CreateNewStoreFile(eventStartTime_);
        // 关闭旧文件句柄，新文件会在WriteEventToGzFile中打开
        CloseGzFile();
    }

    for (const auto& event : events) {
        EnsureGzFileOpen(currentEventFile_);
        if (currentGzFile_ == nullptr) {
            continue;
        }
        std::string date = event.date;
        if (date.empty()) {
            date = SecurityGuardUtils::GetDate();
        }
        std::string data = std::to_string(event.eventId) + "|" + date + "||" + std::to_string(event.userId) + "|||"
            + event.content;
        gzprintf(currentGzFile_, "%s\n", data.c_str());
    }
    gzflush(currentGzFile_, Z_FINISH);
    SGLOGD("InsertEvents file done");
    return SUCCESS;
}

bool FileSystemStoreHelper::IsGzFile(const std::string& filename)
{
    return filename.size() >= STORE_FILE_NAME_SUFFIX.length() &&
        filename.substr(filename.size() - STORE_FILE_NAME_SUFFIX.length()) == STORE_FILE_NAME_SUFFIX;
}

std::string FileSystemStoreHelper::GetTimestampFromFileName(const std::string& filename)
{
    if (filename.empty()) {
        return "";
    }
    size_t startPos = filename.find(STORE_FILE_NAME_PREFIX) + STORE_FILE_NAME_PREFIX.length();
    size_t endPos = filename.find(STORE_FILE_NAME_SUFFIX);
    if (startPos == std::string::npos || endPos == std::string::npos) {
        return "";
    }
    return filename.substr(startPos, endPos - startPos);
}

std::string FileSystemStoreHelper::GetBeginTimeFromFileName(const std::string& filename)
{
    if (filename.empty()) {
        return "";
    }
    size_t firstSeparator = filename.find(STORE_FILE_NAME_DELIMITER);
    if (firstSeparator == std::string::npos) {
        return "";
    }
    size_t secondSeparator = filename.find(STORE_FILE_NAME_DELIMITER, firstSeparator + 1);
    if (secondSeparator == std::string::npos) {
        secondSeparator = filename.find(STORE_FILE_NAME_SUFFIX, firstSeparator + 1);
        if (secondSeparator == std::string::npos) {
            return "";
        }
    }

    return filename.substr(firstSeparator + 1, secondSeparator - firstSeparator - 1);
}

std::string FileSystemStoreHelper::GetEndTimeFromFileName(const std::string& filename)
{
    if (filename.empty()) {
        return "";
    }
    size_t firstSeparator = filename.find(STORE_FILE_NAME_DELIMITER);
    if (firstSeparator == std::string::npos) {
        return "";
    }
    size_t secondSeparator = filename.find(STORE_FILE_NAME_DELIMITER, firstSeparator + 1);
    if (secondSeparator == std::string::npos) {
        return SecurityGuardUtils::GetDate();
    }

    size_t dotGzPos = filename.find(STORE_FILE_NAME_SUFFIX, secondSeparator + 1);
    if (dotGzPos == std::string::npos) {
        return "";
    }
    return filename.substr(secondSeparator + 1, dotGzPos - secondSeparator - 1);
}

// LCOV_EXCL_START
SecurityCollector::SecurityEvent FileSystemStoreHelper::IsWantDate(const std::string& fileEvent,
    const QueryRange& range)
{
    // fileEvent = "eventId|date||userId|||content"
    size_t firstPos = fileEvent.find(STORE_FILE_EVENT_FIRST_DELIMITER);
    size_t secondPos = fileEvent.find(STORE_FILE_EVENT_SECOND_DELIMITER);
    size_t thirdPos = fileEvent.find(STORE_FILE_EVENT_THRID_DELIMITER);
    if (firstPos == std::string::npos || secondPos == std::string::npos || thirdPos == std::string::npos ||
        firstPos >= secondPos || secondPos >= thirdPos) {
        return {};
    }
    std::string fileEventid = fileEvent.substr(0, firstPos);
    if (fileEventid != std::to_string(range.eventId)) {
        return {};
    }
    std::string fileEventTime = fileEvent.substr(firstPos + STORE_FILE_EVENT_FIRST_DELIMITER.length(),
        secondPos - (firstPos + STORE_FILE_EVENT_FIRST_DELIMITER.length()));
    if ((fileEventTime < range.startTime) || (fileEventTime > range.endTime)) {
        return {};
    }
    std::string userId = fileEvent.substr(secondPos + STORE_FILE_EVENT_SECOND_DELIMITER.length(),
        thirdPos - (secondPos + STORE_FILE_EVENT_SECOND_DELIMITER.length()));
    std::string fileEventContent = fileEvent.substr(thirdPos + STORE_FILE_EVENT_THRID_DELIMITER.length());
    return {range.eventId, "1.0", fileEventContent, fileEventTime, atoi(userId.c_str())};
}
// LCOV_EXCL_STOP

int32_t FileSystemStoreHelper::GetQueryStoreFileList(std::vector<std::string>& storeFiles,
    const std::string&  startTime, const std::string&  endTime)
{
    DIR* dir = opendir(STORE_FILE_FOLDER_PATH.c_str());
    if (nullptr == dir) {
        SGLOGE("Store file dir is not exist!");
        return FILE_ERR;
    }
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string filename(ent->d_name);
        if (IsGzFile(filename)) {
            std::string fileBeginTime = GetBeginTimeFromFileName(filename);
            std::string fileEndTime = GetEndTimeFromFileName(filename);
            if (fileBeginTime == "" || fileEndTime < startTime || fileBeginTime > endTime) {
                continue;
            }
            SGLOGD("QuerySecurityEvent add file:%{public}s", GetShortFileName(filename).c_str());
            storeFiles.push_back(filename);
        }
    }
    closedir(dir);
    return SUCCESS;
}

uint32_t FileSystemStoreHelper::ProcessStoreFile(const std::string& filepath, const QueryRange& range,
    sptr<ISecurityEventQueryCallback> proxy, std::vector<SecurityCollector::SecurityEvent>& events)
{
    SGLOGD("Found store file:%{public}s", GetShortFileName(filepath).c_str());
    gzFile file = gzopen(filepath.c_str(), "rb");
    if (!file) {
        std::string mesg = strerror(errno);
        SGLOGE("Failed to open store file:%{public}s, error msg:%{public}s",
            GetShortFileName(filepath).c_str(), mesg.c_str());
        BigData::ReportFileSystemStoreEvent({"open", GetShortFileName(filepath), mesg});
        return 0;
    }
    uint32_t batchCount = 0;
    char buffer[BUF_LEN];
    while (gzgets(file, buffer, sizeof(buffer))) {
        auto event = IsWantDate(std::string(buffer), range);
        if (event.GetEventId() == 0) {
            continue;
        }
        events.push_back(event);
        if (events.size() >= MAX_ON_QUERY_SIZE) {
            proxy->OnQuery(events);
            events.clear();
            ++batchCount;
        }
    }
    gzclose(file);
    return batchCount;
}

int32_t FileSystemStoreHelper::QuerySecurityEvent(const SecurityCollector::SecurityEventRuler& ruler,
    sptr<ISecurityEventQueryCallback> proxy)
{
    SGLOGI("Enter FileSystemStoreHelper QuerySecurityEvent");
    std::string startTime = ruler.GetBeginTime();
    std::string endTime = ruler.GetEndTime();
    int64_t eventid = ruler.GetEventId();
    if (ruler.GetBeginTime().empty()) {
        startTime = MIN_START_TIME;
    }
    if (ruler.GetEndTime().empty()) {
        endTime = SecurityGuardUtils::GetDate();
    }
    std::vector<std::string> storeFiles;
    if (GetQueryStoreFileList(storeFiles, startTime, endTime) != SUCCESS) {
        return FILE_ERR;
    }
    std::sort(storeFiles.begin(), storeFiles.end(), [this](const std::string& a, const std::string& b) {
        return GetTimestampFromFileName(a) < GetTimestampFromFileName(b);
    });
    SGLOGD("QuerySecurityEvent storeFiles size: %{public}zu", storeFiles.size());
    std::vector<SecurityCollector::SecurityEvent> events;
    events.reserve(MAX_ON_QUERY_SIZE);
    QueryRange range { eventid, startTime, endTime };
    uint32_t eventCount = 0;
    for (const auto& filename : storeFiles) {
        std::string filepath = STORE_FILE_FOLDER_PATH + filename;
        eventCount += ProcessStoreFile(filepath, range, proxy, events);
        if (eventCount > (MAX_QUERY_EVENTS_SIZE / MAX_ON_QUERY_SIZE)) {
            break;
        }
    }
    if (eventCount < (MAX_QUERY_EVENTS_SIZE / MAX_ON_QUERY_SIZE) && !events.empty()) {
        proxy->OnQuery(events);
    }
    return SUCCESS;
}

bool FileSystemStoreHelper::OpenGzFile(const std::string& filepath)
{
    if (currentGzFile_ != nullptr) {
        CloseGzFile();
    }
    
    currentGzFile_ = gzopen(filepath.c_str(), "ab");
    if (currentGzFile_ == nullptr) {
        std::string mesg = strerror(errno);
        SGLOGE("Failed to open file:%{public}s, error msg:%{public}s",
            GetShortFileName(filepath).c_str(), mesg.c_str());
        BigData::ReportFileSystemStoreEvent({"open", GetShortFileName(filepath), mesg});
        return false;
    }
    
    currentFilePath_ = filepath;
    return true;
}

void FileSystemStoreHelper::CloseGzFile()
{
    if (currentGzFile_ != nullptr) {
        gzclose(currentGzFile_);
        currentGzFile_ = nullptr;
        currentFilePath_.clear();
    }
}

void FileSystemStoreHelper::EnsureGzFileOpen(const std::string& filepath)
{
    if (currentFilePath_ != filepath || currentGzFile_ == nullptr) {
        OpenGzFile(filepath);
    }
}

} // namespace OHOS::Security::SecurityGuard