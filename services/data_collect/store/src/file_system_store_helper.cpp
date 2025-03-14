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

namespace OHOS::Security::SecurityGuard {
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
    return filename.substr(startPos, filename.size() - startPos);
}

void FileSystemStoreHelper::WriteEventToGzFile(const std::string& filepath, const std::string& data)
{
    gzFile file = gzopen(filepath.c_str(), "ab");
    if (!file) {
        char *mesg = strerror(errno);
        SGLOGE("Failed to open file::%{public}s, error msg:%{public}s", GetShortFileName(filepath).c_str(), mesg);
        BigData::ReportFileSystemStoreEvent({"write", GetShortFileName(filepath), mesg});
        return;
    }
    gzprintf(file, "%s\n", data.c_str());
    gzclose(file);
}

void FileSystemStoreHelper::RenameStoreFile(const std::string& oldFilepath, const std::string& startTime,
    const std::string& endTime)
{
    std::string newFilepath = STORE_FILE_FOLDER_PATH + STORE_FILE_NAME_PREFIX + startTime + "_" + endTime +
        STORE_FILE_NAME_SUFFIX;
    if (rename(oldFilepath.c_str(), newFilepath.c_str()) != 0) {
        char *mesg = strerror(errno);
        SGLOGE("Failed to rename file:%{public}s, error msg:%{public}s", GetShortFileName(oldFilepath).c_str(), mesg);
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
    std::string oldestFile = STORE_FILE_FOLDER_PATH + storeFiles[0];
    if (remove(oldestFile.c_str())) {
        char *mesg = strerror(errno);
        SGLOGE("Failed to delete file:%{public}s, error msg:%{public}s", GetShortFileName(oldestFile).c_str(), mesg);
        BigData::ReportFileSystemStoreEvent({"delete", GetShortFileName(oldestFile), mesg});
    } else {
        SGLOGI("Deleted oldest log file:%{public}s", GetShortFileName(oldestFile).c_str());
    }
}

int32_t FileSystemStoreHelper::InsertEvent(const SecEvent& event)
{
    SGLOGD("Enter FileSystemStoreHelper InsertEvent");
    static std::string currentEventFile;
    static std::string eventStartTime;
    nlohmann::json eventJson = nlohmann::json {
        { EVENT_ID, event.eventId },
        { VERSION, event.version },
        { CONTENT, event.content },
        { TIMESTAMP,  SecurityGuardUtils::GetDate() }
    };
    std::string data = std::to_string(event.eventId) + "|" + event.date + "||" + eventJson.dump();
    // 检查文件是否存在，如果不存在则创建
    SGLOGD("CurrentEventFile:%{public}s", GetShortFileName(currentEventFile).c_str());
    // 如果当前日志文件为空，尝试加载最新的未写满的文件
    std::lock_guard<std::mutex> lock(mutex_);
    if (currentEventFile.empty()) {
        currentEventFile = GetLatestStoreFile();
        if (!currentEventFile.empty()) {
            // 从文件名中提取起始时间
            eventStartTime = GetTimestampFromFileName(currentEventFile);
        } else {
            // 没有未写满的文件，创建新文件
            eventStartTime = SecurityGuardUtils::GetDate();
            currentEventFile = CreateNewStoreFile(eventStartTime);
        }
    }
    // 如果当前文件大小超过限制，创建新文件
    if (GetFileSize(currentEventFile) >= SINGLE_FILE_SIZE) {
        std::string endTime = SecurityGuardUtils::GetDate();
        RenameStoreFile(currentEventFile, eventStartTime, endTime);
        DeleteOldestStoreFile();
        eventStartTime = SecurityGuardUtils::GetDate();
        currentEventFile = CreateNewStoreFile(eventStartTime);
    }
    WriteEventToGzFile(currentEventFile, data);
    SGLOGD("Insert file done");
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
    return filename.substr(startPos, endPos - startPos);
}

std::string FileSystemStoreHelper::GetEndTImeFromFileName(const std::string& fileTime)
{
    size_t startPos = fileTime.find("_");
    if (startPos == std::string::npos) {
        return SecurityGuardUtils::GetDate();
    }
    return fileTime.substr(startPos);
}

SecurityCollector::SecurityEvent FileSystemStoreHelper::SecurityEventFromJson(nlohmann::json jsonObj)
{
    int64_t eventId;
    std::string version;
    std::string content;
    std::string timestamp;
    SecurityGuard::JsonCfg::Unmarshal(eventId, jsonObj, EVENT_ID);
    SecurityGuard::JsonCfg::Unmarshal(version, jsonObj, VERSION);
    SecurityGuard::JsonCfg::Unmarshal(content, jsonObj, CONTENT);
    SecurityGuard::JsonCfg::Unmarshal(timestamp, jsonObj, TIMESTAMP);
    return SecurityCollector::SecurityEvent{eventId, version, content, timestamp};
}

SecurityCollector::SecurityEvent FileSystemStoreHelper::IsWantDate(const std::string& fileEvent, int64_t eventid,
    std::string startTime, std::string endTime)
{
    size_t firstPos = fileEvent.find(STORE_FILE_EVENT_FIRST_DELIMITER);
    size_t secondPos = fileEvent.find(STORE_FILE_EVENT_SECOND_DELIMITER);
    std::string fileEventid = fileEvent.substr(0, firstPos);
    if (fileEventid != std::to_string(eventid)) {
        return {};
    }
    std::string fileEventTime = fileEvent.substr(firstPos + STORE_FILE_EVENT_FIRST_DELIMITER.length(), secondPos);
    if ((fileEventTime < startTime) || (fileEventTime > endTime)) {
        return {};
    }
    std::string fileEventJson = fileEvent.substr(secondPos + STORE_FILE_EVENT_SECOND_DELIMITER.length());
    nlohmann::json jsonObj = nlohmann::json::parse(fileEventJson, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("FileSystemStoreHelper json parse error");
        return {};
    }
    return SecurityEventFromJson(jsonObj);
}

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
            std::string timestamp = GetTimestampFromFileName(filename);
            std::string fileEndTime = GetEndTImeFromFileName(timestamp);
            if (fileEndTime < startTime || timestamp > endTime) {
                continue;
            }
            SGLOGD("QuerySecurityEvent add file:%{public}s", GetShortFileName(filename).c_str());
            storeFiles.push_back(filename);
        }
    }
    closedir(dir);
    return SUCCESS;
}

void FileSystemStoreHelper::QuerySecurityEventCallBack(sptr<ISecurityEventQueryCallback> proxy,
    std::vector<SecurityCollector::SecurityEvent> events)
{
    int32_t step = MAX_ON_QUERY_SIZE;
    if (events.size() > 0 && events.size() <= static_cast<size_t>(MAX_ON_QUERY_SIZE)) {
        proxy->OnQuery(events);
    } else if (events.size() > static_cast<size_t>(MAX_ON_QUERY_SIZE)) {
        std::vector<SecurityCollector::SecurityEvent>::iterator curPtr = events.begin();
        std::vector<SecurityCollector::SecurityEvent>::iterator endPtr = events.end();
        std::vector<SecurityCollector::SecurityEvent>::iterator end;
        while (curPtr < endPtr) {
            end = endPtr - curPtr > step ? step + curPtr : endPtr;
            step = endPtr - curPtr > step ? step : endPtr - curPtr;
            proxy->OnQuery(std::vector<SecurityCollector::SecurityEvent>(curPtr, end));
            curPtr += step;
        }
    }
}


int32_t FileSystemStoreHelper::QuerySecurityEvent(const SecurityCollector::SecurityEventRuler ruler,
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
    std::vector<SecurityCollector::SecurityEvent> events;
    for (const auto& filename : storeFiles) {
        std::string filepath = STORE_FILE_FOLDER_PATH + filename;
        SGLOGD("Found store file:%{public}s", GetShortFileName(filepath).c_str());
        gzFile file = gzopen(filepath.c_str(), "rb");
        if (!file) {
            char *mesg = strerror(errno);
            SGLOGE("Failed to open store file:%{public}s, error msg:%{public}s",
                GetShortFileName(filepath).c_str(), mesg);
            BigData::ReportFileSystemStoreEvent({"open", GetShortFileName(filepath), mesg});
            continue;
        }
        char buffer[BUF_LEN];
        while (gzgets(file, buffer, sizeof(buffer))) {
            SecurityCollector::SecurityEvent event = IsWantDate(std::string(buffer), eventid, startTime, endTime);
            if (event.GetEventId() == 0) {
                continue;
            }
            events.push_back(event);
        }
        gzclose(file);
        if (events.size() > MAX_QUERY_EVENTS_SIZE) {
            break;
        }
    }
    QuerySecurityEventCallBack(proxy, events);
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard